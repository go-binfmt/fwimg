package fwimg

import (
	"bytes"
	"debug/elf"
	"hash/crc32"
	"testing"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// FuzzFlatten feeds arbitrary bytes to Flatten under a small bound. The
// properties: no panic, no allocation beyond the bound, and every image it
// accepts survives the encoders and reads back byte for byte. The committed
// corpus (testdata/fuzz/FuzzFlatten, written by internal/mkcorpus) replays as
// ordinary tests on every run.
func FuzzFlatten(f *testing.F) {
	f.Add(elfgen.Build(elf.EM_ARM, 0x1000, []elfgen.Seg{{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		const bound = 1 << 20
		out, base, err := Flatten(bytes.NewReader(data), int64(len(data)), FlattenOptions{MaxSize: bound, Pad: 0xA5})
		if err != nil {
			if out != nil {
				t.Fatal("an error came with an image")
			}
			return
		}
		if len(out) == 0 || len(out) > bound {
			t.Fatalf("accepted an image of %d bytes under a %d bound", len(out), bound)
		}
		if base > 0xFFFFFFFF || base+uint64(len(out)) > 1<<32 {
			return // not encodable as 32-bit records: refusing is the contract
		}
		srec, err := SREC(uint32(base), out, "fz", uint32(base), 16)
		if err != nil {
			t.Fatalf("SREC refused an in-range image: %v", err)
		}
		mem, _, _ := parseSREC(t, srec)
		if len(mem) != len(out) {
			t.Fatalf("SREC carries %d bytes, image has %d", len(mem), len(out))
		}
		hex, err := IHEX(uint32(base), out, 16)
		if err != nil {
			t.Fatalf("IHEX refused an in-range image: %v", err)
		}
		imem, eof := parseIHEX(t, hex)
		if !eof || len(imem) != len(out) {
			t.Fatalf("IHEX carries %d bytes (eof %v), image has %d", len(imem), eof, len(out))
		}
		for i, b := range out {
			a := uint32(base) + uint32(i)
			if mem[a] != b || imem[a] != b {
				t.Fatalf("byte at 0x%x: image 0x%x srec 0x%x ihex 0x%x", a, b, mem[a], imem[a])
			}
		}
	})
}

// checkImage holds the invariants of every decoded Image: segments are
// non-empty, sorted, disjoint and not adjacent, below 2^32, and within bound.
func checkImage(t *testing.T, im *Image, bound uint64) {
	t.Helper()
	var n, prev uint64
	for i, s := range im.Segments {
		if len(s.Data) == 0 {
			t.Fatalf("segment %d is empty", i)
		}
		if i > 0 && s.Addr <= prev {
			t.Fatalf("segment %d at 0x%x does not follow the end 0x%x of the one before (or touches it)", i, s.Addr, prev)
		}
		if s.End() > 1<<32 {
			t.Fatalf("segment %d ends at 0x%x, past 4 GiB", i, s.End())
		}
		prev, n = s.End(), n+uint64(len(s.Data))
	}
	if n != im.Len() || n > bound {
		t.Fatalf("image of %d bytes under a %d bound (Len %d)", n, bound, im.Len())
	}
}

func sameImage(t *testing.T, a, b *Image) {
	t.Helper()
	if len(a.Segments) != len(b.Segments) {
		t.Fatalf("%d segments became %d", len(a.Segments), len(b.Segments))
	}
	for i := range a.Segments {
		if a.Segments[i].Addr != b.Segments[i].Addr || !bytes.Equal(a.Segments[i].Data, b.Segments[i].Data) {
			t.Fatalf("segment %d changed: 0x%x/%d bytes became 0x%x/%d bytes", i, a.Segments[i].Addr, len(a.Segments[i].Data), b.Segments[i].Addr, len(b.Segments[i].Data))
		}
	}
}

// FuzzIHEX: no panic, nothing past the bound, and an accepted file survives
// encode and decode unchanged. The corpus is testdata/fuzz/FuzzIHEX.
func FuzzIHEX(f *testing.F) {
	f.Add([]byte(":0100000041BE\n:00000001FF\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		const bound = 1 << 16
		im, err := DecodeIHEX(data, DecodeOptions{MaxSize: bound})
		if err != nil {
			if im != nil {
				t.Fatal("an error came with an image")
			}
			return
		}
		checkImage(t, im, bound)
		text, err := EncodeIHEX(im, 16)
		if err != nil {
			t.Fatalf("EncodeIHEX refused a decoded image: %v", err)
		}
		back, err := DecodeIHEX(text, DecodeOptions{MaxSize: bound})
		if err != nil {
			t.Fatalf("decode(encode(x)) failed: %v\n%s", err, text)
		}
		sameImage(t, im, back)
		if im.HasEntry && im.Entry != 0 && (!back.HasEntry || back.Entry != im.Entry) {
			t.Fatalf("start address 0x%x became 0x%x/%v", im.Entry, back.Entry, back.HasEntry)
		}
	})
}

// FuzzSREC is FuzzIHEX for S-records.
func FuzzSREC(f *testing.F) {
	f.Add([]byte("S1040000AA51\nS9030000FC\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		const bound = 1 << 16
		im, err := DecodeSREC(data, DecodeOptions{MaxSize: bound})
		if err != nil {
			if im != nil {
				t.Fatal("an error came with an image")
			}
			return
		}
		checkImage(t, im, bound)
		if !im.HasEntry || im.Entry > 0xFFFFFFFF {
			t.Fatalf("start address 0x%x/%v", im.Entry, im.HasEntry)
		}
		text, err := EncodeSREC(im, im.Name, 16)
		if err != nil {
			return // a header text the encoder will not write: refused, not wrong
		}
		back, err := DecodeSREC(text, DecodeOptions{MaxSize: bound})
		if err != nil {
			t.Fatalf("decode(encode(x)) failed: %v\n%s", err, text)
		}
		sameImage(t, im, back)
		if back.Entry != im.Entry || back.Name != im.Name {
			t.Fatalf("entry/name 0x%x/%q became 0x%x/%q", im.Entry, im.Name, back.Entry, back.Name)
		}
	})
}

// FuzzUImage: no panic; an accepted header has a payload of ih_size bytes
// that its CRC covers, the multi-file table stays inside it, and rebuilding
// the image from its fields parses back to the same fields.
func FuzzUImage(f *testing.F) {
	f.Add(mustUImageSeed())
	f.Fuzz(func(t *testing.T, data []byte) {
		h, p, err := ParseUImage(data)
		if err != nil {
			if h != nil || p != nil {
				t.Fatal("an error came with a result")
			}
			return
		}
		if uint64(len(p)) != uint64(h.Size) || crc32.ChecksumIEEE(p) != h.DataCRC {
			t.Fatalf("payload of %d bytes for size %d", len(p), h.Size)
		}
		comps, err := h.Components(p)
		if err == nil {
			var n int
			for _, c := range comps {
				n += len(c)
			}
			if n > len(p) {
				t.Fatalf("components of %d bytes in a payload of %d", n, len(p))
			}
		}
		_ = h.Listing(comps)
		again, err := UImage(p, UImageOptions{Load: h.Load, Entry: h.Entry, Name: h.Name, OS: h.OS, Arch: h.Arch, Type: h.Type, Comp: h.Comp, Time: h.Time})
		if err != nil {
			t.Fatalf("UImage refused a parsed payload: %v", err)
		}
		h2, p2, err := ParseUImage(again)
		if err != nil || !bytes.Equal(p, p2) || *h2 != *h && !zeroCodes(h) {
			t.Fatalf("rebuilt image differs: %v %+v vs %+v", err, h2, h)
		}
	})
}

// zeroCodes: UImage replaces a zero OS, arch or type by its default, so an
// input that has one cannot come back identical.
func zeroCodes(h *UImageHeader) bool { return h.OS == 0 || h.Arch == 0 || h.Type == 0 }

func mustUImageSeed() []byte {
	b, err := UImage([]byte("seed"), UImageOptions{Load: 0x1000, Entry: 0x1000, Name: "s"})
	if err != nil {
		panic(err)
	}
	return b
}
