package fwimg

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

func rawAt(t *testing.T, b []byte, addr uint64) *Image {
	t.Helper()
	im, err := RawImage(b, addr)
	if err != nil {
		t.Fatal(err)
	}
	return im
}

func TestCompFromName(t *testing.T) {
	for in, want := range map[string]byte{"": CompNone, "none": CompNone, "gzip": CompGzip, "lz4": CompLZ4} {
		if got, err := CompFromName(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"GZIP", "bzip2", "zstd", "5"} {
		if _, err := CompFromName(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if CompLZ4 != 5 {
		t.Errorf("lz4 is ih_comp 5 in U-Boot (image.h IH_COMP_LZ4), not %d", CompLZ4)
	}
}

func TestCompress_RoundTripAndReproducible(t *testing.T) {
	for _, comp := range []byte{CompGzip, CompLZ4} {
		for _, n := range []int{0, 1, 1000, 1 << 18} {
			raw := payloadFor(n)
			a, err := CompressPayload(raw, comp)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := CompressPayload(raw, comp)
			if !bytes.Equal(a, b) {
				t.Errorf("comp %d, %d bytes: two runs differ", comp, n)
			}
			back, err := DecompressPayload(a, comp, 0)
			if err != nil || !bytes.Equal(back, raw) {
				t.Errorf("comp %d, %d bytes: %v", comp, n, err)
			}
			// the limit is exact: n bytes fit n, not n-1
			if _, err := DecompressPayload(a, comp, uint64(n)); n > 0 && err != nil {
				t.Errorf("comp %d, %d bytes at the limit: %v", comp, n, err)
			}
			if _, err := DecompressPayload(a, comp, uint64(n)-1); n > 1 && !errors.Is(err, ErrTooLarge) {
				t.Errorf("comp %d, %d bytes one over the limit: %v", comp, n, err)
			}
		}
	}
	// gzip carries no time and no name: the second to ninth bytes are fixed.
	g, _ := CompressPayload([]byte("x"), CompGzip)
	if !bytes.Equal(g[:8], []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0}) {
		t.Errorf("gzip header % x", g[:10])
	}
	if _, err := CompressPayload([]byte("x"), 99); !errors.Is(err, ErrFormat) {
		t.Errorf("unknown compression: %v", err)
	}
	if _, err := DecompressPayload([]byte("x"), 99, 0); !errors.Is(err, ErrFormat) {
		t.Errorf("unknown decompression: %v", err)
	}
	for _, comp := range []byte{CompGzip, CompLZ4} {
		if _, err := DecompressPayload([]byte("not compressed"), comp, 0); !errors.Is(err, ErrSyntax) {
			t.Errorf("comp %d on garbage: %v", comp, err)
		}
	}
}

// A few kilobytes that inflate to megabytes are refused at the bound, before
// the memory is asked for.
func TestDecompress_BombsAreRefusedUnderAMemoryLimit(t *testing.T) {
	old := debug.SetMemoryLimit(256 << 20)
	defer debug.SetMemoryLimit(old)
	zeros := make([]byte, 32<<20)
	for _, comp := range []byte{CompGzip, CompLZ4} {
		packed, err := CompressPayload(zeros, comp)
		if err != nil {
			t.Fatal(err)
		}
		if len(packed) > 1<<18 {
			t.Fatalf("comp %d: the bomb is %d bytes, not small", comp, len(packed))
		}
		img, err := UImage(packed, UImageOptions{Comp: comp, Load: 0x1000, Entry: 0x1000})
		if err != nil {
			t.Fatal(err)
		}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, e1 := DecompressPayload(packed, comp, 1<<20)
		_, e2 := UImageImageOpts(img, DecodeOptions{MaxSize: 1 << 20})
		runtime.ReadMemStats(&after)
		_, e3 := UImageImage(img) // the default bound is 256 MiB: the 32 MiB bomb is within it
		if !errors.Is(e1, ErrTooLarge) || !errors.Is(e2, ErrTooLarge) {
			t.Errorf("comp %d: %v, %v; want ErrTooLarge", comp, e1, e2)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
			t.Errorf("comp %d: refusals allocated %d bytes", comp, grew)
		}
		if e3 != nil {
			t.Errorf("comp %d: 32 MiB under the default bound: %v", comp, e3)
		}
		// verification of a bomb is bounded by the image it checks
		im := rawAt(t, []byte("tiny"), 0x1000)
		if err := VerifyUImage(img, im, 0, UImageOptions{Comp: comp, Load: 0x1000, Entry: 0x1000}); err == nil {
			t.Errorf("comp %d: a bomb verified as a 4-byte image", comp)
		}
	}
}

func TestUImageImage_Compressed(t *testing.T) {
	raw := payloadFor(5000)
	for _, comp := range []byte{CompGzip, CompLZ4} {
		packed, _ := CompressPayload(raw, comp)
		img := mustUImage(t, packed, UImageOptions{Load: 0x8000, Entry: 0x8040, Comp: comp, Name: "z"})
		im, err := UImageImage(img)
		if err != nil {
			t.Fatal(err)
		}
		flat, base, err := im.Flat(0, 0)
		if err != nil || base != 0x8000 || !bytes.Equal(flat, raw) || im.Entry != 0x8040 || im.UImage == nil || im.UImage.Comp != comp {
			t.Errorf("comp %d: base 0x%x, %v, header %+v", comp, base, err, im.UImage)
		}
		if err := VerifyUImage(img, im, 0, UImageOptions{Load: 0x8000, Entry: 0x8040, Comp: comp, Name: "z"}); err != nil {
			t.Errorf("comp %d: %v", comp, err)
		}
		// the compression is part of what is verified
		if err := VerifyUImage(img, im, 0, UImageOptions{Load: 0x8000, Entry: 0x8040, Comp: CompNone, Name: "z"}); err == nil {
			t.Errorf("comp %d: verified as uncompressed", comp)
		}
		// UImageStored keeps the compressed bytes as they are
		st, err := UImageStored(img)
		if err != nil {
			t.Fatal(err)
		}
		if f, _, _ := st.Flat(0, 0); !bytes.Equal(f, packed) {
			t.Errorf("comp %d: stored image is not the stored bytes", comp)
		}
	}
	// an empty file compresses to something and decodes to nothing
	packed, _ := CompressPayload(nil, CompGzip)
	if im, err := UImageImage(mustUImage(t, packed, UImageOptions{Entry: 7, Comp: CompGzip})); err != nil || im.Len() != 0 || im.Entry != 7 {
		t.Errorf("empty gzip: %v %v", im, err)
	}
}

func TestUF2Families(t *testing.T) {
	for in, want := range map[string]uint32{"rp2040": 0xe48bff56, "RP2040": 0xe48bff56, "0xe48bff56": 0xe48bff56, "3800": 3800, "nrf52": 0x1b57745f} {
		if got, err := ParseUF2Family(in); err != nil || got != want {
			t.Errorf("%q: 0x%x %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0", "nosuch", "0x100000000", "-1"} {
		if _, err := ParseUF2Family(in); !errors.Is(err, ErrFormat) {
			t.Errorf("%q: %v", in, err)
		}
	}
	if UF2FamilyName(0xe48bff56) != "RP2040" || UF2FamilyName(1) != "" {
		t.Errorf("names: %q %q", UF2FamilyName(0xe48bff56), UF2FamilyName(1))
	}
	seen := map[uint32]string{}
	for _, f := range UF2Families {
		if prev, dup := seen[f.ID]; dup {
			t.Errorf("0x%x is %s and %s", f.ID, prev, f.Name)
		}
		seen[f.ID] = f.Name
	}
}

// checkUF2Families compares UF2Families with utils/uf2families.json.
func checkUF2Families(t *testing.T, src []byte) {
	t.Helper()
	var rows []struct{ ID, ShortName, Description string }
	if err := json.Unmarshal(src, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(UF2Families) {
		t.Errorf("the file has %d families, the table %d", len(rows), len(UF2Families))
	}
	for i, r := range rows {
		id, err := strconv.ParseUint(r.ID, 0, 32)
		if err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		if i >= len(UF2Families) {
			t.Errorf("missing: 0x%x %s", id, r.ShortName)
			continue
		}
		if f := UF2Families[i]; f.ID != uint32(id) || f.Name != r.ShortName || f.Description != r.Description {
			t.Errorf("row %d: table has {0x%x %q %q}, file has {0x%x %q %q}", i, f.ID, f.Name, f.Description, id, r.ShortName, r.Description)
		}
	}
}

func TestUF2_EncodeLayout(t *testing.T) {
	got, err := EncodeUF2(rawAt(t, []byte("hello"), 0x10000000), UF2Options{Family: 0xe48bff56})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 512 {
		t.Fatalf("%d bytes", len(got))
	}
	le := binary.LittleEndian
	for i, want := range []uint32{0x0A324655, 0x9E5D5157, 0x2000, 0x10000000, 256, 0, 1, 0xe48bff56} {
		if v := le.Uint32(got[4*i:]); v != want {
			t.Errorf("header word %d = 0x%x, want 0x%x", i, v, want)
		}
	}
	if string(got[32:37]) != "hello" || !bytes.Equal(got[37:32+256], make([]byte, 256-5)) || !bytes.Equal(got[32+256:508], make([]byte, 508-288)) || le.Uint32(got[508:]) != 0x0AB16F30 {
		t.Error("payload, padding or end magic")
	}
	none, _ := EncodeUF2(rawAt(t, []byte("hello"), 0x10000000), UF2Options{})
	if le.Uint32(none[8:]) != 0 || le.Uint32(none[28:]) != 0 {
		t.Error("no family: flags and file size must be 0")
	}
	im, err := DecodeUF2(got, DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if im.Family != 0xe48bff56 || im.Base() != 0x10000000 || im.Len() != 256 {
		t.Errorf("decoded: family 0x%x base 0x%x len %d", im.Family, im.Base(), im.Len())
	}
	if err := VerifyUF2(got, rawAt(t, []byte("hello"), 0x10000000), UF2Options{Family: 0xe48bff56}); err != nil {
		t.Error(err)
	}
	if err := VerifyUF2(got, rawAt(t, []byte("hellp"), 0x10000000), UF2Options{Family: 0xe48bff56}); err == nil {
		t.Error("another image verified")
	}
}

func TestUF2_SegmentsDoNotOverlapInTheirPadding(t *testing.T) {
	// two segments 16 bytes apart: the first block must not be padded over the second
	im := &Image{Segments: []Segment{{Addr: 0x1000, Data: []byte("first-segment-16")}, {Addr: 0x1020, Data: []byte("second")}}}
	b, err := EncodeUF2(im, UF2Options{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeUF2(b, DecodeOptions{})
	if err != nil {
		t.Fatalf("a file we wrote does not decode: %v", err)
	}
	// the first block is cut where the next segment starts; the last one is
	// padded to 256 bytes, as uf2conv.py does
	if len(got.Segments) != 2 || string(got.Segments[0].Data) != "first-segment-16" ||
		!bytes.Equal(got.Segments[1].Data, append([]byte("second"), make([]byte, 250)...)) {
		t.Errorf("decoded %d segments, %d and %d bytes", len(got.Segments), len(got.Segments[0].Data), len(got.Segments[1].Data))
	}
	if err := VerifyUF2(b, im, UF2Options{}); err != nil {
		t.Errorf("VerifyUF2 refused what EncodeUF2 wrote: %v", err)
	}
	b2, err := EncodeUF2(got, UF2Options{})
	if err != nil || !bytes.Equal(b, b2) {
		t.Errorf("not stable: %v", err)
	}
}

func TestUF2_Refusals(t *testing.T) {
	if _, err := EncodeUF2(rawAt(t, []byte("x"), 0x1001), UF2Options{}); !errors.Is(err, ErrFormat) {
		t.Errorf("unaligned address: %v", err)
	}
	if _, err := EncodeUF2(rawAt(t, []byte("xxxx"), 0xFFFFFFFC+0x10), UF2Options{}); !errors.Is(err, ErrAddrOverflow) {
		t.Errorf("past 32 bits: %v", err)
	}
	if _, err := EncodeUF2(&Image{Segments: []Segment{{Addr: 1 << 33, Data: []byte("xxxx")}}}, UF2Options{}); !errors.Is(err, ErrAddrOverflow) {
		t.Errorf("above 32 bits: %v", err)
	}
	valid, _ := EncodeUF2(rawAt(t, bytes.Repeat([]byte{1}, 600), 0x2000), UF2Options{Family: 7})
	put := func(off int, v uint32) []byte {
		c := append([]byte(nil), valid...)
		binary.LittleEndian.PutUint32(c[off:], v)
		return c
	}
	for name, in := range map[string][]byte{
		"empty":             nil,
		"short":             valid[:100],
		"not a block count": valid[:1000],
		"magic":             put(0, 1),
		"magic 1":           put(4, 1),
		"end magic":         put(508, 1),
		"size":              put(16, 477),
		"flags file":        put(8, 0x1000),
		"flags not main":    put(8, 0x2001),
		"flags unknown":     put(8, 0x12000),
		"number":            put(512+20, 5),
		"total":             put(24, 9),
		"family changes":    put(512+28, 8),
		"family dropped":    put(512+8, 0),
		"overlap":           put(512+12, 0x2000),
	} {
		if im, err := noCrash(t, func() (*Image, error) { return DecodeUF2(in, DecodeOptions{}) }); err == nil || im != nil {
			t.Errorf("%s: %v %v", name, im, err)
		}
	}
	if _, err := DecodeUF2(valid, DecodeOptions{MaxSize: 100}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("bound: %v", err)
	}
	// the address of a block that runs past 4 GiB
	if _, err := DecodeUF2(put(12, 0xFFFFFF80), DecodeOptions{}); err == nil {
		t.Error("a block that wraps the address space was accepted")
	}
}

func TestVerilog_ObjcopyLayout(t *testing.T) {
	data := make([]byte, 20)
	for i := range data {
		data[i] = byte(i)
	}
	im := &Image{Segments: []Segment{{Addr: 0x10, Data: data}}}
	for _, c := range []struct {
		name string
		o    VerilogOptions
		want string
	}{
		{"width 1", VerilogOptions{}, "@00000010\r\n00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\r\n10 11 12 13\r\n"},
		{"width 4 little: no trailing space", VerilogOptions{DataWidth: 4}, "@00000004\r\n03020100 07060504 0B0A0908 0F0E0D0C\r\n13121110\r\n"},
		{"width 4 big: a space after every word", VerilogOptions{DataWidth: 4, BigEndian: true}, "@00000004\r\n00010203 04050607 08090A0B 0C0D0E0F \r\n10111213 \r\n"},
		{"width 8 little", VerilogOptions{DataWidth: 8}, "@00000002\r\n0706050403020100 0F0E0D0C0B0A0908\r\n13121110\r\n"},
	} {
		got, err := EncodeVerilog(im, c.o)
		if err != nil || string(got) != c.want {
			t.Errorf("%s:\n got %q\nwant %q (%v)", c.name, got, c.want, err)
		}
	}
	// a last word that is not complete: reversed, with what is there
	odd := &Image{Segments: []Segment{{Addr: 0, Data: []byte{0, 1, 2}}}}
	if got, _ := EncodeVerilog(odd, VerilogOptions{DataWidth: 4}); string(got) != "@00000000\r\n020100\r\n" {
		t.Errorf("short tail: %q", got)
	}
	// a 64-bit word address has 16 digits
	far := &Image{Segments: []Segment{{Addr: 1 << 40, Data: []byte{9}}}}
	if got, _ := EncodeVerilog(far, VerilogOptions{}); string(got) != "@0000010000000000\r\n09\r\n" {
		t.Errorf("far: %q", got)
	}
}

func TestVerilog_RoundTripAndRefusals(t *testing.T) {
	im := &Image{Segments: []Segment{{Addr: 840, Data: payloadFor(77)}, {Addr: 3360, Data: payloadFor(33)}}} // multiples of every width
	for w := 1; w <= 8; w++ {
		for _, big := range []bool{false, true} {
			vo := VerilogOptions{DataWidth: w, BigEndian: big}
			text, err := EncodeVerilog(im, vo)
			if err != nil {
				t.Fatal(err)
			}
			back, err := DecodeVerilog(text, vo, DecodeOptions{})
			if err != nil {
				t.Fatalf("width %d big %v: %v\n%q", w, big, err, text)
			}
			if err := CompareImages(im, back); err != nil {
				t.Errorf("width %d big %v: %v", w, big, err)
			}
		}
	}
	if _, err := EncodeVerilog(&Image{Segments: []Segment{{Addr: 6, Data: []byte{1}}}}, VerilogOptions{DataWidth: 4}); !errors.Is(err, ErrFormat) {
		t.Errorf("unaligned segment: %v", err)
	}
	for _, w := range []int{-1, 9, 16} {
		if _, err := EncodeVerilog(im, VerilogOptions{DataWidth: w}); !errors.Is(err, ErrFormat) {
			t.Errorf("width %d: %v", w, err)
		}
		if _, err := DecodeVerilog([]byte("00"), VerilogOptions{DataWidth: w}, DecodeOptions{}); !errors.Is(err, ErrFormat) {
			t.Errorf("decode width %d: %v", w, err)
		}
	}
	for name, in := range map[string]string{
		"x digit":          "@0\nxx\n",
		"odd digits":       "@0\nABC\n",
		"wide token":       "@0\nAABB\n",
		"bare at":          "@\n",
		"unterminated":     "/* ",
		"overlap":          "@0 01 02 @1 03",
		"address overflow": "@FFFFFFFFFFFFFFFF 01",
		"long":             "@0 " + string(bytes.Repeat([]byte("0"), 40)),
	} {
		if im, err := noCrash(t, func() (*Image, error) { return DecodeVerilog([]byte(in), VerilogOptions{}, DecodeOptions{}) }); err == nil || im != nil {
			t.Errorf("%s: %v %v", name, im, err)
		}
	}
	// the byte address is the word address times the width
	got, err := DecodeVerilog([]byte("@10 04030201"), VerilogOptions{DataWidth: 4}, DecodeOptions{})
	if err != nil || got.Base() != 0x40 || !bytes.Equal(got.Segments[0].Data, []byte{1, 2, 3, 4}) {
		t.Errorf("@10 width 4: %v %v", got, err)
	}
	if _, err := DecodeVerilog(bytes.Repeat([]byte("00 "), 500), VerilogOptions{}, DecodeOptions{MaxSize: 100}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("bound: %v", err)
	}
}

func TestDetect_UF2AndVerilog(t *testing.T) {
	u, _ := EncodeUF2(rawAt(t, []byte("x"), 0x2000), UF2Options{})
	if got := Detect(u); got != FormatUF2 {
		t.Errorf("uf2: %q", got)
	}
	if got := Detect([]byte("@00000000\r\n00\r\n")); got != FormatVerilog {
		t.Errorf("verilog: %q", got)
	}
	if got := Detect([]byte("UF2")); got == FormatUF2 {
		t.Errorf("a short file is not UF2")
	}
}

// FuzzUF2: no panic, nothing past the bound; an accepted file re-encodes to a
// file that decodes and re-encodes to the same bytes.
func FuzzUF2(f *testing.F) {
	seed, _ := EncodeUF2(&Image{Segments: []Segment{{Addr: 0x2000, Data: []byte("seed")}}}, UF2Options{Family: 0xe48bff56})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		const bound = 1 << 16
		im, err := DecodeUF2(data, DecodeOptions{MaxSize: bound})
		if err != nil {
			if im != nil {
				t.Fatal("an error came with an image")
			}
			return
		}
		checkImage(t, im, bound)
		a, err := EncodeUF2(im, UF2Options{Family: im.Family})
		if err != nil {
			return // an address the encoder will not align: refused, not wrong
		}
		back, err := DecodeUF2(a, DecodeOptions{MaxSize: 2 * bound})
		if err != nil {
			t.Fatalf("decode(encode(x)) failed: %v", err)
		}
		b, err := EncodeUF2(back, UF2Options{Family: back.Family})
		if err != nil || !bytes.Equal(a, b) {
			t.Fatalf("encode is not stable: %v", err)
		}
	})
}

// FuzzVerilog: the first byte picks the data width and byte order (the low 3
// bits are the width minus one, the high bit is big-endian), the rest is the
// text. No panic, nothing past the bound, and an accepted file survives
// encode and decode unchanged.
func FuzzVerilog(f *testing.F) {
	f.Add([]byte("\x03@00000010\r\n04030201 08070605\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		vo := VerilogOptions{DataWidth: int(data[0]&7) + 1, BigEndian: data[0]&0x80 != 0}
		const bound = 1 << 16
		im, err := DecodeVerilog(data[1:], vo, DecodeOptions{MaxSize: bound})
		if err != nil {
			if im != nil {
				t.Fatal("an error came with an image")
			}
			return
		}
		if im.Len() > bound {
			t.Fatalf("image of %d bytes under a %d bound", im.Len(), bound)
		}
		text, err := EncodeVerilog(im, vo)
		if err != nil {
			return // a segment that is not aligned to the width: refused, not wrong
		}
		back, err := DecodeVerilog(text, vo, DecodeOptions{MaxSize: bound})
		if err != nil {
			t.Fatalf("decode(encode(x)) failed: %v\n%q", err, text)
		}
		sameImage(t, im, back)
	})
}

// FuzzUImageComp: a uImage of any compression is read under a bound; what is
// accepted holds no more than the bound, at its load address.
func FuzzUImageComp(f *testing.F) {
	p, _ := CompressPayload([]byte("seed seed seed seed"), CompGzip)
	img, _ := UImage(p, UImageOptions{Load: 0x1000, Entry: 0x1000, Comp: CompGzip})
	f.Add(img)
	l, _ := CompressPayload([]byte("seed seed seed seed"), CompLZ4)
	img, _ = UImage(l, UImageOptions{Load: 0x1000, Entry: 0x1000, Comp: CompLZ4})
	f.Add(img)
	f.Fuzz(func(t *testing.T, data []byte) {
		const bound = 1 << 16
		im, err := UImageImageOpts(data, DecodeOptions{MaxSize: bound})
		if err != nil {
			if im != nil {
				t.Fatal("an error came with an image")
			}
			return
		}
		if im.Len() > bound || im.UImage == nil {
			t.Fatalf("image of %d bytes under a %d bound, header %v", im.Len(), bound, im.UImage)
		}
	})
}

// The block count is bounded by the largest text an int can index: a plan of
// more blocks than that is refused before the file is made.
func TestUF2_PlanBound(t *testing.T) {
	old := maxText
	defer func() { maxText = old }()
	im := rawAt(t, bytes.Repeat([]byte{1}, 600), 0x2000) // 3 blocks
	maxText = 3 * uf2BlockSize
	if _, err := EncodeUF2(im, UF2Options{}); err != nil {
		t.Fatalf("exactly at the bound: %v", err)
	}
	maxText--
	if _, err := EncodeUF2(im, UF2Options{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("one byte past the bound: %v", err)
	}
}

// A payload bigger than the bound is refused whatever its compression, and a
// gzip stream that is cut inside its body is a syntax error, not a short read.
func TestDecompressPayload_BoundAndDamage(t *testing.T) {
	if _, err := DecompressPayload(make([]byte, 11), CompNone, 10); !errors.Is(err, ErrTooLarge) {
		t.Errorf("uncompressed past the bound: %v", err)
	}
	if out, err := DecompressPayload(make([]byte, 10), CompNone, 10); err != nil || len(out) != 10 {
		t.Errorf("uncompressed at the bound: %d %v", len(out), err)
	}
	gz, err := CompressPayload(bytes.Repeat([]byte("abcdefgh"), 5000), CompGzip)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecompressPayload(gz[:len(gz)-12], CompGzip, 0); !errors.Is(err, ErrSyntax) {
		t.Errorf("cut gzip body: %v", err)
	}
}

// A uImage that says gzip over bytes that are not gzip is reported as a
// decompression failure, not as whatever the empty payload then differs by.
func TestVerifyUImage_UndecodablePayloadNamesTheContainer(t *testing.T) {
	im := mem(sg(0x8000, "abcd"))
	opts := UImageOptions{Load: 0x8000, Entry: 0x8000, Comp: CompGzip}
	bad := mustUImage(t, []byte("not gzip"), opts)
	err := VerifyUImage(bad, im, 0, opts)
	if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "gzip") {
		t.Errorf("undecodable payload: %v", err)
	}
}
