package fwimg

import (
	"bytes"
	"debug/elf"
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
