package main

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// allocated is the bytes the Go allocator handed out while f ran. It is exact
// under load, unlike a time (go-binfmt/fwimg#17).
func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// TestFlatBinaryCopies pins how often `-O binary` copies the image: the file
// is read once and the output is written from that read, gaps included; no
// second image is built. v0.2.1 and later copied every segment out of the
// input first, a whole extra image (0.5x objcopy at 4 MiB in CI), and v0.4.1
// still laid several segments out in a buffer of their own.
func TestFlatBinaryCopies(t *testing.T) {
	const n = 4 << 20
	body := bytes.Repeat([]byte{0xA5, 0x5A, 0x11}, n/3+1)[:n]
	one := writeELF(t, elf.EM_AARCH64, 0x80000, elfgen.Seg{Paddr: 0x80000, Off: 0x1000, Filesz: n, Memsz: n, Data: body})
	two := writeELF(t, elf.EM_AARCH64, 0x80000,
		elfgen.Seg{Paddr: 0x80000, Off: 0x1000, Filesz: n / 2, Memsz: n / 2, Data: body[:n/2]},
		elfgen.Seg{Paddr: 0x80000 + n/2 + 0x100, Off: 0x1000 + n/2, Filesz: n / 2, Memsz: n / 2, Data: body[n/2:]})
	for _, c := range []struct {
		name  string
		in    string
		extra float64 // the most whole images allocated, beyond the one read
	}{
		{"one segment: the read is the only image", one, 0.25},
		{"two segments: the segments are written from the read, not laid out", two, 0.25},
	} {
		out := filepath.Join(t.TempDir(), "out")
		var err error
		got := allocated(func() { _, _, err = runCmd(t, "-O", "binary", "-o", out, c.in) })
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if st, serr := os.Stat(out); serr != nil || st.Size() < n {
			t.Fatalf("%s: output %v, %v", c.name, st, serr)
		}
		if limit := uint64((1 + c.extra) * n); got > limit {
			t.Errorf("%s: allocated %d bytes (%.2f images), want at most %.2f images", c.name, got, float64(got)/n, 1+c.extra)
		}
	}
}
