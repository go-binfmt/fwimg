package fwimg

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The L5 differential lane: compressed uImage and UF2 and Verilog output
// against mkimage, uf2conv.py and objcopy. Every test here goes through need,
// so FWIMG_REQUIRE_DIFF turns a missing tool into a failure. uf2conv.py comes
// from a clone of microsoft/uf2 at the commit pinned in uf2.go, whose path CI
// gives in FWIMG_UF2CONV.

// payloadFor is a compressible, not trivial, payload of n bytes.
func payloadFor(n int) []byte {
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		if i%7 < 4 {
			b[i] = byte(i / 16)
		} else {
			b[i] = byte(x >> 24 & 0x3f)
		}
	}
	return b
}

// mkimage never compresses a payload it is given with -C: the header it
// writes for the compressed bytes is the reference, and what we compress must
// read back to the input.
func TestDifferential_CompressedUImageAgainstMkimage(t *testing.T) {
	need(t, "mkimage")
	dir := t.TempDir()
	const stamp = 1700000000
	t.Setenv("SOURCE_DATE_EPOCH", fmt.Sprint(stamp))
	for _, tc := range []struct {
		name string
		comp byte
	}{{"gzip", CompGzip}, {"lz4", CompLZ4}} {
		for _, n := range []int{1, 100, 70000} {
			raw := payloadFor(n)
			packed, err := CompressPayload(raw, tc.comp)
			if err != nil {
				t.Fatal(err)
			}
			pp := writeTemp(t, dir, "payload.bin", packed)
			ref := filepath.Join(dir, "ref.img")
			run(t, "mkimage", "-A", "arm", "-O", "linux", "-T", "kernel", "-C", tc.name,
				"-a", "0x8000", "-e", "0x8001", "-n", "fw", "-d", pp, ref)
			want := readFile(t, ref)
			got, err := UImage(packed, UImageOptions{Load: 0x8000, Entry: 0x8001, Name: "fw", OS: OSLinux, Arch: ArchARM, Type: TypeKernel, Comp: tc.comp, Time: stamp})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s/%d: %d bytes, mkimage made %d; first difference at %d", tc.name, n, len(got), len(want), firstDiff(got, want))
			}
			im, err := UImageImage(want) // mkimage's file, decompressed by us
			if err != nil {
				t.Fatalf("%s/%d: %v", tc.name, n, err)
			}
			if flat, _, err := im.Flat(0, 0); err != nil || !bytes.Equal(flat, raw) {
				t.Errorf("%s/%d: round trip through mkimage's header differs: %v", tc.name, n, err)
			}
			h, _, err := ParseUImage(want)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := h.Listing([][]byte{packed}), output(t, "mkimage", "-l", ref); got != want {
				t.Errorf("%s/%d: our listing:\n%s\nmkimage -l:\n%s", tc.name, n, got, want)
			}
		}
	}
}

// uf2conv.py writes the same blocks as EncodeUF2 for a raw binary.
func TestDifferential_UF2AgainstUf2conv(t *testing.T) {
	need(t, "python3")
	conv := os.Getenv("FWIMG_UF2CONV")
	if conv == "" {
		if os.Getenv("FWIMG_REQUIRE_DIFF") != "" {
			t.Fatal("differential lane is REQUIRED here but FWIMG_UF2CONV (utils/uf2conv.py of microsoft/uf2) is not set")
		}
		t.Skip("differential lane needs FWIMG_UF2CONV=<utils/uf2conv.py of microsoft/uf2>")
	}
	dir := t.TempDir()
	for _, fam := range []string{"", "rp2040", "0xada52840"} {
		for _, n := range []int{8, 255, 256, 257, 5000} {
			raw := payloadFor(n)
			in := writeTemp(t, dir, "in.bin", raw)
			ref := filepath.Join(dir, "ref.uf2")
			args := []string{conv, "-c", "-b", "0x10000000", "-o", ref}
			var id uint32
			if fam != "" {
				args = append(args, "-f", fam)
				var err error
				if id, err = ParseUF2Family(fam); err != nil {
					t.Fatal(err)
				}
			}
			run(t, "python3", append(args, in)...)
			im, err := RawImage(raw, 0x10000000)
			if err != nil {
				t.Fatal(err)
			}
			got, err := EncodeUF2(im, UF2Options{Family: id})
			if err != nil {
				t.Fatal(err)
			}
			if want := readFile(t, ref); !bytes.Equal(got, want) {
				t.Errorf("family %q, %d bytes: ours %d bytes, uf2conv %d; first difference at %d", fam, n, len(got), len(want), firstDiff(got, want))
			}
		}
	}
}

// The family table is the file it was copied from: set FWIMG_UF2FAMILIES to
// utils/uf2families.json of microsoft/uf2 at the pinned commit (a Go file need
// not have the python lane's tools, but CI has both).
func TestDifferential_UF2FamiliesAgainstSource(t *testing.T) {
	path := os.Getenv("FWIMG_UF2_FAMILIES")
	if path == "" {
		if os.Getenv("FWIMG_REQUIRE_DIFF") != "" {
			t.Fatal("differential lane is REQUIRED here but FWIMG_UF2_FAMILIES is not set")
		}
		t.Skip("needs FWIMG_UF2_FAMILIES=<utils/uf2families.json of microsoft/uf2>")
	}
	checkUF2Families(t, readFile(t, path))
}

// objcopy -O verilog, with every data width: the same text, the trailing
// space of the big-endian words aside (objcopy picks the byte order from the
// ELF, which is little-endian here).
func TestDifferential_VerilogAgainstObjcopy(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, _ := fixture(t)
	data := readFile(t, elfPath)
	for _, w := range []int{1, 2, 4, 8} {
		ref := filepath.Join(t.TempDir(), "ref.vh")
		run(t, "objcopy", "-O", "verilog", fmt.Sprintf("--verilog-data-width=%d", w), elfPath, ref)
		im, err := ELFImageView(data, FlattenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := EncodeVerilog(im, VerilogOptions{DataWidth: w})
		if err != nil {
			t.Fatal(err)
		}
		if want := readFile(t, ref); !bytes.Equal(got, want) {
			t.Errorf("width %d: ours %d bytes, objcopy %d; first difference at %d\nours:    %q\nobjcopy: %q",
				w, len(got), len(want), firstDiff(got, want), got[:min(120, len(got))], want[:min(120, len(want))])
		}
	}
}
