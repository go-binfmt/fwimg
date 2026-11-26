package fwimg

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The input side of the differential lane (see differential_test.go): the
// decoders against the files GNU objcopy and srecord write, and what they
// read, and the uImage reader against mkimage -l. FWIMG_REQUIRE_DIFF makes a
// missing tool a failure; the tools are objcopy, srec_cat, mkimage.

func output(t *testing.T, name string, args ...string) string {
	t.Helper()
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, errb.String())
	}
	return out.String()
}

func writeTemp(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bytesAt maps every byte of an image to its address.
func bytesAt(im *Image) map[uint64]byte {
	m := map[uint64]byte{}
	for _, s := range im.Segments {
		for i, b := range s.Data {
			m[s.Addr+uint64(i)] = b
		}
	}
	return m
}

func sameBytes(t *testing.T, what string, got, want *Image) {
	t.Helper()
	g, w := bytesAt(got), bytesAt(want)
	if len(g) != len(w) {
		t.Fatalf("%s: %d bytes, the reference has %d", what, len(g), len(w))
	}
	for a, b := range w {
		if x, ok := g[a]; !ok || x != b {
			t.Fatalf("%s: byte at 0x%x is 0x%x (present %v), the reference has 0x%x", what, a, x, ok, b)
		}
	}
}

// Our decoders read what objcopy writes: ihex and srec made from a linked
// ELF with a gap between two segments, read back, then written again by
// objcopy as a flat binary from OUR file and from ITS, and compared.
func TestDifferential_DecodeObjcopyFiles(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, _ := fixture(t)
	dir := t.TempDir()
	want := filepath.Join(dir, "want.bin")
	run(t, "objcopy", "-O", "binary", "--gap-fill=0xff", elfPath, want)
	flat := readFile(t, want)
	for _, c := range []struct {
		format string
		args   []string
		decode func([]byte) (*Image, error)
	}{
		{"ihex", []string{"-O", "ihex"}, func(b []byte) (*Image, error) { return DecodeIHEX(b, DecodeOptions{}) }},
		{"srec", []string{"-O", "srec"}, func(b []byte) (*Image, error) { return DecodeSREC(b, DecodeOptions{}) }},
		{"srec-S3", []string{"-O", "srec", "--srec-forceS3"}, func(b []byte) (*Image, error) { return DecodeSREC(b, DecodeOptions{}) }},
		{"srec-short-lines", []string{"-O", "srec", "--srec-len=16"}, func(b []byte) (*Image, error) { return DecodeSREC(b, DecodeOptions{}) }},
	} {
		t.Run(c.format, func(t *testing.T) {
			ref := filepath.Join(dir, "ref."+c.format)
			run(t, "objcopy", append(c.args, elfPath, ref)...)
			im, err := c.decode(readFile(t, ref))
			if err != nil {
				t.Fatal(err)
			}
			got, base, err := im.Flat(0xff, 0)
			if err != nil || base != 0x80000 {
				t.Fatalf("flat: base 0x%x, %v", base, err)
			}
			if !bytes.Equal(got, flat) {
				t.Errorf("decoded %d bytes, objcopy's binary has %d; first difference at %d", len(got), len(flat), firstDiff(got, flat))
			}
			if len(im.Segments) != 2 {
				t.Errorf("%d segments, the ELF has 2 with a gap", len(im.Segments))
			}
			// objcopy reads the text back to the same binary: the file is
			// understood alike by both.
			back := filepath.Join(dir, "back."+c.format+".bin")
			run(t, "objcopy", "-I", c.format[:4], "-O", "binary", "--gap-fill=0xff", ref, back)
			if b := readFile(t, back); !bytes.Equal(b, got) {
				t.Errorf("objcopy -I %s reads %d bytes, ours %d; first difference at %d", c.format[:4], len(b), len(got), firstDiff(b, got))
			}
		})
	}
}

// What our encoders write from an Image with a gap is read by objcopy -I and
// by srec_cat to the same bytes.
func TestDifferential_ObjcopyAndSrecCatReadOurFiles(t *testing.T) {
	need(t, "objcopy", "srec_cat")
	dir := t.TempDir()
	im := &Image{
		Segments: []Segment{{Addr: 0x80000, Data: bytes.Repeat([]byte("abcdefg"), 300)}, {Addr: 0x90010, Data: bytes.Repeat([]byte("XYZ"), 500)}},
		Entry:    0x80040, HasEntry: true,
	}
	srec, err := EncodeSREC(im, "fw", 0)
	if err != nil {
		t.Fatal(err)
	}
	ihex, err := EncodeIHEX(im, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := func(pad byte) []byte { b, _, _ := im.Flat(pad, 0); return b }
	for _, c := range []struct {
		format string
		text   []byte
	}{{"srec", srec}, {"ihex", ihex}} {
		p := writeTemp(t, dir, "ours."+c.format, c.text)
		bin := filepath.Join(dir, "objcopy."+c.format+".bin")
		run(t, "objcopy", "-I", c.format, "-O", "binary", "--gap-fill=0x5a", p, bin)
		if b := readFile(t, bin); !bytes.Equal(b, want(0x5a)) {
			t.Errorf("objcopy reads %s as %d bytes, expected %d; first difference at %d", c.format, len(b), len(want(0x5a)), firstDiff(b, want(0x5a)))
		}
		// srec_cat re-writes it as Motorola and Intel; both go through our decoders.
		in := "-Motorola"
		if c.format == "ihex" {
			in = "-Intel"
		}
		for _, out := range []struct{ flag, ext string }{{"-Motorola", "srec"}, {"-Intel", "hex"}} {
			q := filepath.Join(dir, "cat-"+c.format+"."+out.ext)
			run(t, "srec_cat", p, in, "-o", q, out.flag)
			var got *Image
			var err error
			if out.ext == "srec" {
				got, err = DecodeSREC(readFile(t, q), DecodeOptions{})
			} else {
				got, err = DecodeIHEX(readFile(t, q), DecodeOptions{})
			}
			if err != nil {
				t.Fatalf("srec_cat %s -> %s: %v", c.format, out.ext, err)
			}
			sameBytes(t, "srec_cat "+c.format+" -> "+out.ext, got, im)
		}
	}
}

// -I binary: objcopy puts a raw file at an address with --change-addresses,
// srec_cat with -offset; ours is RawImage.
func TestDifferential_RawBinaryInput(t *testing.T) {
	need(t, "objcopy", "srec_cat")
	dir := t.TempDir()
	raw := make([]byte, 1000)
	for i := range raw {
		raw[i] = byte(i*7 + 1)
	}
	in := writeTemp(t, dir, "raw.bin", raw)
	for _, base := range []uint64{0, 0x8000, 0x12340000, 0xFFFF0000} {
		want, err := RawImage(raw, base)
		if err != nil {
			t.Fatal(err)
		}
		hex := filepath.Join(dir, fmt.Sprintf("o%x.hex", base))
		srec := filepath.Join(dir, fmt.Sprintf("o%x.srec", base))
		cat := filepath.Join(dir, fmt.Sprintf("c%x.hex", base))
		run(t, "objcopy", "-I", "binary", "-O", "ihex", "--change-addresses", fmt.Sprintf("0x%x", base), in, hex)
		run(t, "objcopy", "-I", "binary", "-O", "srec", "--change-addresses", fmt.Sprintf("0x%x", base), in, srec)
		run(t, "srec_cat", in, "-binary", "-offset", fmt.Sprintf("0x%x", base), "-o", cat, "-Intel")
		for what, f := range map[string]func() (*Image, error){
			"objcopy ihex": func() (*Image, error) { return DecodeIHEX(readFile(t, hex), DecodeOptions{}) },
			"objcopy srec": func() (*Image, error) { return DecodeSREC(readFile(t, srec), DecodeOptions{}) },
			"srec_cat hex": func() (*Image, error) { return DecodeIHEX(readFile(t, cat), DecodeOptions{}) },
		} {
			got, err := f()
			if err != nil {
				t.Fatalf("base 0x%x, %s: %v", base, what, err)
			}
			sameBytes(t, fmt.Sprintf("base 0x%x, %s", base, what), got, want)
		}
		// And the other way: our text from a raw image, read by objcopy.
		text, err := EncodeSREC(want, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		p := writeTemp(t, dir, "ours.srec", text)
		bin := filepath.Join(dir, "ours.bin")
		run(t, "objcopy", "-I", "srec", "-O", "binary", p, bin)
		if b := readFile(t, bin); !bytes.Equal(b, raw) {
			t.Errorf("base 0x%x: objcopy reads our srec as %d bytes, want %d", base, len(b), len(raw))
		}
	}
}

// mkimage -l and our Listing print the same text for a header.
func TestDifferential_ListingAgainstMkimage(t *testing.T) {
	need(t, "mkimage")
	dir := t.TempDir()
	const stamp = 1700000000
	t.Setenv("SOURCE_DATE_EPOCH", fmt.Sprint(stamp))
	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i)
	}
	pp := writeTemp(t, dir, "p.bin", payload)
	if err := os.Chtimes(pp, time.Unix(stamp, 0), time.Unix(stamp, 0)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
	}{
		{"kernel", []string{"-A", "arm", "-O", "linux", "-T", "kernel", "-C", "none", "-a", "0x8000", "-e", "0x8040", "-n", "Linux 6.1"}},
		{"arm64 standalone", []string{"-A", "arm64", "-O", "u-boot", "-T", "standalone", "-C", "none", "-a", "0x80000", "-e", "0x80000", "-n", "bare metal"}},
		{"riscv firmware gzip", []string{"-A", "riscv", "-O", "linux", "-T", "firmware", "-C", "gzip", "-a", "0x1000", "-e", "0x1000", "-n", "fw"}},
		{"x86_64 ramdisk lzma", []string{"-A", "x86_64", "-O", "linux", "-T", "ramdisk", "-C", "lzma", "-a", "0", "-e", "0", "-n", ""}},
		{"mips script", []string{"-A", "mips", "-O", "netbsd", "-T", "script", "-C", "none", "-a", "0x1", "-e", "0x2", "-n", "boot script"}},
		{"powerpc filesystem bzip2", []string{"-A", "ppc", "-O", "vxworks", "-T", "filesystem", "-C", "bzip2", "-a", "0xffffffff", "-e", "0xfffffff0", "-n", "a name of exactly thirty-one chars"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ref := filepath.Join(dir, "ref.img")
			run(t, "mkimage", append(append([]string{}, c.args...), "-d", pp, ref)...)
			img := readFile(t, ref)
			h, p, err := ParseUImage(img)
			if err != nil {
				t.Fatal(err)
			}
			comps, err := h.Components(p)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := h.Listing(comps), output(t, "mkimage", "-l", ref); got != want {
				t.Errorf("our listing:\n%s\nmkimage -l:\n%s", got, want)
			}
		})
	}
}

// A multi-file image made by mkimage: our table reader finds the files
// mkimage put in, and the listing matches.
func TestDifferential_MultiFileAgainstMkimage(t *testing.T) {
	need(t, "mkimage")
	dir := t.TempDir()
	files := [][]byte{[]byte("first file"), bytes.Repeat([]byte("B"), 4096), []byte("x"), bytes.Repeat([]byte("end"), 33)}
	var names string
	for i, f := range files {
		p := writeTemp(t, dir, fmt.Sprintf("f%d", i), f)
		if i > 0 {
			names += ":"
		}
		names += p
	}
	ref := filepath.Join(dir, "multi.img")
	run(t, "mkimage", "-A", "arm", "-O", "linux", "-T", "multi", "-C", "none", "-a", "0x8000", "-e", "0x8000", "-n", "multi", "-d", names, ref)
	h, p, err := ParseUImage(readFile(t, ref))
	if err != nil {
		t.Fatal(err)
	}
	comps, err := h.Components(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != len(files) {
		t.Fatalf("%d components, mkimage was given %d", len(comps), len(files))
	}
	for i := range files {
		if !bytes.Equal(comps[i], files[i]) {
			t.Errorf("file %d: %d bytes, want %d", i, len(comps[i]), len(files[i]))
		}
	}
	if got, want := h.Listing(comps), output(t, "mkimage", "-l", ref); got != want {
		t.Errorf("our listing:\n%s\nmkimage -l:\n%s", got, want)
	}
}

// What our UImage writes, mkimage -l and dumpimage read to the same header,
// and dumpimage extracts our payload.
func TestDifferential_MkimageReadsOurUImage(t *testing.T) {
	need(t, "mkimage", "dumpimage")
	dir := t.TempDir()
	payload := bytes.Repeat([]byte("payload"), 100)
	img, err := UImage(payload, UImageOptions{Load: 0x8000, Entry: 0x8040, Name: "ours", Arch: ArchARM64, Type: TypeKernel, Time: 1700000000})
	if err != nil {
		t.Fatal(err)
	}
	p := writeTemp(t, dir, "ours.img", img)
	h, pl, err := ParseUImage(img)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := h.Listing([][]byte{pl}), output(t, "mkimage", "-l", p); got != want {
		t.Errorf("our listing:\n%s\nmkimage -l:\n%s", got, want)
	}
	out := filepath.Join(dir, "extracted")
	run(t, "dumpimage", "-T", "kernel", "-p", "0", "-o", out, p)
	if b := readFile(t, out); !bytes.Equal(b, payload) {
		t.Errorf("dumpimage extracted %d bytes, want %d", len(b), len(payload))
	}
	// Both refuse a flipped payload byte; we agree on that with mkimage.
	bad := bytes.Clone(img)
	bad[100] ^= 1
	if _, _, err := ParseUImage(bad); err == nil {
		t.Error("we accepted a bad data CRC")
	}
	if c := exec.Command("mkimage", "-l", writeTemp(t, dir, "bad.img", bad)); c.Run() == nil {
		t.Error("mkimage -l accepted a bad data CRC: the reference does not verify, so the comparison is moot")
	}
}
