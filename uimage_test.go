package fwimg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// multi builds the payload of a multi-file image by hand: the size table, a
// zero, then every file padded to 4 bytes (the last one too, as mkimage does).
func multi(files ...[]byte) []byte {
	var p []byte
	for _, f := range files {
		p = binary.BigEndian.AppendUint32(p, uint32(len(f)))
	}
	p = binary.BigEndian.AppendUint32(p, 0)
	for _, f := range files {
		p = append(p, f...)
		for len(p)%4 != 0 {
			p = append(p, 0)
		}
	}
	return p
}

// wrap puts a header with the fields of o around payload, with both CRCs
// computed here, and lets a test override the size.
func wrap(t *testing.T, payload []byte, o UImageOptions, size *uint32) []byte {
	t.Helper()
	b := mustUImage(t, payload, o)
	if size != nil {
		binary.BigEndian.PutUint32(b[12:], *size)
		binary.BigEndian.PutUint32(b[4:], 0)
		binary.BigEndian.PutUint32(b[4:], crc32.ChecksumIEEE(b[:64]))
	}
	return b
}

func TestParseUImage(t *testing.T) {
	opts := UImageOptions{Load: 0x80008000, Entry: 0x80008040, Name: "kernel", Time: 1700000000, Arch: ArchARM64, Type: TypeFirmware}
	img := mustUImage(t, []byte("payload!"), opts)
	img = append(img, "trailing junk"...)
	h, p, err := ParseUImage(img)
	if err != nil {
		t.Fatal(err)
	}
	if string(p) != "payload!" || h.Load != 0x80008000 || h.Entry != 0x80008040 || h.Name != "kernel" || h.Time != 1700000000 ||
		h.Size != 8 || h.Arch != ArchARM64 || h.Type != TypeFirmware || h.OS != OSLinux || h.Comp != CompNone {
		t.Errorf("%+v %q", h, p)
	}
	if h.DataCRC != crc32.ChecksumIEEE(p) {
		t.Errorf("data CRC %08x", h.DataCRC)
	}
	// A 32-byte name fills the field with no NUL.
	long := mustUImage(t, nil, UImageOptions{Name: strings.Repeat("n", 40)})
	copy(long[32:], strings.Repeat("m", 32))
	binary.BigEndian.PutUint32(long[4:], 0)
	binary.BigEndian.PutUint32(long[4:], crc32.ChecksumIEEE(long[:64]))
	if h, _, err := ParseUImage(long); err != nil || h.Name != strings.Repeat("m", 32) {
		t.Errorf("full name: %v %q", err, h.Name)
	}
}

func TestParseUImage_Refusals(t *testing.T) {
	good := mustUImage(t, []byte("payload!"), UImageOptions{})
	flip := func(i int) []byte {
		b := bytes.Clone(good)
		b[i] ^= 1
		return b
	}
	huge := uint32(1 << 31)
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrSyntax},
		{"short", good[:63], ErrSyntax},
		{"bad magic", flip(0), ErrSyntax},
		{"header CRC", flip(33), ErrChecksum},
		{"header CRC field itself", flip(5), ErrChecksum},
		{"data CRC", flip(64), ErrChecksum},
		{"data truncated", good[:70], ErrRange},
		{"size past the file", wrap(t, []byte("abc"), UImageOptions{}, &huge), ErrRange},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, p, err := ParseUImage(c.in)
			if !errors.Is(err, c.want) || h != nil || p != nil {
				t.Fatalf("%v %v %v, want %v", h, p, err, c.want)
			}
		})
	}
}

// noCrash runs a reader on hostile input and reports a crash as a failed
// assertion naming the case, so that a mutation of a guard fails a test on
// what the guard is for rather than killing the test binary (see guarded).
func noCrash[T any](t *testing.T, f func() (T, error)) (v T, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the reader crashed instead of refusing: %v", r)
		}
	}()
	return f()
}

func TestComponents(t *testing.T) {
	a, b, c := []byte("first"), []byte("second file"), []byte("x")
	hdr := &UImageHeader{Type: TypeMulti}
	got, err := hdr.Components(multi(a, b, c))
	if err != nil || len(got) != 3 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) || !bytes.Equal(got[2], c) {
		t.Fatalf("%q %v", got, err)
	}
	// The last file may lack its padding: mkimage writes it, a short file ends there.
	p := multi(a, b)
	got, err = hdr.Components(p[:len(p)-1])
	if err != nil || len(got) != 2 || !bytes.Equal(got[1], b) {
		t.Fatalf("unpadded last file: %q %v", got, err)
	}
	if got, err := hdr.Components(multi()); err != nil || len(got) != 0 {
		t.Errorf("no files: %q %v", got, err)
	}
	// The segments cannot grow into each other.
	if got, _ = hdr.Components(multi(a, b)); cap(got[0]) != len(a) {
		t.Errorf("cap %d", cap(got[0]))
	}
	// Any other type is one component.
	one := &UImageHeader{Type: TypeKernel}
	if got, err := one.Components([]byte("zz")); err != nil || len(got) != 1 || string(got[0]) != "zz" {
		t.Errorf("single: %q %v", got, err)
	}

	for name, p := range map[string][]byte{
		"table never ends":      {0, 0, 0, 1, 0, 0, 0, 2},
		"table of nothing":      nil,
		"table cut inside":      {0, 0, 0},
		"file past the payload": append(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 100), 0), 1, 2, 3),
		"file of 4 GiB - 1":     binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 0xFFFFFFFF), 0),
		"padding past payload":  append(append(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 1), 4), 0), 'a'), 0),
	} {
		got, err := noCrash(t, func() ([][]byte, error) { return hdr.Components(p) })
		if !errors.Is(err, ErrRange) || got != nil {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}

func TestComponents_BombsAreRefusedUnderAMemoryLimit(t *testing.T) {
	old := debug.SetMemoryLimit(256 << 20)
	defer debug.SetMemoryLimit(old)
	hdr := &UImageHeader{Type: TypeMulti}
	// 4 MiB of non-zero table entries and no terminator: bounded by the
	// payload, and the table of sizes holds no more entries than it has words.
	p := bytes.Repeat([]byte{0, 0, 0, 1}, 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, err := noCrash(t, func() ([][]byte, error) { return hdr.Components(p) })
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrRange) || got != nil {
		t.Fatalf("%v %v", got, err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("a refused table allocated %d bytes", grew)
	}
	// A header that claims 4 GiB of data over a short file.
	huge := uint32(0xFFFFFFFF)
	img := wrap(t, []byte("abc"), UImageOptions{}, &huge)
	if _, _, err := ParseUImage(img); !errors.Is(err, ErrRange) {
		t.Errorf("huge size: %v", err)
	}
}

func TestListing(t *testing.T) {
	img := mustUImage(t, make([]byte, 3000), UImageOptions{Load: 0x8000, Entry: 0x8040, Name: "boot", Time: 1700000000})
	h, p, err := ParseUImage(img)
	if err != nil {
		t.Fatal(err)
	}
	want := "Image Name:   boot\n" +
		"Created:      Tue Nov 14 22:13:20 2023\n" +
		"Image Type:   ARM Linux Kernel Image (uncompressed)\n" +
		"Data Size:    3000 Bytes = 2.93 KiB = 0.00 MiB\n" +
		"Load Address: 00008000\n" +
		"Entry Point:  00008040\n"
	if got := h.Listing([][]byte{p}); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	// Unknown codes, and a multi-file image with its contents.
	m := &UImageHeader{Type: TypeMulti, Size: 20, Arch: 200, OS: 200, Comp: 200}
	got := m.Listing([][]byte{make([]byte, 5), make([]byte, 1<<20)})
	for _, s := range []string{
		"Image Type:   Unknown Architecture Unknown OS Multi-File Image (Unknown Compression)\n",
		"Contents:\n   Image 0: 5 Bytes = 0.00 KiB = 0.00 MiB\n   Image 1: 1048576 Bytes = 1024.00 KiB = 1.00 MiB\n",
	} {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q in\n%s", s, got)
		}
	}
	if u := (&UImageHeader{Type: 200}).Listing(nil); !strings.Contains(u, "Unknown Image") || strings.Contains(u, "Contents") {
		t.Errorf("unknown type:\n%s", u)
	}
	// A compressed payload reads "(gzip compressed)", as U-Boot prints it.
	if g := (&UImageHeader{Comp: 1}).Listing(nil); !strings.Contains(g, "(gzip compressed)\n") {
		t.Errorf("gzip:\n%s", g)
	}
}

// mkimage wraps a script as a table of one file and lists it as such.
func TestScriptIsListedLikeAOneFileTable(t *testing.T) {
	h := &UImageHeader{Type: TypeScript, Size: 17}
	got, err := h.Components(multi([]byte("echo hi")))
	if err != nil || len(got) != 1 || string(got[0]) != "echo hi" {
		t.Fatalf("%q %v", got, err)
	}
	if l := h.Listing(got); !strings.Contains(l, "Contents:\n   Image 0: 7 Bytes") {
		t.Errorf("listing:\n%s", l)
	}
	// Without the table it is one payload, listed without contents.
	got, err = h.Components([]byte("echo hi"))
	if err != nil || len(got) != 1 || string(got[0]) != "echo hi" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestUImageImage(t *testing.T) {
	img := mustUImage(t, []byte("code"), UImageOptions{Load: 0x1000, Entry: 0x1004, Name: "n"})
	im, err := UImageImage(img)
	if err != nil || segs(im) != `1000:"code"` || im.Entry != 0x1004 || !im.HasEntry || im.Name != "n" || im.UImage == nil || im.UImage.Load != 0x1000 {
		t.Fatalf("%v %v", im, err)
	}
	// An empty payload is an empty image that still has its entry.
	if im, err := UImageImage(mustUImage(t, nil, UImageOptions{Entry: 7})); err != nil || len(im.Segments) != 0 || im.Entry != 7 {
		t.Errorf("empty: %v %v", im, err)
	}
	for name, in := range map[string][]byte{
		"garbage":    []byte("nope"),
		"compressed": mustUImage(t, []byte("zz"), UImageOptions{Comp: CompGzip}),
		"multi":      mustUImage(t, multi([]byte("a")), UImageOptions{Type: TypeMulti}),
	} {
		if im, err := noCrash(t, func() (*Image, error) { return UImageImage(in) }); err == nil || im != nil {
			t.Errorf("%s: %v %v", name, im, err)
		}
	}
	if _, err := UImageImage(mustUImage(t, []byte("zz"), UImageOptions{Comp: CompGzip})); !errors.Is(err, ErrSyntax) {
		t.Errorf("a gzip payload that is not gzip: %v", err)
	}
	if _, err := UImageImage(mustUImage(t, []byte("zz"), UImageOptions{Comp: 99})); !errors.Is(err, ErrFormat) {
		t.Errorf("unknown compression: %v", err)
	}
}
