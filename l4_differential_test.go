package fwimg

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The L4 differential lane: the ranges and the start address of a manifest
// against srec_info, which reads both Motorola and Intel files. The mkimage -l
// side is TestDifferential_ListingAgainstMkimage (the text `fwimg info` prints
// for a uImage is Listing's). Like the others it needs the tools and skips
// without them, and FWIMG_REQUIRE_DIFF makes a missing one a failure.

var (
	srecInfoRange = regexp.MustCompile(`^(?:Data:)?\s*([0-9A-Fa-f]+)\s+-\s+([0-9A-Fa-f]+)\s*$`)
	srecInfoStart = regexp.MustCompile(`^Execution Start Address:\s*([0-9A-Fa-f]+)\s*$`)
)

// parseSrecInfo reads the data ranges (first, last byte) and the start address
// out of srec_info's text. It matches lines, not columns: the widths of the
// numbers depend on the file's address size.
func parseSrecInfo(t *testing.T, text string) (ranges [][2]uint64, start uint64, hasStart bool) {
	t.Helper()
	num := func(s string) uint64 {
		v, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			t.Fatalf("srec_info number %q: %v", s, err)
		}
		return v
	}
	for _, line := range regexp.MustCompile(`\r?\n`).Split(text, -1) {
		if m := srecInfoRange.FindStringSubmatch(line); m != nil {
			ranges = append(ranges, [2]uint64{num(m[1]), num(m[2])})
		} else if m := srecInfoStart.FindStringSubmatch(line); m != nil {
			start, hasStart = num(m[1]), true
		}
	}
	return ranges, start, hasStart
}

func TestDifferential_ManifestRangesAgainstSrecInfo(t *testing.T) {
	need(t, "srec_info")
	dir := t.TempDir()
	im := &Image{
		Segments: []Segment{
			{Addr: 0x8000000, Data: []byte("AAAAAAAA")},
			{Addr: 0x8000010, Data: []byte("BBBB")},
			{Addr: 0x8001000, Data: []byte("CC")},
		},
		Entry: 0x8000004, HasEntry: true,
	}
	srec, err := EncodeSRECOpts(im, SRECOptions{Name: "manifest"})
	if err != nil {
		t.Fatal(err)
	}
	ihex, err := EncodeIHEX(im, 0)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManifest(im, ManifestOptions{Format: FormatSREC})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		file string
		args []string
		data []byte
	}{
		{"srec", "a.srec", nil, srec},
		{"ihex", "a.hex", []string{"-Intel"}, ihex},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := writeTemp(t, dir, c.file, c.data)
			ranges, start, hasStart := parseSrecInfo(t, output(t, "srec_info", append([]string{p}, c.args...)...))
			if len(ranges) != len(m.Segments) {
				t.Fatalf("srec_info lists %d ranges %x, the manifest %d segments", len(ranges), ranges, len(m.Segments))
			}
			for i, s := range m.Segments {
				a, err := strconv.ParseUint(s.Address[2:], 16, 64)
				if err != nil {
					t.Fatal(err)
				}
				if want := [2]uint64{a, a + s.Size - 1}; ranges[i] != want {
					t.Errorf("range %d: srec_info %#x - %#x, manifest %#x - %#x", i, ranges[i][0], ranges[i][1], want[0], want[1])
				}
			}
			if !hasStart || m.Entry == nil || fmt.Sprintf("0x%x", start) != *m.Entry {
				t.Errorf("start: srec_info %#x (%v), manifest %v", start, hasStart, m.Entry)
			}
			// What we hash is what srec_cat reads back: the flat bytes of the file.
			back, err := DecodeIHEX(readFile(t, writeIHEXViaSrecCat(t, dir, p, c.args)), DecodeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Verify(back, VerifyOptions{}); err != nil {
				t.Errorf("a file srec_cat rewrote does not match the manifest: %v", err)
			}
		})
	}
}

// writeIHEXViaSrecCat has srec_cat rewrite p as Intel HEX and returns the path.
func writeIHEXViaSrecCat(t *testing.T, dir, p string, inArgs []string) string {
	t.Helper()
	q := filepath.Join(dir, "rewritten.hex")
	args := append([]string{p}, inArgs...)
	if len(inArgs) == 0 {
		args = append(args, "-Motorola")
	}
	run(t, "srec_cat", append(args, "-o", q, "-Intel")...)
	return q
}
