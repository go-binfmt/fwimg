package fwimg

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The L2 differential lane: the options added in v0.4.0 against the tool that
// defines each one. Text output is compared byte for byte (CRLF included),
// except for the S0 header, whose text objcopy takes from the file name.

func withoutS0(b []byte) []byte {
	var out []byte
	for _, line := range bytes.SplitAfter(b, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("S0")) {
			out = append(out, line...)
		}
	}
	return out
}

func objcopyOut(t *testing.T, elfPath, format string, args ...string) []byte {
	t.Helper()
	ref := filepath.Join(t.TempDir(), "ref")
	run(t, "objcopy", append(append([]string{"-O", format}, args...), elfPath, ref)...)
	b, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sameText(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		i := firstDiff(got, want)
		lo := max(0, i-30)
		t.Errorf("%s: %d bytes, reference %d; first difference at %d:\n got %q\nwant %q", what, len(got), len(want), i,
			got[lo:min(len(got), i+30)], want[lo:min(len(want), i+30)])
	}
}

func TestDifferentialL2_SRECAgainstObjcopy(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, _ := fixture(t)
	data := readFile(t, elfPath)
	for _, tc := range []struct {
		name string
		args []string
		bits int
	}{
		{"auto", nil, SRECAuto},
		{"S3", []string{"--srec-forceS3"}, 32},
	} {
		im, err := ELFImage(data, FlattenOptions{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := EncodeSRECOpts(im, SRECOptions{AddrBits: tc.bits, CRLF: true})
		if err != nil {
			t.Fatal(err)
		}
		sameText(t, "srec "+tc.name, withoutS0(got), withoutS0(objcopyOut(t, elfPath, "srec", tc.args...)))
	}
}

func TestDifferentialL2_IHEXObjcopyMode(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, _ := fixture(t)
	im, err := ELFImage(readFile(t, elfPath), FlattenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeIHEXOpts(im, IHEXOptions{Mode: IHEXObjcopy, CRLF: true})
	if err != nil {
		t.Fatal(err)
	}
	sameText(t, "ihex", got, objcopyOut(t, elfPath, "ihex"))
}

func TestDifferentialL2_Options(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, _ := fixture(t)
	data := readFile(t, elfPath)
	for _, tc := range []struct {
		name  string
		args  []string
		sel   SectionSelect
		build func(*Image) error
	}{
		{"gap-fill", []string{"--gap-fill=0xee"}, SectionSelect{},
			func(im *Image) error { return im.GapFill(0xee, 0) }},
		{"pad-to", []string{"--pad-to=0x90400"}, SectionSelect{},
			func(im *Image) error { return im.PadTo(0x90400, 0, 0) }},
		{"gap-fill and pad-to", []string{"--gap-fill=0x5a", "--pad-to=0x90400"}, SectionSelect{},
			func(im *Image) error {
				if err := im.GapFill(0x5a, 0); err != nil {
					return err
				}
				return im.PadTo(0x90400, 0x5a, 0)
			}},
		{"-j .data", []string{"-j", ".data"}, SectionSelect{Only: []string{".data"}}, nil},
		{"-j wildcard", []string{"-j", ".t*"}, SectionSelect{Only: []string{".t*"}}, nil},
		{"-R .data", []string{"-R", ".data"}, SectionSelect{Remove: []string{".data"}}, nil},
		{"-R negated", []string{"-R", ".*", "-R", "!.text"}, SectionSelect{Remove: []string{".*", "!.text"}}, nil},
		{"change-addresses", []string{"--change-addresses=0x100"}, SectionSelect{},
			func(im *Image) error {
				im.Entry += 0x100
				return im.Offset(0x100)
			}},
		{"adjust-vma", []string{"--adjust-vma=-0x10"}, SectionSelect{},
			func(im *Image) error {
				im.Entry -= 0x10
				return im.Offset(-0x10)
			}},
		{"set-start", []string{"--set-start=0x80010"}, SectionSelect{},
			func(im *Image) error { im.Entry, im.HasEntry = 0x80010, true; return nil }},
		{"change-start", []string{"--change-start=0x20"}, SectionSelect{},
			func(im *Image) error { im.Entry += 0x20; return nil }},
	} {
		var im *Image
		var err error
		if len(tc.sel.Only)+len(tc.sel.Remove) > 0 {
			im, err = ELFSections(data, tc.sel, FlattenOptions{})
		} else {
			im, err = ELFImage(data, FlattenOptions{})
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.build != nil {
			if err := tc.build(im); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
		}
		for _, f := range []struct {
			format string
			encode func() ([]byte, error)
		}{
			{"srec", func() ([]byte, error) {
				b, err := EncodeSRECOpts(im, SRECOptions{AddrBits: SRECAuto, CRLF: true})
				return withoutS0(b), err
			}},
			{"ihex", func() ([]byte, error) {
				return EncodeIHEXOpts(im, IHEXOptions{Mode: IHEXObjcopy, CRLF: true})
			}},
		} {
			got, err := f.encode()
			if err != nil {
				t.Fatalf("%s %s: %v", tc.name, f.format, err)
			}
			want := objcopyOut(t, elfPath, f.format, tc.args...)
			if f.format == "srec" {
				want = withoutS0(want)
			}
			sameText(t, fmt.Sprintf("%s (%s)", tc.name, f.format), got, want)
		}
	}
}

func TestDifferentialL2_CountAndLinearAgainstSrecCat(t *testing.T) {
	need(t, "gcc", "objcopy", "srec_cat")
	elfPath, _ := fixture(t)
	im, err := ELFImage(readFile(t, elfPath), FlattenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ours, err := EncodeSRECOpts(im, SRECOptions{AddrBits: 24, Count: true, CRLF: true})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "in.srec")
	if err := os.WriteFile(in, ours, 0o644); err != nil {
		t.Fatal(err)
	}
	// srec_cat reads our file and writes its own: the data, count and start
	// records must come back identical (its S0 is its own).
	ref := filepath.Join(dir, "ref.srec")
	run(t, "srec_cat", in, "-Motorola", "-o", ref, "-Motorola", "-address-length=3", "-line-length=46", "-crlf")
	sameText(t, "srec_cat S2 + S5", withoutS0(ours), withoutS0(readFile(t, ref)))

	// Linear Intel HEX: srec_cat's default is type 04 + type 05.
	hexRef := filepath.Join(dir, "ref.hex")
	run(t, "srec_cat", in, "-Motorola", "-o", hexRef, "-Intel", "-line-length=43", "-crlf")
	hex, err := EncodeIHEXOpts(im, IHEXOptions{Mode: IHEXLinear, CRLF: true})
	if err != nil {
		t.Fatal(err)
	}
	sameText(t, "srec_cat Intel", hex, readFile(t, hexRef))
}
