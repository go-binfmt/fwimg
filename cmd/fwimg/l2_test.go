package main

import (
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// sectionedELF links one segment (vaddr 0x9000, paddr 0x1000) with two
// allocated sections, a gap, and a second segment.
func sectionedELF(t *testing.T) string {
	t.Helper()
	segs := []elfgen.Seg{
		{Paddr: 0x1000, Vaddr: 0x9000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
		{Paddr: 0x1010, Vaddr: 0x9010, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")},
	}
	secs := []elfgen.Sec{
		{Name: ".text", Type: 1, Flags: 6, Addr: 0x9000, Off: 0x200, N: 4},
		{Name: ".data", Type: 1, Flags: 3, Addr: 0x9010, Off: 0x300, N: 4},
	}
	p := filepath.Join(t.TempDir(), "s.elf")
	if err := os.WriteFile(p, elfgen.BuildSections(elf.EM_ARM, 0x9000, segs, secs), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func twoSeg(t *testing.T) string {
	return writeELF(t, elf.EM_ARM, 0x1004,
		elfgen.Seg{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
		elfgen.Seg{Paddr: 0x1010, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")})
}

func decode(t *testing.T, path string) *fwimg.Image {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	im, err := fwimg.DecodeSREC(b, fwimg.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return im
}

func TestL2_GapFillPadToAndStart(t *testing.T) {
	o := filepath.Join(t.TempDir(), "o")
	// The default: a gap between two segments stays a gap in a text format.
	if _, _, err := runCmd(t, "-O", "srec", "-o", o, twoSeg(t)); err != nil {
		t.Fatal(err)
	}
	if im := decode(t, o); len(im.Segments) != 2 {
		t.Errorf("default: %+v", im.Segments)
	}
	if _, _, err := runCmd(t, "-O", "srec", "--gap-fill", "0xee", "--pad-to", "0x1018", "-o", o, twoSeg(t)); err != nil {
		t.Fatal(err)
	}
	im := decode(t, o)
	if len(im.Segments) != 1 || im.Segments[0].End() != 0x1018 || im.Segments[0].Data[4] != 0xee || im.Segments[0].Data[0x17] != 0xee {
		t.Errorf("gap-fill + pad-to: %+v", im.Segments)
	}
	// --pad is the same option for a flat binary, and the same value is accepted twice.
	if _, _, err := runCmd(t, "--pad", "0xee", "--gap-fill", "0xee", "-o", o, twoSeg(t)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(o); len(b) != 0x14 || b[4] != 0xee {
		t.Errorf("binary: %x", b)
	}
	// A start address: --set-start, then --change-start; the later of --change-addresses and
	// --change-start wins, and --change-addresses moves the sections too.
	for _, tc := range []struct {
		args  []string
		entry uint64
		base  uint64
	}{
		{[]string{"--set-start", "0x2000"}, 0x2000, 0x1000},
		{[]string{"--entry", "0x2000", "--change-start", "-0x10"}, 0x1ff0, 0x1000},
		{[]string{"--change-start", "0x10"}, 0x1014, 0x1000},
		{[]string{"--change-addresses", "0x100"}, 0x1104, 0x1100},
		{[]string{"--adjust-vma", "-0x100", "--change-start", "8"}, 0x100c, 0xf00},
		{[]string{"--change-start", "8", "--change-addresses", "0x100"}, 0x1104, 0x1100},
	} {
		args := append(append([]string{"-O", "srec", "-o", o}, tc.args...), twoSeg(t))
		if _, _, err := runCmd(t, args...); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if im := decode(t, o); im.Entry != tc.entry || im.Base() != tc.base {
			t.Errorf("%v: entry 0x%x base 0x%x, want 0x%x 0x%x", tc.args, im.Entry, im.Base(), tc.entry, tc.base)
		}
	}
	// --load still places the image after the shifts.
	if _, _, err := runCmd(t, "-O", "srec", "--change-addresses", "0x100", "--load", "0x8000", "-o", o, twoSeg(t)); err != nil {
		t.Fatal(err)
	}
	if im := decode(t, o); im.Base() != 0x8000 {
		t.Errorf("load: 0x%x", im.Base())
	}
}

func TestL2_Sections(t *testing.T) {
	o := filepath.Join(t.TempDir(), "o")
	in := sectionedELF(t)
	if _, _, err := runCmd(t, "-O", "srec", "-j", ".d*", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	if im := decode(t, o); len(im.Segments) != 1 || im.Base() != 0x1010 {
		t.Errorf("-j: %+v", im.Segments)
	}
	if _, _, err := runCmd(t, "-O", "srec", "-R", ".d*", "-R", "!.data", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	if im := decode(t, o); len(im.Segments) != 2 { // a negative pattern keeps .data
		t.Errorf("-R: %+v", im.Segments)
	}
	if _, _, err := runCmd(t, "-O", "srec", "--use-vaddr", "-j", ".text", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	if im := decode(t, o); im.Base() != 0x9000 {
		t.Errorf("use-vaddr: 0x%x", im.Base())
	}
	for _, tc := range []struct {
		name string
		args []string
		in   string
		want string
	}{
		{"both", []string{"-j", "a", "-R", "b"}, in, "undefined"},
		{"not an ELF", []string{"-j", "a", "-I", "binary", "--base", "0"}, o, "sections of an ELF"},
		{"nothing", []string{"-j", "nomatch"}, in, "no loadable section"},
		{"no table", []string{"-j", ".text"}, simple(t), "sections:"},
	} {
		_, _, err := runCmd(t, append(append(tc.args, "-O", "srec", "-o", o), tc.in)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
		var u usageErr
		if (tc.name == "both" || tc.name == "not an ELF") && !errors.As(err, &u) {
			t.Errorf("%s: not a usage error: %v", tc.name, err)
		}
	}
}

func TestL2_Formats(t *testing.T) {
	o := filepath.Join(t.TempDir(), "o")
	read := func() string { b, _ := os.ReadFile(o); return string(b) }
	in := twoSeg(t)
	if _, _, err := runCmd(t, "-O", "srec", "--srec-addr-len", "auto", "--srec-count", "--crlf", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	if s := read(); !strings.Contains(s, "\r\nS1") || !strings.Contains(s, "\r\nS5030002") || !strings.Contains(s, "\r\nS9") {
		t.Errorf("srec:\n%q", s)
	}
	if _, _, err := runCmd(t, "-O", "srec", "--srec-addr-len", "24", "-o", o, in); err != nil || !strings.Contains(read(), "\nS2") {
		t.Errorf("24: %v", err)
	}
	if _, _, err := runCmd(t, "-O", "srec", "--srec-addr-len", "16", "-o", o, in); err != nil || !strings.Contains(read(), "\nS1") {
		t.Errorf("16: %v", err)
	}
	if _, _, err := runCmd(t, "-O", "ihex", "--ihex-mode", "objcopy", "--crlf", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	if s := read(); !strings.Contains(s, ":04000003") || !strings.Contains(s, "\r\n") {
		t.Errorf("ihex:\n%q", s)
	}
	if _, _, err := runCmd(t, "-O", "ihex", "-o", o, in); err != nil || !strings.Contains(read(), ":04000005") {
		t.Errorf("ihex default: %v", err)
	}
}

func TestL2_Refusals(t *testing.T) {
	o := filepath.Join(t.TempDir(), "o")
	in := twoSeg(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--ihex-mode", "x"}, "--ihex-mode"},
		{[]string{"--srec-addr-len", "8"}, "--srec-addr-len"},
		{[]string{"--gap-fill", "300"}, "--gap-fill"},
		{[]string{"--pad", "1", "--gap-fill", "2"}, "same option"},
		{[]string{"--pad-to", "x"}, "--pad-to"},
		{[]string{"--change-addresses", "x"}, "--change-addresses"},
		{[]string{"--change-start", "x"}, "--change-start"},
		{[]string{"--change-start", "-0x2000"}, "address range overflows"},
		{[]string{"--change-addresses", "-0x1001"}, "address range overflows"},
		{[]string{"--pad-to", "0x20000000", "--max-size", "0x1000"}, "limit"},
		{[]string{"--gap-fill", "0", "--max-size", "4"}, "allowed size"},
		{[]string{"--srec-addr-len", "16", "--change-addresses", "0xf000"}, "address range overflows"},
	} {
		_, _, err := runCmd(t, append(append([]string{"-O", "srec", "-o", o}, tc.args...), in)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v", tc.args, err)
		}
	}
}

func TestL2_HelpListsHookFlags(t *testing.T) {
	out, _, err := runCmd(t, "--help")
	if err != nil || !strings.Contains(out, "--change-addresses") {
		t.Errorf("help: %v\n%s", err, out)
	}
}
