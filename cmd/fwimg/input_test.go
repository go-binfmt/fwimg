package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
	"github.com/go-binfmt/fwimg/internal/elfgen"
)

func put(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func get(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func out(t *testing.T) string { return filepath.Join(t.TempDir(), "out") }

// srecFile and ihexFile make small valid inputs with this package's encoders.
func srecFile(t *testing.T, addr uint32, data string, entry uint32) string {
	t.Helper()
	b, err := fwimg.SREC(addr, []byte(data), "nm", entry, 0)
	if err != nil {
		t.Fatal(err)
	}
	return put(t, "in.srec", b)
}

func ihexFile(t *testing.T, addr uint32, data string) string {
	t.Helper()
	b, err := fwimg.IHEX(addr, []byte(data), 0)
	if err != nil {
		t.Fatal(err)
	}
	return put(t, "in.hex", b)
}

func uimageFile(t *testing.T, payload []byte, o fwimg.UImageOptions) string {
	t.Helper()
	b, err := fwimg.UImage(payload, o)
	if err != nil {
		t.Fatal(err)
	}
	return put(t, "in.uimg", b)
}

func TestInputs_AnyToAny(t *testing.T) {
	const data = "FIRMWARE"
	inputs := map[string]struct {
		path string
		args []string
	}{
		"ihex":   {ihexFile(t, 0x8000, data), nil},
		"srec":   {srecFile(t, 0x8000, data, 0x8004), nil},
		"binary": {put(t, "in.bin", []byte(data)), []string{"-I", "binary", "--base", "0x8000"}},
		"uimage": {uimageFile(t, []byte(data), fwimg.UImageOptions{Load: 0x8000, Entry: 0x8004, Name: "nm"}), nil},
		"elf": {writeELF(t, elf.EM_ARM, 0x8004, elfgen.Seg{Paddr: 0x8000, Off: 0x200, Filesz: 8, Memsz: 8, Data: []byte(data)}),
			nil},
	}
	for name, in := range inputs {
		for _, format := range []string{"binary", "srec", "ihex", "uimage"} {
			t.Run(name+"_to_"+format, func(t *testing.T) {
				o := out(t)
				args := append([]string{"-O", format, "-o", o}, in.args...)
				if format == "uimage" && (name == "ihex" || name == "binary" || name == "srec") {
					args = append(args, "--uimage-arch", "arm", "--entry", "0x8004")
				}
				if _, _, err := runCmd(t, append(args, in.path)...); err != nil {
					t.Fatal(err)
				}
				got := get(t, o)
				// Read it back with the other direction of the tool.
				switch format {
				case "binary":
					if string(got) != data {
						t.Errorf("binary = %q", got)
					}
				case "srec":
					im, err := fwimg.DecodeSREC(got, fwimg.DecodeOptions{})
					if err != nil || im.Base() != 0x8000 || string(im.Segments[0].Data) != data {
						t.Errorf("srec: %v %v", im, err)
					}
				case "ihex":
					im, err := fwimg.DecodeIHEX(got, fwimg.DecodeOptions{})
					if err != nil || im.Base() != 0x8000 || string(im.Segments[0].Data) != data {
						t.Errorf("ihex: %v %v", im, err)
					}
				case "uimage":
					h, p, err := fwimg.ParseUImage(got)
					if err != nil || h.Load != 0x8000 || string(p) != data {
						t.Errorf("uimage: %v %v", h, err)
					}
				}
			})
		}
	}
}

func TestInputs_EntryAndName(t *testing.T) {
	// srec -> srec keeps the S0 name and the S7 address; --entry and --name win.
	in := srecFile(t, 0x100, "ab", 0x104)
	o := out(t)
	if _, _, err := runCmd(t, "-I", "srec", "-O", "srec", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	im, err := fwimg.DecodeSREC(get(t, o), fwimg.DecodeOptions{})
	if err != nil || im.Entry != 0x104 || im.Name != "nm" {
		t.Errorf("kept: %v %v", im, err)
	}
	if _, _, err := runCmd(t, "-O", "srec", "--entry", "0x200", "--name", "new", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	if im, err = fwimg.DecodeSREC(get(t, o), fwimg.DecodeOptions{}); err != nil || im.Entry != 0x200 || im.Name != "new" {
		t.Errorf("overridden: %v %v", im, err)
	}
	// srec -> ihex carries the start address; ihex -> uimage needs one.
	if _, _, err := runCmd(t, "-O", "ihex", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(get(t, o)), ":0400000500000104F2") {
		t.Errorf("no type 05 record:\n%s", get(t, o))
	}
	// An ELF to ihex carries its start address as a type 05 record (since
	// v0.4.0; v0.2.1 left it out).
	e := simple(t)
	if _, _, err := runCmd(t, "-O", "ihex", "-o", o, e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(get(t, o)), ":04000005") {
		t.Errorf("an ELF's start address is not written to ihex:\n%s", get(t, o))
	}
	// --entry gives an ELF's ihex one.
	if _, _, err := runCmd(t, "-O", "ihex", "--entry", "0x80004", "-o", o, e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(get(t, o)), ":0400000500080004") {
		t.Errorf("--entry not written:\n%s", get(t, o))
	}
}

func TestInputs_LoadMovesTheImageNotTheEntry(t *testing.T) {
	in := srecFile(t, 0x100, "ab", 0x104)
	o := out(t)
	if _, _, err := runCmd(t, "-O", "srec", "--load", "0x2000", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	im, err := fwimg.DecodeSREC(get(t, o), fwimg.DecodeOptions{})
	if err != nil || im.Base() != 0x2000 || im.Entry != 0x104 {
		t.Errorf("%v %v", im, err)
	}
	// A sparse hex file keeps its gap in hex and srec, and fills it in binary.
	sparse := fwimg.Image{Segments: []fwimg.Segment{{Addr: 0x10, Data: []byte("A")}, {Addr: 0x14, Data: []byte("B")}}}
	text, err := fwimg.EncodeIHEX(&sparse, 0)
	if err != nil {
		t.Fatal(err)
	}
	hx := put(t, "s.hex", text)
	if _, _, err := runCmd(t, "--pad", "0xAA", "-o", o, hx); err != nil {
		t.Fatal(err)
	}
	if string(get(t, o)) != "A\xaa\xaa\xaaB" {
		t.Errorf("flat = %q", get(t, o))
	}
	if _, _, err := runCmd(t, "-O", "srec", "-o", o, hx); err != nil {
		t.Fatal(err)
	}
	if im, err := fwimg.DecodeSREC(get(t, o), fwimg.DecodeOptions{}); err != nil || len(im.Segments) != 2 {
		t.Errorf("srec of a sparse image: %v %v", im, err)
	}
}

func TestInputs_UImageKeepsItsHeaderFields(t *testing.T) {
	in := uimageFile(t, []byte("data"), fwimg.UImageOptions{Load: 0x1000, Entry: 0x1008, Name: "keep", Arch: fwimg.ArchRISCV, OS: 17, Type: fwimg.TypeFirmware})
	o := out(t)
	if _, _, err := runCmd(t, "-O", "uimage", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	h, _, err := fwimg.ParseUImage(get(t, o))
	if err != nil || h.Arch != fwimg.ArchRISCV || h.OS != 17 || h.Type != fwimg.TypeFirmware || h.Name != "keep" || h.Entry != 0x1008 {
		t.Errorf("%+v %v", h, err)
	}
	// A flag wins over the header.
	if _, _, err := runCmd(t, "-O", "uimage", "--uimage-arch", "arm64", "--uimage-os", "5", "--uimage-type", "2", "--name", "n2", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	if h, _, err = fwimg.ParseUImage(get(t, o)); err != nil || h.Arch != fwimg.ArchARM64 || h.OS != 5 || h.Type != 2 || h.Name != "n2" {
		t.Errorf("%+v %v", h, err)
	}
}

func TestInputs_Refusals(t *testing.T) {
	garbage := put(t, "g", []byte("hello world"))
	elfPath := simple(t)
	raw := put(t, "raw", []byte("rawbytes"))
	badSum := ihexFile(t, 0, "a")
	b := get(t, badSum)
	b[len(b)-20] ^= 1
	badSum = put(t, "bad.hex", b)
	gz := uimageFile(t, []byte("zz"), fwimg.UImageOptions{Comp: fwimg.CompGzip})
	noEntry := ihexFile(t, 0, "a")
	var many strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&many, ":01%04X0001%02X\n", 2*i, byte(-(1 + byte(2*i>>8) + byte(2*i) + 1)))
	}
	many.WriteString(":00000001FF\n")
	bomb := put(t, "bomb.hex", []byte(many.String()))
	o := out(t)
	cases := []struct {
		name string
		args []string
		want string
		code int
	}{
		{"unrecognised input is never read as binary", []string{"-o", o, garbage}, "-I binary --base", 1},
		{"-I binary needs --base", []string{"-I", "binary", "-o", o, raw}, "--base", 2},
		{"--base without -I binary", []string{"--base", "0x10", "-o", o, raw}, "only for -I binary", 2},
		{"--base without -I binary, forced elf", []string{"-I", "elf", "--base", "0x10", "-o", o, elfPath}, "only for -I binary", 2},
		{"bad --base", []string{"-I", "binary", "--base", "zz", "-o", o, raw}, "--base", 2},
		{"unknown -I", []string{"-I", "coff", "-o", o, raw}, "unknown --input-target", 2},
		{"-I elf on garbage names the file", []string{"-I", "elf", "-o", o, garbage}, garbage + ": ", 1},
		{"-I elf on a hex file", []string{"-I", "elf", "-o", o, ihexFile(t, 0, "a")}, "ELF", 1},
		{"-I ihex on an ELF", []string{"-I", "ihex", "-o", o, elfPath}, "ihex line 1", 1},
		{"-I srec on a hex file", []string{"-I", "srec", "-o", o, ihexFile(t, 0, "a")}, "srec line 1", 1},
		{"-I uimage on a raw file", []string{"-I", "uimage", "-o", o, raw}, "uimage", 1},
		{"bad checksum", []string{"-o", o, badSum}, "checksum", 1},
		{"uimage whose gzip payload is not gzip", []string{"-o", o, gz}, "malformed", 1},
		{"raw to uimage needs an arch", []string{"-I", "binary", "--base", "0", "--entry", "0", "-O", "uimage", "-o", o, raw}, "--uimage-arch is required", 2},
		{"hex to uimage needs an entry", []string{"-O", "uimage", "--uimage-arch", "arm", "-o", o, noEntry}, "--entry is required", 2},
		{"raw base above 32 bits to srec", []string{"-I", "binary", "--base", "0x100000000", "-O", "srec", "-o", o, raw}, "image base", 1},
		{"raw base above 32 bits to uimage", []string{"-I", "binary", "--base", "0x100000000", "-O", "uimage", "--uimage-arch", "arm", "--entry", "0", "-o", o, raw}, "image base", 1},
		{"raw past 2^64", []string{"-I", "binary", "--base", "0xFFFFFFFFFFFFFFFE", "-o", o, raw}, "address", 1},
		{"max-size bounds a text decoder", []string{"--max-size", "1000", "-o", o, bomb}, "more than", 1},
		{"max-size bounds a flat image", []string{"--max-size", "3", "-o", o, ihexFile(t, 0, "abcdef")}, "more than", 1},
		{"uimage max-size", []string{"--max-size", "2", "-O", "uimage", "--uimage-arch", "arm", "--entry", "0", "-I", "binary", "--base", "0", "-o", o, raw}, "limit 2", 1},
		{"binary max-size", []string{"--max-size", "2", "-I", "binary", "--base", "0", "-o", o, raw}, "limit 2", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := runCmd(t, c.args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to contain %q", err, c.want)
			}
			if _, isUsage := err.(usageErr); isUsage != (c.code == 2) {
				t.Errorf("usage error = %v, want %v", isUsage, c.code == 2)
			}
			if _, statErr := os.Stat(o); statErr == nil {
				t.Errorf("a refused run wrote %s", o)
			}
		})
	}
}

func TestInfo(t *testing.T) {
	in := uimageFile(t, make([]byte, 3000), fwimg.UImageOptions{Load: 0x8000, Entry: 0x8040, Name: "boot", Time: 1700000000})
	stdout, _, err := runCmd(t, "info", in)
	if err != nil {
		t.Fatal(err)
	}
	want := "Image Name:   boot\n" +
		"Created:      Tue Nov 14 22:13:20 2023\n" +
		"Image Type:   ARM Linux Kernel Image (uncompressed)\n" +
		"Data Size:    3000 Bytes = 2.93 KiB = 0.00 MiB\n" +
		"Load Address: 00008000\n" +
		"Entry Point:  00008040\n"
	if stdout != want {
		t.Errorf("got:\n%s\nwant:\n%s", stdout, want)
	}
	// A multi-file image lists its contents.
	p := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 4), 2), 0)
	p = append(p, 'a', 'b', 'c', 'd', 'e', 'f', 0, 0)
	m := uimageFile(t, p, fwimg.UImageOptions{Type: fwimg.TypeMulti})
	stdout, _, err = runCmd(t, "info", m)
	if err != nil || !strings.Contains(stdout, "Contents:\n   Image 0: 4 Bytes") || !strings.Contains(stdout, "   Image 1: 2 Bytes") {
		t.Errorf("multi: %v\n%s", err, stdout)
	}
	// Refusals.
	bad := get(t, in)
	bad[70] ^= 1
	truncMulti := uimageFile(t, []byte{0, 0, 0, 1}, fwimg.UImageOptions{Type: fwimg.TypeMulti})
	for name, c := range map[string]struct {
		args []string
		want string
		code int
	}{
		"not a format":    {[]string{"info", put(t, "x", []byte("nope"))}, "a raw binary is read only with -I binary", 1},
		"data CRC":        {[]string{"info", put(t, "bad", bad)}, "checksum", 1},
		"bad multi table": {[]string{"info", truncMulti}, "size table", 1},
		"missing":         {[]string{"info", filepath.Join(t.TempDir(), "absent")}, "no such file", 1},
		"no argument":     {[]string{"info"}, "accepts 1 arg", 2},
		"two arguments":   {[]string{"info", in, in}, "accepts 1 arg", 2},
	} {
		_, _, err := runCmd(t, c.args...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
			continue
		}
		if _, isUsage := err.(usageErr); isUsage != (c.code == 2) {
			t.Errorf("%s: usage error = %v", name, isUsage)
		}
	}
}

func TestInfo_WriteErrorIsReturned(t *testing.T) {
	in := uimageFile(t, []byte("x"), fwimg.UImageOptions{})
	cmd := RootCmd()
	cmd.SetOut(failWriter{})
	cmd.SetArgs([]string{"info", in})
	if err := cmd.Execute(); err == nil {
		t.Error("a failed write was not reported")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestUImageHeaderCRCsHoldAfterConversion(t *testing.T) {
	o := out(t)
	if _, _, err := runCmd(t, "-I", "binary", "--base", "0x100", "-O", "uimage", "--uimage-arch", "arm64", "--entry", "0x100", "-o", o, put(t, "r", []byte("abc"))); err != nil {
		t.Fatal(err)
	}
	b := get(t, o)
	if binary.BigEndian.Uint32(b[24:]) != crc32.ChecksumIEEE([]byte("abc")) || !bytes.Equal(b[64:], []byte("abc")) {
		t.Error("data CRC or payload wrong")
	}
}

func TestInputs_ELFEntryAbove32BitsIsRefusedForSRECAndIHEXUnlessGiven(t *testing.T) {
	in := writeELF(t, elf.EM_X86_64, 0xffffffff80001000, elfgen.Seg{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")})
	o := out(t)
	if _, _, err := runCmd(t, "-O", "srec", "-o", o, in); err == nil || !strings.Contains(err.Error(), "ELF entry") {
		t.Errorf("srec: %v", err)
	}
	// ihex writes the start record since v0.4.0, so it refuses the same way.
	if _, _, err := runCmd(t, "-O", "ihex", "-o", o, in); err == nil || !strings.Contains(err.Error(), "ELF entry") {
		t.Errorf("ihex: %v", err)
	}
	if _, _, err := runCmd(t, "-O", "ihex", "--entry", "0x1000", "-o", o, in); err != nil {
		t.Errorf("ihex with --entry: %v", err)
	}
	if _, _, err := runCmd(t, "-O", "srec", "--entry", "0x1000", "-o", o, in); err != nil {
		t.Errorf("srec with --entry: %v", err)
	}
}
