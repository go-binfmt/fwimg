package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
)

func l5Payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/13)
	}
	return b
}

func TestL5_UImageCompressionRoundTrip(t *testing.T) {
	raw := l5Payload(3000)
	in := put(t, "in.bin", raw)
	for _, comp := range []string{"gzip", "lz4"} {
		o := out(t)
		if _, _, err := runCmd(t, "-I", "binary", "--base", "0x8000", "-O", "uimage", "--uimage-comp", comp, "--uimage-arch", "arm", "--entry", "0x8000", "-o", o, in); err != nil {
			t.Fatalf("%s: %v", comp, err)
		}
		h, _, err := fwimg.ParseUImage(get(t, o))
		want, _ := fwimg.CompFromName(comp)
		if err != nil || h.Comp != want || h.Size >= 3000 {
			t.Errorf("%s: header %+v %v", comp, h, err)
		}
		// back to a flat binary: decompressed
		flat := out(t)
		if _, _, err := runCmd(t, "-o", flat, o); err != nil || !bytes.Equal(get(t, flat), raw) {
			t.Errorf("%s: back to binary: %v", comp, err)
		}
		// info lists the compression the way mkimage -l does
		stdout, _, err := runCmd(t, "info", o)
		if err != nil || !strings.Contains(stdout, "("+comp+" compressed)") {
			t.Errorf("%s: info: %v\n%s", comp, err, stdout)
		}
		// the manifest written with the file describes the program, and verifies it
		js, _, err := runCmd(t, "info", "--json", o)
		if err != nil || !strings.Contains(js, `"uimage"`) {
			t.Fatalf("%s: info --json: %v", comp, err)
		}
		man := put(t, "m.json", []byte(js))
		if _, _, err := runCmd(t, "verify", "--manifest", man, o); err != nil {
			t.Errorf("%s: verify: %v", comp, err)
		}
		// the manifest describes the decompressed program: size 3000
		if !strings.Contains(js, `"size": 3000`) {
			t.Errorf("%s: manifest does not describe the decompressed image:\n%s", comp, js)
		}
	}
}

func TestL5_UF2(t *testing.T) {
	raw := l5Payload(700)
	in := put(t, "in.bin", raw)
	o := out(t)
	if _, _, err := runCmd(t, "-I", "binary", "--base", "0x10000000", "-O", "uf2", "--uf2-family", "rp2040", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	b := get(t, o)
	if len(b) != 3*512 || b[0] != 'U' || b[1] != 'F' || b[2] != '2' {
		t.Fatalf("%d bytes", len(b))
	}
	im, err := fwimg.DecodeUF2(b, fwimg.DecodeOptions{})
	if err != nil || im.Family != 0xe48bff56 || im.Base() != 0x10000000 {
		t.Fatalf("%v %v", im, err)
	}
	// uf2 as an input, detected; the last block's padding is part of the image
	flat := out(t)
	if _, _, err := runCmd(t, "-o", flat, o); err != nil || !bytes.Equal(get(t, flat)[:700], raw) || len(get(t, flat)) != 768 {
		t.Errorf("uf2 to binary: %v", err)
	}
	stdout, _, err := runCmd(t, "info", o)
	if err != nil || !strings.Contains(stdout, "Format:   uf2") || !strings.Contains(stdout, "0x10000000") {
		t.Errorf("info: %v\n%s", err, stdout)
	}
	// a manifest of the uf2, verified against the file
	man := out(t)
	again := out(t)
	// (768 bytes: a whole number of 256-byte blocks, so there is no padding)
	if _, _, err := runCmd(t, "-I", "binary", "--base", "0x10000000", "-O", "uf2", "--manifest", man, "-o", again, put(t, "full.bin", l5Payload(768))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd(t, "verify", "--manifest", man, again); err != nil {
		t.Errorf("verify: %v", err)
	}
	// a flipped byte is refused
	bad := append([]byte(nil), b...)
	bad[510] ^= 1
	if _, _, err := runCmd(t, "info", put(t, "bad.uf2", bad)); err == nil {
		t.Error("a UF2 file with a damaged end magic was accepted")
	}
}

func TestL5_Verilog(t *testing.T) {
	raw := l5Payload(40)
	in := put(t, "in.bin", raw)
	for _, endian := range []string{"little", "big"} {
		for _, w := range []string{"1", "4", "8"} {
			o := out(t)
			args := []string{"-I", "binary", "--base", "0x1000", "-O", "verilog", "--verilog-data-width", w, "--verilog-endian", endian, "-o", o, in}
			if _, _, err := runCmd(t, args...); err != nil {
				t.Fatalf("%s %s: %v", endian, w, err)
			}
			text := get(t, o)
			if !bytes.HasPrefix(text, []byte("@")) || !bytes.Contains(text, []byte("\r\n")) {
				t.Errorf("%s %s: %q", endian, w, text)
			}
			flat := out(t)
			if _, _, err := runCmd(t, "-I", "verilog", "--verilog-data-width", w, "--verilog-endian", endian, "-O", "binary", "-o", flat, o); err != nil || !bytes.Equal(get(t, flat), raw) {
				t.Errorf("%s %s: back: %v", endian, w, err)
			}
		}
	}
	// a Verilog file is detected by its first '@'
	o := out(t)
	if _, _, err := runCmd(t, "-I", "binary", "--base", "0", "-O", "verilog", "-o", o, in); err != nil {
		t.Fatal(err)
	}
	flat := out(t)
	if _, _, err := runCmd(t, "-O", "binary", "-o", flat, o); err != nil || !bytes.Equal(get(t, flat), raw) {
		t.Errorf("detected: %v", err)
	}
	stdout, _, err := runCmd(t, "info", o)
	if err != nil || !strings.Contains(stdout, "Format:   verilog") {
		t.Errorf("info: %v\n%s", err, stdout)
	}
}

func TestL5_FlagRefusals(t *testing.T) {
	in := put(t, "in.bin", []byte("abcd"))
	base := []string{"-I", "binary", "--base", "0x1000"}
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"comp without uimage": {[]string{"-O", "srec", "--uimage-comp", "gzip"}, "only for -O uimage"},
		"unknown comp":        {[]string{"-O", "uimage", "--uimage-comp", "bzip2", "--uimage-arch", "arm", "--entry", "0"}, "bzip2"},
		"family without uf2":  {[]string{"-O", "srec", "--uf2-family", "rp2040"}, "only for -O uf2"},
		"unknown family":      {[]string{"-O", "uf2", "--uf2-family", "nosuchchip"}, "nosuchchip"},
		"zero family":         {[]string{"-O", "uf2", "--uf2-family", "0"}, "non-zero"},
		"width 0":             {[]string{"-O", "verilog", "--verilog-data-width", "0"}, "1 to 8"},
		"width 9":             {[]string{"-O", "verilog", "--verilog-data-width", "9"}, "1 to 8"},
		"bad endian":          {[]string{"-O", "verilog", "--verilog-endian", "middle"}, "little or big"},
		"unaligned verilog":   {[]string{"-O", "verilog", "--verilog-data-width", "8"}, "multiple of the data width"},
		"unaligned uf2":       {[]string{"-O", "uf2", "--base", "0x1001"}, "UF2"},
	} {
		args := append(append([]string{}, base...), c.args...)
		if name == "unaligned uf2" {
			args = []string{"-I", "binary", "--base", "0x1001", "-O", "uf2"}
		}
		if name == "unaligned verilog" {
			args = []string{"-I", "binary", "--base", "0x1004", "-O", "verilog", "--verilog-data-width", "8"}
		}
		args = append(args, "-o", out(t), in)
		_, _, err := runCmd(t, args...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
}
