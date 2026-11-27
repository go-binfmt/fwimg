package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
)

func TestFITConvertInfoVerify(t *testing.T) {
	dir := t.TempDir()
	in := simple(t)
	dtb := filepath.Join(dir, "board.dtb")
	if err := os.WriteFile(dtb, []byte("0123456789abcdef-dtb"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"embedded", nil},
		{"crc", []string{"--fit-hash", "crc32,sha1,sha256"}},
		{"external", []string{"--fit-external"}},
		{"aligned", []string{"--fit-external", "--fit-align", "40"}},
		{"positioned", []string{"--fit-external", "--fit-position", "0x1000"}},
		{"added", []string{"--fit-add", "fdt:" + dtb, "--fit-add", "ramdisk@0x8000000:" + dtb, "--name", "board"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(dir, tc.name+".fit")
			args := append([]string{"-O", "fit", "--time", "1700000000", "-o", out}, tc.args...)
			if _, _, err := runCmd(t, append(args, in)...); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(out)
			if got := fwimg.Detect(b); got != fwimg.FormatFIT {
				t.Fatalf("Detect = %q", got)
			}
			f, err := fwimg.ParseFIT(b)
			if err != nil {
				t.Fatal(err)
			}
			k := f.Image("kernel-1")
			if k == nil || string(k.Data) != "ABCD" || k.Load != 0x80000 || k.Entry != 0x80004 || k.Arch != "arm64" {
				t.Fatalf("kernel %+v", k)
			}
			stdout, _, err := runCmd(t, "info", out)
			if err != nil || !strings.Contains(stdout, "Image 0 (kernel-1)") || !strings.Contains(stdout, "Default Configuration: 'conf-1'") {
				t.Fatalf("info: %v\n%s", err, stdout)
			}
			stdout, _, err = runCmd(t, "info", "--json", out)
			var j fitJSON
			if err != nil || json.Unmarshal([]byte(stdout), &j) != nil || j.Format != "fit" || len(j.Images) != len(f.Images) || j.Images[0].Size != 4 {
				t.Fatalf("info --json: %v\n%s", err, stdout)
			}
			stdout, _, err = runCmd(t, "verify", "--require-hash", out)
			if err != nil || !strings.Contains(stdout, "FIT ok") {
				t.Fatalf("verify: %v\n%s", err, stdout)
			}
		})
	}
}

func TestFITVerifyCatchesTampering(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "k.fit")
	if _, _, err := runCmd(t, "-O", "fit", "-o", out, simple(t)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	i := strings.Index(string(b), "ABCD")
	if i < 0 {
		t.Fatal("payload not found")
	}
	b[i] ^= 1
	bad := filepath.Join(dir, "bad.fit")
	if err := os.WriteFile(bad, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd(t, "verify", bad); !errors.Is(err, fwimg.ErrChecksum) {
		t.Errorf("tampered FIT verified: %v", err)
	}
	// info still lists it: it reads, it does not judge.
	if _, _, err := runCmd(t, "info", bad); err != nil {
		t.Errorf("info: %v", err)
	}
	// A hashless FIT is refused under --require-hash.
	nh := filepath.Join(dir, "nh.fit")
	if _, _, err := runCmd(t, "-O", "fit", "--fit-hash", "crc32", "-o", nh, simple(t)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd(t, "verify", "--require-hash", nh); err != nil {
		t.Errorf("crc32 is a hash: %v", err)
	}
}

func TestFITRefusals(t *testing.T) {
	dir := t.TempDir()
	in := simple(t)
	out := filepath.Join(dir, "o.fit")
	for name, args := range map[string][]string{
		"fit flag, other format": {"-O", "binary", "--fit-external", "-o", out, in},
		"manifest":               {"-O", "fit", "--manifest", filepath.Join(dir, "m.json"), "-o", out, in},
		"align w/o external":     {"-O", "fit", "--fit-align", "10", "-o", out, in},
		"align not pow2":         {"-O", "fit", "--fit-external", "--fit-align", "30", "-o", out, in},
		"position w/o external":  {"-O", "fit", "--fit-position", "0x1000", "-o", out, in},
		"unknown hash":           {"-O", "fit", "--fit-hash", "rot13", "-o", out, in},
		"bad add":                {"-O", "fit", "--fit-add", "nocolon", "-o", out, in},
		"missing add file":       {"-O", "fit", "--fit-add", "fdt:" + filepath.Join(dir, "none"), "-o", out, in},
		"time, other format":     {"-O", "srec", "--time", "5", "-o", out, in},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := runCmd(t, args...); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("an output was left behind")
			}
		})
	}
	// A FIT is not converted, and a non-FIT is not a FIT.
	fit := filepath.Join(dir, "k.fit")
	if _, _, err := runCmd(t, "-O", "fit", "-o", fit, in); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd(t, "-o", out, fit); err == nil {
		t.Error("a FIT was converted")
	}
	if _, _, err := runCmd(t, "info", "-I", "fit", in); err == nil {
		t.Error("an ELF read as a FIT")
	}
	if _, _, err := runCmd(t, "verify", in); err == nil {
		t.Error("verify without a manifest accepted an ELF")
	}
}
