package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
)

// Each refusal of the FIT code has a case that names it: the message says which
// guard fired, and the exit code (2 usage, 1 failure) is the one it promises.
func TestFITGuards(t *testing.T) {
	dir := t.TempDir()
	in := simple(t)
	out := filepath.Join(dir, "o.fit")
	raw := put(t, "raw.bin", []byte("abcd"))
	dtb := filepath.Join(dir, "b.dtb")
	if err := os.WriteFile(dtb, []byte("dtb-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want string
		code int
	}{
		{"fit flag with another format", []string{"-O", "binary", "--fit-hash", "sha1", "-o", out, in}, "only for -O fit", 2},
		{"fit-external with another format", []string{"-O", "srec", "--fit-external", "-o", out, in}, "only for -O fit", 2},
		{"manifest", []string{"-O", "fit", "--manifest", filepath.Join(dir, "m.json"), "-o", out, in}, "carries its own hashes", 2},
		{"time with binary", []string{"-O", "binary", "--time", "5", "-o", out, in}, "--time is only for", 2},
		{"max-size", []string{"--max-size", "2", "-I", "binary", "--base", "0", "--entry", "0", "--uimage-arch", "arm", "-O", "fit", "-o", out, raw}, "limit 2", 1},
		{"raw needs an arch", []string{"-I", "binary", "--base", "0", "--entry", "0", "-O", "fit", "-o", out, raw}, "--uimage-arch is required", 2},
		{"raw needs an entry", []string{"-I", "binary", "--base", "0", "--uimage-arch", "arm", "-O", "fit", "-o", out, raw}, "--entry is required", 2},
		{"bad fit-align", []string{"-O", "fit", "--fit-external", "--fit-align", "zz", "-o", out, in}, "fit-align", 2},
		{"bad fit-position", []string{"-O", "fit", "--fit-external", "--fit-position", "zz", "-o", out, in}, "fit-position", 2},
		{"fit-add without a colon", []string{"-O", "fit", "--fit-add", "nocolon", "-o", out, in}, "want TYPE[@LOAD]:FILE", 2},
		{"fit-add without a file", []string{"-O", "fit", "--fit-add", "fdt:", "-o", out, in}, "want TYPE[@LOAD]:FILE", 2},
		{"fit-add bad load", []string{"-O", "fit", "--fit-add", "fdt@zz:" + dtb, "-o", out, in}, "fit-add", 2},
		{"fit-add missing file", []string{"-O", "fit", "--fit-add", "fdt:" + filepath.Join(dir, "none"), "-o", out, in}, "no such file", 1},
		{"a FIT is not converted", nil, "not of a conversion", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := tc.args
			if args == nil {
				fit := filepath.Join(dir, "k.fit")
				if _, _, err := runCmd(t, "-O", "fit", "-o", fit, in); err != nil {
					t.Fatal(err)
				}
				args = []string{"-o", out, fit}
			}
			_, _, err := runCmd(t, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
			if isUsage := errors.As(err, new(usageErr)); isUsage != (tc.code == 2) {
				t.Errorf("usage error = %v, want exit code %d", isUsage, tc.code)
			}
			if _, err := os.Stat(out); err == nil {
				t.Error("an output was left behind")
			}
		})
	}
}

func TestFITInfoVerifyGuards(t *testing.T) {
	dir := t.TempDir()
	in := simple(t)
	fit := filepath.Join(dir, "k.fit")
	if _, _, err := runCmd(t, "-O", "fit", "-o", fit, in); err != nil {
		t.Fatal(err)
	}
	man := filepath.Join(dir, "m.json")
	if _, _, err := runCmd(t, "-O", "binary", "--manifest", man, "-o", filepath.Join(dir, "o.bin"), in); err != nil {
		t.Fatal(err)
	}
	// A FIT carries its hashes: a manifest beside it is refused, with the reason.
	if _, _, err := runCmd(t, "verify", "--manifest", man, fit); err == nil || !strings.Contains(err.Error(), "carries its own hashes") {
		t.Errorf("verify --manifest FIT: %v", err)
	}
	// Without a manifest, a non-FIT says what is missing.
	if _, _, err := runCmd(t, "verify", in); err == nil || !strings.Contains(err.Error(), "--manifest FILE is required") {
		t.Errorf("verify without a manifest: %v", err)
	}
	// A manifest that does not read is reported before the image is.
	if _, _, err := runCmd(t, "verify", "--manifest", filepath.Join(dir, "none.json"), fit); err == nil || !strings.Contains(err.Error(), "none.json") {
		t.Errorf("verify, no manifest file: %v", err)
	}
	// A blob that is not a FIT, read as one.
	notFIT := put(t, "x.fit", []byte("\xd0\x0d\xfe\xed garbage that is not a devicetree"))
	for _, args := range [][]string{{"info", notFIT}, {"verify", notFIT}} {
		if _, _, err := runCmd(t, args...); err == nil || !strings.Contains(err.Error(), notFIT) {
			t.Errorf("%v: %v", args, err)
		}
	}
	// The listing and the JSON are two different outputs of the same FIT.
	listing, _, _ := runCmd(t, "info", fit)
	js, _, _ := runCmd(t, "info", "--json", fit)
	if strings.HasPrefix(listing, "{") || !strings.HasPrefix(js, "{") {
		t.Errorf("info prints %q and %q", listing, js)
	}
	// The match that verify prints names the FIT and what it checked.
	if stdout, _, err := runCmd(t, "verify", fit); err != nil || !strings.Contains(stdout, "1 images, 1 hashes, 1 configurations") {
		t.Errorf("verify: %v %q", err, stdout)
	}
}

// noPanic reports a crash as a failed assertion: a refusal that is only held by
// a crash further down is not a test of the refusal.
func noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: the refusal is missing, the code crashed instead: %v", what, r)
		}
	}()
	f()
}

// A uImage for an architecture the FIT specification has no name for cannot
// become a FIT, and the refusal says which code.
func TestFITUnnamedArch(t *testing.T) {
	in := uimageFile(t, []byte("data"), fwimg.UImageOptions{Arch: 4, Load: 0x100, Entry: 0x100})
	_, _, err := runCmd(t, "-O", "fit", "-o", filepath.Join(t.TempDir(), "o.fit"), in)
	if err == nil || !strings.Contains(err.Error(), "architecture code 4 has no FIT name") || !errors.As(err, new(usageErr)) {
		t.Fatalf("error %v", err)
	}
}

func TestFITCheck(t *testing.T) {
	noPanic(t, "fitCheck on garbage", func() {
		if err := fitCheck([]byte("not a FIT")); err == nil {
			t.Error("garbage passed fitCheck")
		}
	})
	dir := t.TempDir()
	fit := filepath.Join(dir, "k.fit")
	if _, _, err := runCmd(t, "-O", "fit", "-o", fit, simple(t)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(fit)
	if err := fitCheck(b); err != nil {
		t.Fatalf("a good FIT: %v", err)
	}
	i := strings.Index(string(b), "ABCD")
	b[i] ^= 1
	if err := fitCheck(b); err == nil {
		t.Error("a tampered FIT passed fitCheck")
	}
}
