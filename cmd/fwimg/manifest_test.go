package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
)

func readM(t *testing.T, p string) *fwimg.Manifest {
	t.Helper()
	m, err := fwimg.ReadManifest(get(t, p))
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return m
}

func TestManifestFlag_EveryFormatThenVerifyAnyFormat(t *testing.T) {
	in := twoSeg(t) // 4 bytes at 0x1000 and 4 at 0x1010
	dir := t.TempDir()
	mf := filepath.Join(dir, "fw.json")
	for _, f := range []string{"ihex", "srec", "uimage", "binary"} {
		o := filepath.Join(dir, "fw."+f)
		args := []string{"-O", f, "--manifest", mf, "--region", "FLASH=0x1000:0x100", "-o", o, in}
		if f == "uimage" {
			args = append(args, "--load", "0x1000")
		}
		if _, _, err := runCmd(t, args...); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		m := readM(t, mf)
		if m.Format != f || m.Source == nil || m.Source.File != "in.elf" || m.Source.Format != "elf" || len(m.Regions) != 1 {
			t.Errorf("%s: %+v", f, m)
		}
		if (f == "uimage") != (m.UImage != nil) {
			t.Errorf("%s: uimage block %+v", f, m.UImage)
		}
		// The manifest checks the file it was written with.
		args = []string{"verify", "--manifest", mf, o}
		if f == "binary" {
			args = append(args, "-I", "binary", "--base", "0x1000")
		}
		if f == "uimage" {
			// A uImage is read as stored: its payload, based at its load address,
			// is the image the manifest was made from.
			args = []string{"verify", "--manifest", mf, "-I", "uimage", o}
		}
		stdout, _, err := runCmd(t, args...)
		if err != nil || !strings.Contains(stdout, "matches") {
			t.Errorf("%s: verify: %v %s", f, err, stdout)
		}
	}
	// A manifest of the ihex output also checks the srec one.
	if _, _, err := runCmd(t, "-O", "ihex", "--manifest", mf, "-o", filepath.Join(dir, "a.hex"), in); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd(t, "verify", "--manifest", mf, filepath.Join(dir, "fw.srec")); err != nil {
		t.Errorf("srec against the ihex manifest: %v", err)
	}
	// And the ELF itself: its image is the same bytes.
	if _, _, err := runCmd(t, "verify", "--manifest", mf, in); err != nil {
		t.Errorf("elf against the manifest: %v", err)
	}
}

func TestManifestFlag_DeterministicAndClockOnlyFromSourceDateEpoch(t *testing.T) {
	in := sectionedELF(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	for _, p := range []string{a, b} {
		if _, _, err := runCmd(t, "-O", "ihex", "--manifest", p, "-o", filepath.Join(dir, "o.hex"), in); err != nil {
			t.Fatal(err)
		}
	}
	if string(get(t, a)) != string(get(t, b)) || strings.Contains(string(get(t, a)), "created") {
		t.Errorf("not reproducible or has a clock:\n%s", get(t, a))
	}
	if m := readM(t, a); len(m.Sections) == 0 {
		t.Error("an ELF input lists its sections")
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	if _, _, err := runCmd(t, "-O", "ihex", "--manifest", a, "-o", filepath.Join(dir, "o.hex"), in); err != nil {
		t.Fatal(err)
	}
	if m := readM(t, a); m.Created != "2023-11-14T22:13:20Z" {
		t.Errorf("created %q", m.Created)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "tomorrow")
	if _, _, err := runCmd(t, "-O", "ihex", "--manifest", a, "-o", filepath.Join(dir, "o.hex"), in); err == nil {
		t.Error("a bad SOURCE_DATE_EPOCH accepted by --manifest")
	}
	if _, _, err := runCmd(t, "info", "--json", in); err == nil {
		t.Error("a bad SOURCE_DATE_EPOCH accepted by info")
	}
}

func TestManifestFlag_Refusals(t *testing.T) {
	in := simple(t)
	dir := t.TempDir()
	o := filepath.Join(dir, "o")
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"same file":  {[]string{"--manifest", o, "-o", o, in}, "name the same file"},
		"unwritable": {[]string{"--manifest", filepath.Join(dir, "no", "such", "m.json"), "-o", o, in}, "no such file"},
		"too large":  {[]string{"--manifest", filepath.Join(dir, "m.json"), "--max-size", "2", "-o", o, in}, "limit"},
	} {
		if _, _, err := runCmd(t, c.args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestManifest_UImageHeaderDefaultsAndName(t *testing.T) {
	dir := t.TempDir()
	mf := filepath.Join(dir, "m.json")
	long := strings.Repeat("n", 40)
	args := []string{"-O", "uimage", "--name", long, "--manifest", mf, "-o", filepath.Join(dir, "u"), simple(t)}
	if _, _, err := runCmd(t, args...); err != nil {
		t.Fatal(err)
	}
	if u := readM(t, mf).UImage; u == nil || u.Name != long[:31] || u.OS != fwimg.OSLinux || u.Type != fwimg.TypeKernel {
		t.Errorf("%+v", u)
	}
	// The command always gives an architecture; the helper still mirrors the
	// library's defaults for whoever does not.
	if h := uimageHeader(fwimg.UImageOptions{}); h.OS != fwimg.OSLinux || h.Arch != fwimg.ArchARM || h.Type != fwimg.TypeKernel {
		t.Errorf("defaults: %+v", h)
	}
	if h := uimageHeader(fwimg.UImageOptions{OS: 1, Arch: 2, Type: 3}); h.OS != 1 || h.Arch != 2 || h.Type != 3 {
		t.Errorf("explicit values are kept: %+v", h)
	}
}

func TestManifest_MalformedSectionTableIsRefusedNotIgnored(t *testing.T) {
	whole := get(t, sectionedELF(t))
	cut := put(t, "cut.elf", whole[:len(whole)-1])
	for _, args := range [][]string{
		{"info", "--json", cut},
		{"-O", "ihex", "--manifest", filepath.Join(t.TempDir(), "m.json"), "-o", filepath.Join(t.TempDir(), "o"), cut},
	} {
		if _, _, err := runCmd(t, args...); err == nil || !strings.Contains(err.Error(), "section header table") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestManifest_BoundIsAppliedToTheHashedImageToo(t *testing.T) {
	// The flat image is never built for ihex output, so the bound is the
	// manifest's to check.
	_, _, err := runCmd(t, "-O", "ihex", "--max-size", "8", "--manifest", filepath.Join(t.TempDir(), "m.json"), "-o", out(t), twoSeg(t))
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("%v", err)
	}
}

func TestInfo_EmptyUImage(t *testing.T) {
	u := uimageFile(t, nil, fwimg.UImageOptions{Name: "empty"})
	stdout, _, err := runCmd(t, "info", u)
	if err != nil || !strings.Contains(stdout, "Data Size:    0 Bytes") {
		t.Errorf("%v\n%s", err, stdout)
	}
}

func TestInfo_EveryInputFormat(t *testing.T) {
	dir := t.TempDir()
	raw := put(t, "fw.bin", []byte("abcdefgh"))
	for name, c := range map[string]struct {
		args   []string
		format string
		entry  string
		base   string
	}{
		"elf":    {[]string{simple(t)}, "elf", "0x80004", "0x80000"},
		"ihex":   {[]string{ihexFile(t, 0x1000, "abcd")}, "ihex", "none", "0x1000"},
		"srec":   {[]string{srecFile(t, 0x2000, "abcd", 0x2002)}, "srec", "0x2002", "0x2000"},
		"binary": {[]string{"-I", "binary", "--base", "0x8000000", raw}, "binary", "none", "0x8000000"},
	} {
		stdout, _, err := runCmd(t, append([]string{"info"}, c.args...)...)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, w := range []string{"Format:   " + c.format, "Entry:    " + c.entry, "Base:     " + c.base, "CRC-32:", "SHA-256:", "Segments: 1"} {
			if !strings.Contains(stdout, w) {
				t.Errorf("%s: %q missing from\n%s", name, w, stdout)
			}
		}
		js, _, err := runCmd(t, append([]string{"info", "--json"}, c.args...)...)
		if err != nil {
			t.Errorf("%s --json: %v", name, err)
			continue
		}
		m, err := fwimg.ReadManifest([]byte(js))
		if err != nil || m.Format != c.format || m.Base != c.base {
			t.Errorf("%s --json: %v %+v", name, err, m)
		}
		if !json.Valid([]byte(js)) {
			t.Errorf("%s: invalid JSON", name)
		}
	}
	// An ELF lists its sections, and a uImage as JSON is a manifest too.
	stdout, _, err := runCmd(t, "info", sectionedELF(t))
	if err != nil || !strings.Contains(stdout, "Sections:") {
		t.Errorf("sections: %v\n%s", err, stdout)
	}
	u := uimageFile(t, []byte("payload!"), fwimg.UImageOptions{Load: 0x8000, Entry: 0x8040, Name: "boot", Time: 7})
	js, _, err := runCmd(t, "info", "--json", u)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := fwimg.ReadManifest([]byte(js)); err != nil || m.Format != "uimage" || m.UImage == nil || m.UImage.Load != "0x8000" {
		t.Errorf("uimage --json: %v %+v", err, m)
	}
	_ = dir
}

func TestInfo_Refusals(t *testing.T) {
	in := simple(t)
	bad := put(t, "bad.elf", []byte("\x7fELF-not-really"))
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"unknown -I":         {[]string{"info", "-I", "coff", in}, "unknown --input-target"},
		"binary no base":     {[]string{"info", "-I", "binary", in}, "needs --base"},
		"base without -I":    {[]string{"info", "--base", "0", in}, "only for -I binary"},
		"bad base":           {[]string{"info", "-I", "binary", "--base", "zz", in}, "base"},
		"bad max-size":       {[]string{"info", "--max-size", "zz", in}, "max-size"},
		"too large":          {[]string{"info", "--json", "--max-size", "2", in}, "limit"},
		"broken ELF":         {[]string{"info", bad}, ""},
		"verify no manifest": {[]string{"verify", in}, "--manifest FILE is required"},
		"verify no file":     {[]string{"verify", "--manifest", "m.json"}, "accepts 1 arg"},
	} {
		_, _, err := runCmd(t, c.args...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestVerify_NamesTheDifference(t *testing.T) {
	dir := t.TempDir()
	mf := filepath.Join(dir, "m.json")
	hex := filepath.Join(dir, "fw.hex")
	in := twoSeg(t)
	if _, _, err := runCmd(t, "-O", "ihex", "--manifest", mf, "-o", hex, in); err != nil {
		t.Fatal(err)
	}
	other := ihexFile(t, 0x1000, "WXYZ")
	_, _, err := runCmd(t, "verify", "--manifest", mf, other)
	if err == nil || !strings.Contains(err.Error(), "difference(s)") {
		t.Errorf("a different image: %v", err)
	}
	if _, _, err := runCmd(t, "verify", "--manifest", mf, "--max-size", "4", hex); err == nil || !strings.Contains(err.Error(), "larger than the allowed size") {
		t.Errorf("a bound: %v", err)
	}
	// Manifest files that cannot be used.
	bad := put(t, "bad.json", []byte(`{"schema_version": 2}`))
	for name, c := range map[string]struct{ m, want string }{
		"missing":     {filepath.Join(dir, "absent.json"), "no such file"},
		"invalid":     {bad, "schema_version"},
		"a directory": {dir, "is a directory"},
	} {
		if _, _, err := runCmd(t, "verify", "--manifest", c.m, hex); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	// A manifest above the library's bound is refused without reading it all.
	huge := filepath.Join(dir, "huge.json")
	if err := os.WriteFile(huge, make([]byte, fwimg.MaxManifestSize+10), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd(t, "verify", "--manifest", huge, hex); err == nil {
		t.Error("an oversized manifest accepted")
	}
	// A broken image is the image's refusal, not a verification result.
	if _, _, err := runCmd(t, "verify", "--manifest", mf, put(t, "x", []byte("nope"))); err == nil || !strings.Contains(err.Error(), "raw binary") {
		t.Errorf("an unknown format: %v", err)
	}
}
