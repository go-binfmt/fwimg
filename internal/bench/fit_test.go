package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The FIT rows need a scratch ITS and a FIT that mkimage -f made; each of the
// two steps is refused, and named, when it fails.
func TestRunFITSetupRefusals(t *testing.T) {
	tr, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true(1)")
	}
	mk := func(dir string) ([]fixture, error) {
		p := filepath.Join(dir, "x")
		return []fixture{{"fx", p}}, os.WriteFile(p, []byte("x"), 0o644)
	}
	script := func(body string) string {
		p := filepath.Join(t.TempDir(), "tool")
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var w bytes.Buffer

	// mkimage -f fails: the error names the file and the tool's own words.
	bad := script(`case "$1" in -f) echo no-its-for-you; exit 1;; esac`)
	err = run([]string{"-objcopy", tr, "-mkimage", bad, "-fwimg", tr, "-dumpimage", tr, "-rounds", "1"}, &w, mk)
	if err == nil || !strings.Contains(err.Error(), "mkimage -f on fx") || !strings.Contains(err.Error(), "no-its-for-you") {
		t.Errorf("a failing mkimage -f: %v", err)
	}

	// The ITS cannot be written: a directory sits where the file would go
	// (the fake fwimg puts it there, after the path of the flat payload, $4).
	blocker := script(`mkdir "$4.its"`)
	err = run([]string{"-objcopy", tr, "-mkimage", tr, "-fwimg", blocker, "-dumpimage", tr, "-rounds", "1"}, &w, mk)
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("an unwritable ITS: %v", err)
	}
}
