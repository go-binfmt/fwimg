package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMedian(t *testing.T) {
	d := []time.Duration{5, 1, 3}
	if got := median(d); got != 3 {
		t.Errorf("median = %v, want 3", got)
	}
}

func TestRunRejectsZeroRounds(t *testing.T) {
	var w bytes.Buffer
	err := run([]string{"-rounds", "0"}, &w, nil)
	if err == nil || !strings.Contains(err.Error(), "-rounds") {
		t.Fatalf("err = %v", err)
	}
}

// With `true` standing in for every tool the table has one row per fixture
// and operation, and a failing fixture builder is reported, not swallowed.
func TestRunTable(t *testing.T) {
	tr, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true(1)")
	}
	mk := func(dir string) ([]fixture, error) {
		p := filepath.Join(dir, "x")
		return []fixture{{"fx", p}}, os.WriteFile(p, []byte("x"), 0o644)
	}
	var w bytes.Buffer
	if err := run([]string{"-objcopy", tr, "-mkimage", tr, "-fwimg", tr, "-rounds", "2"}, &w, mk); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(w.String(), "| fx |"); n != len(ops) {
		t.Errorf("%d rows, want %d:\n%s", n, len(ops), w.String())
	}
	bad := func(string) ([]fixture, error) { return nil, errors.New("no gcc") }
	if err := run([]string{"-rounds", "1"}, &w, bad); err == nil || !strings.Contains(err.Error(), "no gcc") {
		t.Errorf("err = %v", err)
	}
	// A tool that fails fails the run.
	fl, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false(1)")
	}
	if err := run([]string{"-objcopy", fl, "-mkimage", fl, "-fwimg", tr, "-rounds", "1"}, &w, mk); err == nil {
		t.Error("a failing reference tool did not fail the run")
	}
}

func TestRunRefusals(t *testing.T) {
	tr, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true(1)")
	}
	fl, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false(1)")
	}
	mk := func(dir string) ([]fixture, error) {
		p := filepath.Join(dir, "x")
		return []fixture{{"fx", p}}, os.WriteFile(p, []byte("x"), 0o644)
	}
	var w bytes.Buffer
	if err := run([]string{"-nonsense"}, &w, mk); err == nil {
		t.Error("an unknown flag did not fail the run")
	}
	// fwimg failing to make the flat payload names the file.
	if err := run([]string{"-objcopy", tr, "-mkimage", tr, "-fwimg", fl, "-rounds", "1"}, &w, mk); err == nil || !strings.Contains(err.Error(), "fwimg on fx") {
		t.Errorf("failing fwimg: err = %v", err)
	}
	// No scratch directory, no run.
	missing := filepath.Join(t.TempDir(), "absent")
	t.Setenv("TMPDIR", missing)
	t.Setenv("TMP", missing)
	t.Setenv("TEMP", missing)
	if err := run([]string{"-objcopy", tr, "-mkimage", tr, "-fwimg", tr, "-rounds", "1"}, &w, mk); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("no temp dir: err = %v", err)
	}
}

// Each step of the fixture builder is refused in turn by putting a directory
// where its file would go, and the compiler by taking it off the PATH.
func TestFixturesRefusals(t *testing.T) {
	for _, c := range []struct{ name, blocker, want string }{
		{"linker script", "fw.ld", "fw.ld"},
		{"blob", "blob-1", "blob-1"},
		{"source", "fw-1.c", "fw-1.c"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, c.blocker), 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := fixtures(dir); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to name %s", err, c.want)
			}
		})
	}
	t.Run("no compiler", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := fixtures(t.TempDir()); err == nil || !strings.Contains(err.Error(), "gcc") {
			t.Fatalf("err = %v, want it to name gcc", err)
		}
	})
}

func TestOpsBuildArgv(t *testing.T) {
	tl := tools{"objcopy", "mkimage", "fwimg"}
	for _, o := range ops {
		ref := o.ref(tl, "in.elf", "flat", "out")
		if ref[0] != "objcopy" && ref[0] != "mkimage" {
			t.Errorf("%s: reference argv %v", o.name, ref)
		}
		if got := o.ours("in.elf", "out"); got[len(got)-1] != "in.elf" {
			t.Errorf("%s: fwimg argv %v does not end with the input", o.name, got)
		}
	}
}
