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
