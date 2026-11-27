package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMedian(t *testing.T) {
	if got := median([]time.Duration{5, 1, 3}); got != 3 {
		t.Errorf("median = %v, want 3", got)
	}
}

func TestRunRefusals(t *testing.T) {
	var w bytes.Buffer
	for _, a := range [][]string{{"-rounds", "0", "-native", "x"}, {}, {"-nosuchflag"}} {
		if err := run(a, &w); err == nil {
			t.Errorf("run(%v) succeeded", a)
		}
	}
}

func TestFixtureIsAnELFofTheSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.elf")
	if err := fixture(p, 1<<12); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte("\x7fELF")) || len(b) < 1<<12 {
		t.Fatalf("fixture: %d bytes, prefix %q", len(b), b[:4])
	}
}

// With `true` standing in for the program the table has a row per input and
// operation; a program that fails is an error, not a fast time.
func TestRunTableAndFailure(t *testing.T) {
	tr, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true(1)")
	}
	var w bytes.Buffer
	if err := run([]string{"-native", tr, "-rounds", "1", "-big=false"}, &w); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(w.String(), "\n| "); n != 2*len(ops) { // 2 sizes; the header opens the output, the rule starts with |-
		t.Errorf("%d table lines:\n%s", n, w.String())
	}
	f, err := exec.LookPath("false")
	if err != nil {
		t.Skip("no false(1)")
	}
	if err := run([]string{"-native", f, "-rounds", "1", "-big=false"}, &w); err == nil {
		t.Error("a failing program gave a table")
	}
}
