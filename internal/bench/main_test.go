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
	if n := strings.Count(w.String(), "| fx |"); n != len(ops)+len(decodeOps) {
		t.Errorf("%d rows, want %d:\n%s", n, len(ops)+len(decodeOps), w.String())
	}
	for _, want := range []string{"`-I ihex -O binary`", "`-I srec -O binary`"} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("no row %s in:\n%s", want, w.String())
		}
	}
	// The text the decoders read is made by objcopy from each fixture, once
	// per format, before the rows that read it.
	logDir := t.TempDir()
	logFile := filepath.Join(logDir, "calls")
	spy := filepath.Join(logDir, "objcopy")
	if err := os.WriteFile(spy, []byte("#!/bin/sh\necho \"$*\" >> "+logFile+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w.Reset()
	if err := run([]string{"-objcopy", spy, "-mkimage", tr, "-fwimg", tr, "-rounds", "1"}, &w, mk); err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(logFile)
	for _, want := range []string{"-O ihex ", "-O srec "} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("objcopy was never asked for %q; calls:\n%s", want, calls)
		}
	}
	// objcopy failing to make the text the decoders read names the format.
	stub := filepath.Join(t.TempDir(), "objcopy")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ncase \"$*\" in *\"-O srec /\"*) exit 1;; esac\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-objcopy", stub, "-mkimage", tr, "-fwimg", tr, "-rounds", "1"}, &w, mk); err == nil || !strings.Contains(err.Error(), "-O srec on fx") {
		t.Errorf("err = %v, want the text step named", err)
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

// -write-small leaves the first fixture at the path and runs no benchmark.
func TestRunWriteSmall(t *testing.T) {
	mk := func(dir string) ([]fixture, error) {
		p := filepath.Join(dir, "x")
		return []fixture{{"fx", p}, {"other", p + "-other"}}, os.WriteFile(p, []byte("first"), 0o644)
	}
	dst := filepath.Join(t.TempDir(), "small")
	var w bytes.Buffer
	if err := run([]string{"-write-small", dst}, &w, mk); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "first" {
		t.Errorf("the small fixture: %q, %v", b, err)
	}
	if w.Len() != 0 {
		t.Errorf("a benchmark ran: %q", w.String())
	}
	if err := run([]string{"-write-small", filepath.Join(t.TempDir(), "no", "x")}, &w, mk); err == nil {
		t.Error("an unwritable destination was accepted")
	}
	gone := func(dir string) ([]fixture, error) { return []fixture{{"fx", filepath.Join(dir, "gone")}}, nil }
	if err := run([]string{"-write-small", dst}, &w, gone); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Errorf("a missing fixture: %v", err)
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
	if err := run([]string{"-nonsense"}, &w, mk); err == nil || !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("an unknown flag: err = %v, want the flag package's refusal", err)
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
			// Refused at its own step, not by the compiler further on.
			if _, err := fixtures(dir); err == nil || !strings.Contains(err.Error(), c.want) || strings.HasPrefix(err.Error(), "gcc:") {
				t.Fatalf("err = %v, want it to name %s from the step itself", err, c.want)
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

// The floor table has one row, four timings, the difference and a verdict,
// and refuses one reference program without the other and a failing one.
func TestRunFloor(t *testing.T) {
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
	base := []string{"-objcopy", tr, "-mkimage", tr, "-fwimg", tr, "-rounds", "4"}
	var w bytes.Buffer
	if err := run(append(base, "-hello", tr, "-cobra", tr), &w, mk); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"| objcopy | fwimg | cobra-only | hello | fwimg minus cobra-only | noise (MAD) |", "fwimg minus cobra-only is "} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("no %q in:\n%s", want, w.String())
		}
	}
	if err := run(append(base, "-hello", tr), &w, mk); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Errorf("one reference program: err = %v", err)
	}
	if err := run(append(base, "-cobra", tr), &w, mk); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Errorf("the other one alone: err = %v", err)
	}
	for _, bad := range [][]string{{"-hello", fl, "-cobra", tr}, {"-hello", tr, "-cobra", fl}} {
		if err := run(append(base, bad...), &w, mk); err == nil || !strings.Contains(err.Error(), fl) {
			t.Errorf("%v: err = %v, want the failing program named", bad, err)
		}
	}
}

// paired takes the median of the round-by-round difference and the median
// absolute deviation around it; the inputs are left in order.
func TestPaired(t *testing.T) {
	a := []time.Duration{110, 130, 120, 400, 125}
	b := []time.Duration{100, 100, 100, 100, 100}
	// differences 10, 30, 20, 300, 25: median 25; deviations 15, 5, 5, 275, 0: median 5.
	diff, noise := paired(a, b)
	if diff != 25 || noise != 5 {
		t.Errorf("diff, noise = %v, %v, want 25, 5", diff, noise)
	}
	if a[3] != 400 || b[0] != 100 {
		t.Error("paired reordered its inputs")
	}
	// A negative difference is as large as its absolute value.
	if d, n := paired(b, a); d != -25 || n != 5 {
		t.Errorf("reversed: %v, %v, want -25, 5", d, n)
	}
}

func TestVerdict(t *testing.T) {
	for _, c := range []struct {
		diff, noise time.Duration
		want        string
	}{
		{5 * time.Microsecond, 5 * time.Microsecond, "within the noise"},
		{-5 * time.Microsecond, 5 * time.Microsecond, "within the noise"},
		{6 * time.Microsecond, 5 * time.Microsecond, "is 6µs, beyond the noise of 5µs"},
		{-6 * time.Microsecond, 5 * time.Microsecond, "is -6µs, beyond the noise of 5µs"},
	} {
		if got := verdict(c.diff, c.noise); !strings.Contains(got, c.want) {
			t.Errorf("verdict(%v, %v) = %q, want %q in it", c.diff, c.noise, got, c.want)
		}
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
	for _, d := range decodeOps {
		ref := d.ref(tl, "in."+d.kind, "", "out")
		if ref[0] != "objcopy" || ref[2] != d.kind || ref[len(ref)-2] != "in."+d.kind {
			t.Errorf("%s: reference argv %v", d.name, ref)
		}
		if got := d.ours("in."+d.kind, "out"); got[1] != d.kind || got[len(got)-1] != "in."+d.kind {
			t.Errorf("%s: fwimg argv %v", d.name, got)
		}
	}
}
