package main

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-binfmt/fwimg"
	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// The test binary stands in for the command: run starts os.Args[0] with -once,
// and with the variable set the binary does what the command does.
func TestMain(m *testing.M) {
	if os.Getenv("PHASES_AS_COMMAND") != "" {
		if err := run(os.Args[1:], os.Stdout, os.Args[0]); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRunTable(t *testing.T) {
	t.Setenv("PHASES_AS_COMMAND", "1")
	var w bytes.Buffer
	if err := run([]string{"-rounds", "2"}, &w, os.Args[0]); err != nil {
		t.Fatal(err)
	}
	for _, p := range phaseNames {
		if !strings.Contains(w.String(), "| "+p+" |") {
			t.Errorf("no row for %s in:\n%s", p, w.String())
		}
	}
}

func TestRunInput(t *testing.T) {
	t.Setenv("PHASES_AS_COMMAND", "1")
	in := filepath.Join(t.TempDir(), "big.elf")
	if err := os.WriteFile(in, fixture(), 0o644); err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if err := run([]string{"-rounds", "1", "-input", in}, &w, os.Args[0]); err != nil || !strings.Contains(w.String(), "big.elf") {
		t.Errorf("-input: %v\n%s", err, w.String())
	}
	if err := run([]string{"-rounds", "1", "-input", in + ".none"}, &w, "x"); err == nil || !strings.Contains(err.Error(), "big.elf.none") {
		t.Error("a missing -input was accepted")
	}
}

func TestRunRefusals(t *testing.T) {
	var w bytes.Buffer
	if err := run([]string{"-rounds", "0"}, &w, "x"); err == nil || !strings.Contains(err.Error(), "-rounds") {
		t.Errorf("zero rounds: %v", err)
	}
	if err := run([]string{"-nonsense"}, &w, "x"); err == nil || !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("an unknown flag: %v", err)
	}
	// A command that exits 0 and prints nothing is a driver error, not a table.
	if tr, e := exec.LookPath("true"); e == nil {
		if err := run([]string{"-rounds", "1"}, &w, tr); err == nil || !strings.Contains(err.Error(), "phase lines") {
			t.Errorf("a silent command: %v", err)
		}
	}
	t.Setenv(depthVar, "1")
	if err := run([]string{"-rounds", "1"}, &w, "x"); err == nil || !strings.Contains(err.Error(), "-once child") {
		t.Errorf("a child driving rounds: %v", err)
	}
	t.Setenv(depthVar, "")
	// -once through run prints one line per phase and stops there.
	dir := t.TempDir()
	in := filepath.Join(dir, "in.elf")
	if err := os.WriteFile(in, fixture(), 0o644); err != nil {
		t.Fatal(err)
	}
	w.Reset()
	if err := run([]string{"-once", "-in", in, "-out", filepath.Join(dir, "o")}, &w, "x"); err != nil || strings.Count(w.String(), "\n") != len(phaseNames) {
		t.Errorf("-once: %v, %q", err, w.String())
	}
	if err := run([]string{"-rounds", "1"}, &w, filepath.Join(t.TempDir(), "absent")); err == nil || !strings.Contains(err.Error(), "-once") {
		t.Errorf("a missing command: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	t.Setenv("TMPDIR", missing)
	if err := run([]string{"-rounds", "1"}, &w, "x"); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("no scratch directory: %v", err)
	}
}

func TestOnceRefusals(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "in.elf")
	if err := os.WriteFile(good, fixture(), 0o644); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(dir, "junk")
	if err := os.WriteFile(junk, []byte("not an elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	far := filepath.Join(dir, "far.elf")
	if err := os.WriteFile(far, elfgen.Build(elf.EM_AARCH64, 0x80000, []elfgen.Seg{
		{Paddr: 0x80000, Vaddr: 0x80000, Off: 0x400, Filesz: 1, Memsz: 1, Data: []byte{1}},
		{Paddr: 0x80000 + 1<<30, Vaddr: 0x80000 + 1<<30, Off: 0x600, Filesz: 1, Memsz: 1, Data: []byte{2}},
	}), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, in, out, want string }{
		{"span over the limit", far, filepath.Join(dir, "o"), "write: " + fwimg.ErrTooLarge.Error()},
		{"no input", filepath.Join(dir, "none"), filepath.Join(dir, "o"), "read"},
		{"not an elf", junk, filepath.Join(dir, "o"), "parse"},
		{"no output directory", good, filepath.Join(dir, "none", "o"), "write"},
	} {
		var w bytes.Buffer
		if err := once1(&w, c.in, c.out); err == nil || !strings.HasPrefix(err.Error(), c.want) || (c.name != "span over the limit" && c.name != "not an elf" && !strings.Contains(err.Error(), "none")) {
			t.Errorf("%s: err = %v, want it to start with %q", c.name, err, c.want)
		}
	}
	var w bytes.Buffer
	if err := once1(&w, good, filepath.Join(dir, "o")); err != nil {
		t.Fatal(err)
	}
	if got, err := parseLines(w.String()); err != nil || len(got) != len(phaseNames) {
		t.Errorf("parse of own output: %v, %d lines", err, len(got))
	}
}

func TestParseLines(t *testing.T) {
	ok := "read 1000 3\nparse 2000 4\nview 3000 5\nwrite 4000 6\n"
	got, err := parseLines(ok)
	if err != nil || got[1].d != 2*time.Microsecond || got[2].allocs != 5 || got[3].phase != "write" {
		t.Errorf("got %+v, %v", got, err)
	}
	for _, bad := range []string{"read 1\n", "read x 3\nparse 1 1\nview 1 1\nwrite 1 1\n", "read 1 y\nparse 1 1\nview 1 1\nwrite 1 1\n", "read 1000 3\n", ""} {
		if _, err := parseLines(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestMed(t *testing.T) {
	if got := med([]time.Duration{5 * time.Microsecond, time.Microsecond, 3 * time.Microsecond}); got != 3*time.Microsecond {
		t.Errorf("med = %v", got)
	}
}
