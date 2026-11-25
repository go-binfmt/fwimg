package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const sample = `101  12:00:00.000100 execve("/x", ["x"], 0x0) = 0 <0.000500>
101  12:00:00.000700 openat(AT_FDCWD, "in", O_RDONLY|O_CLOEXEC) = 3 <0.000020>
101  12:00:00.000800 read(3, "", 512) = 0 <0.000010>
[pid   102] 12:00:00.000900 futex(0x1, FUTEX_WAIT, 0, NULL <unfinished ...>
101  12:00:00.001000 read(3, "", 512) = 0 <0.000030>
[pid   102] 12:00:00.001100 <... futex resumed>) = 0 <0.000200>
101  12:00:00.001200 --- SIGURG {si_signo=SIGURG} ---
101  12:00:00.001300 +++ exited with 0 +++
`

func TestParse(t *testing.T) {
	got, err := parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := trace{
		"execve": {1, 500 * time.Microsecond},
		"openat": {1, 20 * time.Microsecond},
		"read":   {2, 40 * time.Microsecond},
		"futex":  {1, 200 * time.Microsecond},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %v, want %v", k, got[k], w)
		}
	}
	// A call without a duration still counts, once.
	got, _ = parse(strings.NewReader("1  12:00:00.1 exit_group(0) = ?\n"))
	if got["exit_group"] != (stat{1, 0}) {
		t.Errorf("no duration: %v", got)
	}
}

func TestCmdList(t *testing.T) {
	var c cmdList
	if err := c.Set("a=prog x y"); err != nil || len(c) != 1 || c[0].label != "a" || len(c[0].argv) != 3 {
		t.Fatalf("good: %v %v", c, err)
	}
	for _, bad := range []string{"noequals", "=prog", "a=", "a=  ", "a/b=prog", "../x=prog", "..=prog"} {
		if err := c.Set(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if len(c) != 1 {
		t.Errorf("a refused value was kept: %v", c)
	}
	_ = c.String()
}

// The test binary stands in for strace: it writes the trace named by -o, a
// different one for each program, and fails for the program "bad".
func TestMain(m *testing.M) {
	if os.Getenv("SYSCALLS_AS_STRACE") != "" {
		a := os.Args[1:]
		if len(a) < 6 || a[0] != "-f" || a[1] != "-T" || a[2] != "-tt" || a[3] != "-o" {
			os.Stderr.WriteString("bad strace arguments\n")
			os.Exit(2)
		}
		if a[5] == "bad" {
			os.Stderr.WriteString("no such program\n")
			os.Exit(1)
		}
		body := sample
		if a[5] == "long" {
			body += strings.Repeat("x", 2<<20) + "\n"
		}
		if a[5] == "other" {
			body += "101  12:00:00.002000 fsync(3) = 0 <0.000300>\n"
		}
		if err := os.WriteFile(a[4], []byte(body), 0o644); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestRunTable(t *testing.T) {
	t.Setenv("SYSCALLS_AS_STRACE", "1")
	dir := t.TempDir()
	var w bytes.Buffer
	err := run([]string{"-strace", os.Args[0], "-dir", dir, "-raw", "-cmd", "plain=same a", "-cmd", "more=other a"}, &w)
	if err != nil {
		t.Fatal(err)
	}
	out := w.String()
	for _, want := range []string{
		"| syscall | plain | more |",
		"| read | 2 / 40µs | 2 / 40µs |",
		"| fsync | - | 1 / 300µs |",
		"| **total** | 5 / 760µs | 6 / 1.06ms |",
		"- fsync: made by more (1)",
		"--- raw trace of plain",
		"execve(",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "| read |") > strings.Index(out, "| openat |") {
		t.Errorf("the most-called call is not first:\n%s", out)
	}
	fx := filepath.Join(dir, "fixture.elf")
	w.Reset()
	if err := run([]string{"-strace", os.Args[0], "-fixture", fx, "-cmd", "a=same x", "-cmd", "b=same y"}, &w); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(fx); err != nil || st.Size() < 1024 {
		t.Errorf("fixture: %v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "more.trace")); err != nil {
		t.Errorf("the raw trace was not kept: %v", err)
	}
	w.Reset()
	if err := run([]string{"-strace", os.Args[0], "-cmd", "a=same x", "-cmd", "b=same y"}, &w); err != nil || !strings.Contains(w.String(), "- none") {
		t.Errorf("identical commands: %v\n%s", err, w.String())
	}
}

func TestRunRefusals(t *testing.T) {
	var w bytes.Buffer
	if err := run([]string{"-cmd", "a=x"}, &w); err == nil || !strings.Contains(err.Error(), "two") {
		t.Errorf("one command: %v", err)
	}
	t.Setenv("SYSCALLS_AS_STRACE", "1")
	two := []string{"-strace", os.Args[0], "-cmd", "a=same x", "-cmd", "b=same y"}
	if err := run(append(slices.Clone(two), "-nonsense"), &w); err == nil {
		t.Error("an unknown flag was accepted")
	}
	if err := run(append([]string{"-fixture", filepath.Join(t.TempDir(), "no", "x")}, two...), &w); err == nil {
		t.Error("an unwritable fixture path was accepted")
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if err := run(two, &w); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Errorf("no scratch directory: %v", err)
	}
	t.Setenv("TMPDIR", t.TempDir())
	if err := run([]string{"-strace", os.Args[0], "-cmd", "a=same x", "-cmd", "b=long"}, &w); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("a trace line over the scanner's limit: %v", err)
	}
	if err := run([]string{"-strace", os.Args[0], "-cmd", "a=same x", "-cmd", "b=bad"}, &w); err == nil || !strings.Contains(err.Error(), "no such program") || !strings.Contains(err.Error(), "b:") {
		t.Errorf("a failing strace: %v", err)
	}
	if err := run([]string{"-strace", filepath.Join(t.TempDir(), "absent"), "-cmd", "a=x", "-cmd", "b=y"}, &w); err == nil {
		t.Error("a missing strace was accepted")
	}
	// strace that succeeds but leaves no trace file.
	if err := run([]string{"-strace", "true", "-cmd", "a=x", "-cmd", "b=y"}, &w); err == nil || !strings.Contains(err.Error(), "a.trace") {
		t.Errorf("a missing trace file: %v", err)
	}
}
