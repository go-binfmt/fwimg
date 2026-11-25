// Command syscalls runs commands under strace and prints, for each system call,
// how many times and for how long each command made it, then the calls only
// some of the commands make (go-binfmt/fwimg#2: where the start-up time above a
// do-nothing cobra program goes). The diff is computed here, not in a shell.
//
//	syscalls -cmd "label=program args" -cmd "label2=program2 args" ...
package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

type stat struct {
	n int
	d time.Duration
}

// trace is what one command did: per system call name, its count and total time.
type trace map[string]stat

var (
	// "1234  12:00:00.123456 openat(" or "[pid 1234] 12:00:00.123456 openat("
	// or, resumed, "1234  12:00:00.123456 <... futex resumed>) = 0 <0.000010>".
	lineRE     = regexp.MustCompile(`^(?:\[pid\s+\d+\]|\d+)?\s*[0-9:.]+\s+(?:<\.\.\. (\w+) resumed>|(\w+)\()`)
	durRE      = regexp.MustCompile(`<([0-9]+\.[0-9]+)>\s*$`)
	unfinished = "<unfinished ...>"
)

// parse reads an strace -f -T -tt trace. A call split by another thread counts
// once, on its resumed half, which is where its duration is.
func parse(r io.Reader) (trace, error) {
	t := trace{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		m := lineRE.FindStringSubmatch(line)
		if m == nil || strings.Contains(line, unfinished) {
			continue
		}
		name := m[1] + m[2]
		var d time.Duration
		if dm := durRE.FindStringSubmatch(line); dm != nil {
			f, _ := strconv.ParseFloat(dm[1], 64) // the pattern admits digits and one point only
			d = time.Duration(f * float64(time.Second))
		}
		s := t[name]
		s.n++
		s.d += d
		t[name] = s
	}
	return t, sc.Err()
}

type cmdSpec struct {
	label string
	argv  []string
}

type cmdList []cmdSpec

func (c *cmdList) String() string { return "" }

func (c *cmdList) Set(v string) error {
	label, rest, ok := strings.Cut(v, "=")
	f := strings.Fields(rest)
	if !ok || label == "" || len(f) == 0 {
		return fmt.Errorf("-cmd %q: want label=program args", v)
	}
	if label != filepath.Base(label) || label == ".." {
		return fmt.Errorf("-cmd %q: the label names a file, so it holds no path separator", v)
	}
	*c = append(*c, cmdSpec{label, f})
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "syscalls:", err)
		os.Exit(1)
	}
}

func run(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("syscalls", flag.ContinueOnError)
	fs.SetOutput(w)
	var cmds cmdList
	fs.Var(&cmds, "cmd", "label=program args; repeatable")
	strace := fs.String("strace", "strace", "the strace program")
	dir := fs.String("dir", "", "keep each raw trace here as <label>.trace (default: a scratch directory, removed)")
	fixture := fs.String("fixture", "", "first write the 1 KiB two-segment ELF the benchmarks use to this path")
	raw := fs.Bool("raw", false, "also print each raw trace")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(cmds) < 2 {
		return errors.New("need at least two -cmd to compare")
	}
	if *fixture != "" {
		if err := os.WriteFile(*fixture, fixtureELF(), 0o644); err != nil {
			return err
		}
	}
	if *dir == "" {
		d, err := os.MkdirTemp("", "fwimg-strace-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(d)
		*dir = d
	}
	traces := make([]trace, len(cmds))
	for i, c := range cmds {
		file := filepath.Join(*dir, c.label+".trace")
		argv := append([]string{"-f", "-T", "-tt", "-o", file}, c.argv...)
		if b, err := exec.Command(*strace, argv...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %v: %s", c.label, err, b)
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		traces[i], err = parse(f)
		if err == nil && *raw {
			if _, err = f.Seek(0, io.SeekStart); err == nil {
				fmt.Fprintf(w, "--- raw trace of %s\n", c.label)
				_, err = io.Copy(w, f)
			}
		}
		f.Close()
		if err != nil {
			return err
		}
	}
	labels := make([]string, len(cmds))
	for i, c := range cmds {
		labels[i] = c.label
	}
	table(w, labels, traces)
	return nil
}

// table prints every system call with its count and time per command, the
// calls not made by every command first.
func table(w io.Writer, labels []string, traces []trace) {
	names := map[string]bool{}
	for _, t := range traces {
		for n := range t {
			names[n] = true
		}
	}
	all := make([]string, 0, len(names))
	for n := range names {
		all = append(all, n)
	}
	// Most-called first, name to break ties.
	slices.SortFunc(all, func(a, b string) int {
		if x, y := maxN(traces, a), maxN(traces, b); x != y {
			return y - x
		}
		return strings.Compare(a, b)
	})
	fmt.Fprintf(w, "System calls per process, `strace -f -T`; count / total time\n\n| syscall |")
	for _, l := range labels {
		fmt.Fprintf(w, " %s |", l)
	}
	fmt.Fprint(w, "\n|---|")
	for range labels {
		fmt.Fprint(w, "---:|")
	}
	fmt.Fprintln(w)
	row := func(n string) {
		fmt.Fprintf(w, "| %s |", n)
		for _, t := range traces {
			fmt.Fprintf(w, " %s |", cell(t[n]))
		}
		fmt.Fprintln(w)
	}
	totals := make([]stat, len(traces))
	for _, n := range all {
		row(n)
		for i, t := range traces {
			totals[i].n += t[n].n
			totals[i].d += t[n].d
		}
	}
	fmt.Fprint(w, "| **total** |")
	for _, s := range totals {
		fmt.Fprintf(w, " %s |", cell(s))
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "\nCalls not made by every command:\n\n")
	any := false
	for _, n := range all {
		if !inAll(traces, n) {
			any = true
			fmt.Fprintf(w, "- %s: made by", n)
			for i, t := range traces {
				if t[n].n > 0 {
					fmt.Fprintf(w, " %s (%d)", labels[i], t[n].n)
				}
			}
			fmt.Fprintln(w)
		}
	}
	if !any {
		fmt.Fprintln(w, "- none")
	}
}

// fixtureELF is the 1 KiB image in two PT_LOAD segments with a gap that the
// phases command and the bench fixtures use.
func fixtureELF() []byte {
	return elfgen.Build(elf.EM_AARCH64, 0x80000, []elfgen.Seg{
		{Paddr: 0x80000, Vaddr: 0x80000, Off: 0x400, Filesz: 512, Memsz: 512, Data: bytes.Repeat([]byte{1}, 512)},
		{Paddr: 0x90000, Vaddr: 0x90000, Off: 0x600, Filesz: 512, Memsz: 512, Data: bytes.Repeat([]byte{2}, 512)},
	})
}

func cell(s stat) string {
	if s.n == 0 {
		return "-"
	}
	return fmt.Sprintf("%d / %s", s.n, s.d.Round(time.Microsecond))
}

func maxN(ts []trace, n string) int {
	m := 0
	for _, t := range ts {
		m = max(m, t[n].n)
	}
	return m
}

func inAll(ts []trace, n string) bool {
	for _, t := range ts {
		if t[n].n == 0 {
			return false
		}
	}
	return true
}
