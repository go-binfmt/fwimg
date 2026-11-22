// Command phases times, inside one cold fwimg-sized process, each step the
// command takes between cobra and the exit: reading the input, parsing the
// program headers, flattening, and writing the output (to a new file and over
// an existing one). It exists to find where the time above a cobra root that
// does nothing goes (go-binfmt/fwimg#2), on the CI runner, where timing is
// valid. Run it pinned to one core:
//
//	taskset -c 0 ./phases -rounds 60
//
// The driver builds a 1 KiB two-segment ELF, then runs itself with -once in
// every round (a fresh process, so the first call of every function pays its
// page faults, as fwimg does) and prints the median time and the exact
// allocation count of each phase. Even rounds write to a file that does not
// exist, odd rounds over the one the previous round left.
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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-binfmt/elfpatch"
	"github.com/go-binfmt/fwimg"
	"github.com/go-binfmt/fwimg/internal/elfgen"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Args[0]); err != nil {
		fmt.Fprintln(os.Stderr, "phases:", err)
		os.Exit(1)
	}
}

// phaseNames are the steps of once, in order; once prints one line for each.
var phaseNames = []string{"read", "parse", "flatten", "write"}

func run(args []string, w io.Writer, self string) error {
	fs := flag.NewFlagSet("phases", flag.ContinueOnError)
	fs.SetOutput(w)
	rounds := fs.Int("rounds", 40, "fresh processes per kind of write")
	once := fs.Bool("once", false, "internal: run the phases once and print one line each")
	in := fs.String("in", "", "internal: input ELF for -once")
	out := fs.String("out", "", "internal: output file for -once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *once {
		return once1(w, *in, *out)
	}
	if *rounds < 1 {
		return errors.New("-rounds must be at least 1")
	}
	dir, err := os.MkdirTemp("", "fwimg-phases-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	input := filepath.Join(dir, "in.elf")
	// A failed write shows as the child's "read" error below.
	_ = os.WriteFile(input, fixture(), 0o644)
	output := filepath.Join(dir, "out.bin")

	type key struct {
		phase string
		fresh bool
	}
	times := map[key][]time.Duration{}
	allocs := map[key]uint64{}
	for r := 0; r < *rounds*2; r++ {
		fresh := r%2 == 0
		if fresh {
			_ = os.Remove(output) // absent on the first round; a real failure shows in the write phase
		}
		b, err := exec.Command(self, "-once", "-in", input, "-out", output).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s -once: %v: %s", self, err, b)
		}
		got, err := parseLines(string(b))
		if err != nil {
			return err
		}
		for _, l := range got {
			k := key{l.phase, fresh}
			times[k] = append(times[k], l.d)
			allocs[k] = l.allocs
		}
	}
	fmt.Fprintf(w, "Phases of one cold fwimg process, 1 KiB ELF, `-O binary`; %d fresh processes per kind of write\n\n", *rounds)
	fmt.Fprintln(w, "| phase | new output file | existing output file | allocations |")
	fmt.Fprintln(w, "|---|---:|---:|---:|")
	for _, p := range phaseNames {
		nf, ex := times[key{p, true}], times[key{p, false}]
		if p != "write" {
			nf = append(slices.Clone(nf), ex...)
			ex = nf
		}
		fmt.Fprintf(w, "| %s | %s | %s | %d |\n", p, med(nf), med(ex), allocs[key{p, true}])
	}
	return nil
}

func med(d []time.Duration) time.Duration {
	d = slices.Clone(d)
	slices.Sort(d)
	return d[len(d)/2].Round(time.Microsecond)
}

type line struct {
	phase  string
	d      time.Duration
	allocs uint64
}

func parseLines(s string) ([]line, error) {
	var out []line
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			return nil, fmt.Errorf("bad line %q", sc.Text())
		}
		ns, err1 := strconv.ParseInt(f[1], 10, 64)
		n, err2 := strconv.ParseUint(f[2], 10, 64)
		if err := errors.Join(err1, err2); err != nil {
			return nil, fmt.Errorf("bad line %q: %w", sc.Text(), err)
		}
		out = append(out, line{f[0], time.Duration(ns), n})
	}
	if len(out) != len(phaseNames) {
		return nil, fmt.Errorf("%d phase lines, want %d", len(out), len(phaseNames))
	}
	return out, nil
}

// fixture is a 1 KiB image in two PT_LOAD segments with a gap, the shape the
// bench fixtures have.
func fixture() []byte {
	return elfgen.Build(elf.EM_AARCH64, 0x80000, []elfgen.Seg{
		{Paddr: 0x80000, Vaddr: 0x80000, Off: 0x400, Filesz: 512, Memsz: 512, Data: bytes.Repeat([]byte{1}, 512)},
		{Paddr: 0x90000, Vaddr: 0x90000, Off: 0x600, Filesz: 512, Memsz: 512, Data: bytes.Repeat([]byte{2}, 512)},
	})
}

// once runs the phases the way fwimg's run does and prints, for each, its name,
// the nanoseconds it took and the allocations it made.
func once1(w io.Writer, in, out string) error {
	var ms0, ms1 runtime.MemStats
	var data, flat []byte
	var err error
	phase := func(name string, f func() error) error {
		runtime.ReadMemStats(&ms0)
		t := time.Now()
		err := f()
		d := time.Since(t)
		runtime.ReadMemStats(&ms1)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Fprintf(w, "%s %d %d\n", name, d.Nanoseconds(), ms1.Mallocs-ms0.Mallocs)
		return nil
	}
	steps := []struct {
		name string
		f    func() error
	}{
		{"read", func() error {
			f, err := os.Open(in)
			if err != nil {
				return err
			}
			defer f.Close()
			_, _ = f.Stat() // fwimg stats the input before it reads
			data, err = io.ReadAll(io.LimitReader(f, 1<<31))
			return err
		}},
		{"parse", func() error { _, err := elfpatch.Parse(data); return err }},
		{"flatten", func() error {
			var err error
			flat, _, err = fwimg.FlattenBytes(data, fwimg.FlattenOptions{})
			return err
		}},
		{"write", func() error { return os.WriteFile(out, flat, 0o644) }},
	}
	for _, s := range steps {
		if err = phase(s.name, s.f); err != nil {
			return err
		}
	}
	return nil
}
