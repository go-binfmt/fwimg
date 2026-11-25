// Command startup times short-lived processes in interleaved rounds and
// prints a Markdown table of the median and minimum wall time and the median
// number of minor page faults of each. It is the measurement behind the
// small-file rows of the bench table, where a conversion takes microseconds
// and the process start-up is what is left:
//
//	taskset -c 0 ./startup -rounds 200 \
//	    -cmd 'objcopy=objcopy -O binary fw.elf out' \
//	    -cmd 'fwimg=./fwimg -O binary -o out fw.elf'
//
// A -cmd is a label, '=', and the command line split on spaces. Each round runs
// every command once, and the one that goes first rotates, so a warm cache or a
// frequency step does not favour the same one.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "startup:", err)
		os.Exit(1)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, "; ") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

type cmdline struct {
	label string
	argv  []string
}

func parse(specs []string) ([]cmdline, error) {
	var out []cmdline
	for _, s := range specs {
		label, rest, ok := strings.Cut(s, "=")
		argv := strings.Fields(rest)
		if !ok || label == "" || len(argv) == 0 {
			return nil, fmt.Errorf("-cmd %q: want label=command args", s)
		}
		out = append(out, cmdline{label, argv})
	}
	if len(out) == 0 {
		return nil, errors.New("at least one -cmd is required")
	}
	return out, nil
}

func run(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("startup", flag.ContinueOnError)
	fs.SetOutput(w)
	var specs multi
	fs.Var(&specs, "cmd", "label=command line (repeatable)")
	rounds := fs.Int("rounds", 200, "interleaved rounds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rounds < 1 {
		return errors.New("-rounds must be at least 1")
	}
	cmds, err := parse(specs)
	if err != nil {
		return err
	}
	wall := make([][]time.Duration, len(cmds))
	minor := make([][]int64, len(cmds))
	major := make([][]int64, len(cmds))
	for r := 0; r < *rounds; r++ {
		for k := range cmds {
			i := (k + r) % len(cmds)
			d, f, err := timeOne(cmds[i].argv)
			if err != nil {
				return fmt.Errorf("%s: %w", cmds[i].label, err)
			}
			wall[i] = append(wall[i], d)
			minor[i] = append(minor[i], f.minor)
			major[i] = append(major[i], f.major)
		}
	}
	fmt.Fprintf(w, "rounds: %d; wall time per process, interleaved; faults are getrusage of the child\n\n", *rounds)
	fmt.Fprintln(w, "| command | binary | median | min | minor faults | major faults |")
	fmt.Fprintln(w, "|---|---:|---:|---:|---:|---:|")
	for i, c := range cmds {
		slices.Sort(wall[i])
		slices.Sort(minor[i])
		slices.Sort(major[i])
		fmt.Fprintf(w, "| %s | %s | %s | %s | %d | %d |\n", c.label, binarySize(c.argv[0]),
			wall[i][len(wall[i])/2].Round(10*time.Microsecond),
			wall[i][0].Round(10*time.Microsecond), minor[i][len(minor[i])/2], major[i][len(major[i])/2])
	}
	return nil
}

// faultCount is the page faults of one finished process.
type faultCount struct{ minor, major int64 }

// binarySize is the size of the program a command runs, found on PATH when it
// has no directory, or "?" when it cannot be found.
func binarySize(prog string) string {
	path := prog
	if !strings.Contains(prog, "/") {
		if p, err := exec.LookPath(prog); err == nil {
			path = p
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		return "?"
	}
	return fmt.Sprintf("%d KiB", (st.Size()+512)/1024)
}

// timeOne runs argv to completion and returns its wall time and its page
// faults.
func timeOne(argv []string) (time.Duration, faultCount, error) {
	c := exec.Command(argv[0], argv[1:]...)
	start := time.Now()
	out, err := c.CombinedOutput()
	d := time.Since(start)
	if err != nil {
		return 0, faultCount{}, fmt.Errorf("%v: %s", err, out)
	}
	minor, major := faults(c.ProcessState)
	return d, faultCount{minor, major}, nil
}
