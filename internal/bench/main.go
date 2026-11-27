// Command bench times fwimg against GNU objcopy and U-Boot mkimage on
// freestanding ELF files built by gcc, as processes, in interleaved rounds
// (the tool that goes first alternates every round), and prints a Markdown
// table of medians. Run it pinned to one core, from a quiet machine:
//
//	taskset -c 0 ./bench -objcopy $(which objcopy) -mkimage $(which mkimage) -fwimg ./fwimg
//
// It builds three fixtures with 1 KiB, 4 MiB and 32 MiB of initialised data
// in two loadable segments. The uImage row compares mkimage wrapping an
// already flat file with fwimg doing the whole job from the ELF, so it is
// the conservative one.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, fixtures); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

// op is one conversion: the reference command line and fwimg's, each a
// function of the ELF path, the flat payload path and the output path.
type op struct {
	name string
	ref  func(tools tools, elf, flat, out string) []string
	ours func(elf, out string) []string
}

// fromFlat: both programs read the flat payload (made once by fwimg), not the
// ELF, because the reference has no ELF reader (uf2conv.py).
func fromFlat(o op) bool { return strings.HasPrefix(o.name, "-O uf2") }

type tools struct{ objcopy, mkimage, fwimg, uf2conv string }

// l5Ops are the formats of v0.7.0 and their reference tools. The UF2 row
// needs uf2conv.py (-uf2conv), so it is added only when given.
func l5Ops(t tools) []op {
	rows := []op{
		{name: "-O verilog",
			ref: func(t tools, elf, _, out string) []string {
				return []string{t.objcopy, "-O", "verilog", elf, out}
			},
			ours: func(elf, out string) []string { return []string{"-O", "verilog", "-o", out, elf} }},
		{name: "-O uimage --uimage-comp gzip (mkimage -C gzip: flat file in)",
			ref: func(t tools, _, flat, out string) []string {
				return []string{t.mkimage, "-A", "arm", "-O", "linux", "-T", "kernel", "-C", "gzip",
					"-a", "0x80000", "-e", "0x80000", "-n", "fw", "-d", flat, out}
			},
			ours: func(elf, out string) []string {
				return []string{"-O", "uimage", "--uimage-comp", "gzip", "--uimage-arch", "arm", "--load", "0x80000", "--entry", "0x80000", "--name", "fw", "-o", out, elf}
			}},
	}
	if t.uf2conv != "" {
		rows = append(rows, op{name: "-O uf2 (uf2conv.py: flat file in)",
			ref: func(t tools, _, flat, out string) []string {
				return []string{"python3", t.uf2conv, "-c", "-b", "0x80000", "-f", "0xe48bff56", "-o", out, flat}
			},
			ours: func(flat, out string) []string {
				return []string{"-I", "binary", "--base", "0x80000", "-O", "uf2", "--uf2-family", "rp2040", "-o", out, flat}
			}})
	}
	return rows
}

var ops = []op{
	{"-O binary",
		func(t tools, elf, _, out string) []string { return []string{t.objcopy, "-O", "binary", elf, out} },
		func(elf, out string) []string { return []string{"-O", "binary", "-o", out, elf} }},
	{"-O srec",
		func(t tools, elf, _, out string) []string {
			return []string{t.objcopy, "-O", "srec", "--srec-forceS3", elf, out}
		},
		func(elf, out string) []string { return []string{"-O", "srec", "-o", out, elf} }},
	{"-O ihex",
		func(t tools, elf, _, out string) []string { return []string{t.objcopy, "-O", "ihex", elf, out} },
		func(elf, out string) []string { return []string{"-O", "ihex", "-o", out, elf} }},
	{"-O uimage (mkimage: flat file in)",
		func(t tools, _, flat, out string) []string {
			return []string{t.mkimage, "-A", "arm", "-O", "linux", "-T", "kernel", "-C", "none",
				"-a", "0x80000", "-e", "0x80000", "-n", "fw", "-d", flat, out}
		},
		func(elf, out string) []string {
			return []string{"-O", "uimage", "--uimage-arch", "arm", "--load", "0x80000", "--entry", "0x80000", "--name", "fw", "-o", out, elf}
		}},
}

// decodeOps read a text file (Intel HEX, S-records) back to a flat binary:
// the input side. The text is made once per fixture by objcopy from the ELF,
// and both programs read that same file.
var decodeOps = []struct {
	kind string
	op
}{
	{"ihex", op{"-I ihex -O binary",
		func(t tools, in, _, out string) []string {
			return []string{t.objcopy, "-I", "ihex", "-O", "binary", in, out}
		},
		func(in, out string) []string { return []string{"-I", "ihex", "-O", "binary", "-o", out, in} }}},
	{"srec", op{"-I srec -O binary",
		func(t tools, in, _, out string) []string {
			return []string{t.objcopy, "-I", "srec", "-O", "binary", in, out}
		},
		func(in, out string) []string { return []string{"-I", "srec", "-O", "binary", "-o", out, in} }}},
}

// run is main without the process: arguments, output and the fixture builder
// are parameters so a test can drive it with stand-in tools.
func run(args []string, w io.Writer, mk func(dir string) ([]fixture, error)) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(w)
	t := tools{}
	fs.StringVar(&t.objcopy, "objcopy", "objcopy", "objcopy binary")
	fs.StringVar(&t.mkimage, "mkimage", "mkimage", "mkimage binary")
	fs.StringVar(&t.fwimg, "fwimg", "fwimg", "fwimg binary")
	fs.StringVar(&t.uf2conv, "uf2conv", "", "path of uf2conv.py (microsoft/uf2); empty skips the UF2 row")
	rounds := fs.Int("rounds", 40, "interleaved rounds per operation and file")
	hello := fs.String("hello", "", "empty Go program (internal/floor/hello), built like fwimg: with -cobra, adds the floor table")
	cobra := fs.String("cobra", "", "cobra root that does nothing (internal/floor/cobraonly), built like fwimg")
	small := fs.String("write-small", "", "write the 1 KiB fixture ELF to this path and stop")
	index := fs.Int("fixture", 0, "with -write-small: which fixture to write (0 1 KiB, 1 4 MiB, 2 32 MiB)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*hello == "") != (*cobra == "") {
		return errors.New("-hello and -cobra go together: the floor table needs both")
	}
	if *rounds < 1 {
		return errors.New("-rounds must be at least 1")
	}
	dir, err := os.MkdirTemp("", "fwimg-bench-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	files, err := mk(dir)
	if err != nil {
		return err
	}
	if *small != "" {
		// Only the first (1 KiB) fixture, for the commands that need a real
		// ELF with sections; objcopy refuses a bare set of program headers.
		if *index < 0 || *index >= len(files) {
			return fmt.Errorf("-fixture %d: there are %d fixtures", *index, len(files))
		}
		b, err := os.ReadFile(files[*index].path)
		if err != nil {
			return err
		}
		return os.WriteFile(*small, b, 0o644)
	}
	ver, _ := exec.Command(t.objcopy, "--version").Output()
	first, _, _ := strings.Cut(string(ver), "\n")
	fmt.Fprintf(w, "reference: %s; rounds: %d; median wall time per process, interleaved\n\n", strings.TrimSpace(first), *rounds)
	fmt.Fprintln(w, "| file | operation | reference | fwimg | speedup |")
	fmt.Fprintln(w, "|---|---|---:|---:|---:|")
	out := filepath.Join(dir, "out")
	for _, f := range files {
		// The flat payload mkimage wraps, made once by fwimg itself.
		flat := filepath.Join(dir, "flat")
		if b, err := exec.Command(t.fwimg, "-O", "binary", "-o", flat, f.path).CombinedOutput(); err != nil {
			return fmt.Errorf("fwimg on %s: %v: %s", f.name, err, b)
		}
		type row struct {
			op
			src string
		}
		var rows []row
		for _, o := range append(slices.Clone(ops), l5Ops(t)...) {
			src := f.path
			if fromFlat(o) {
				src = flat
			}
			rows = append(rows, row{o, src})
		}
		for _, d := range decodeOps {
			text := filepath.Join(dir, "in."+d.kind)
			if b, err := exec.Command(t.objcopy, "-O", d.kind, f.path, text).CombinedOutput(); err != nil {
				return fmt.Errorf("objcopy -O %s on %s: %v: %s", d.kind, f.name, err, b)
			}
			rows = append(rows, row{d.op, text})
		}
		for _, o := range rows {
			var tr, to []time.Duration
			for r := 0; r < *rounds; r++ {
				order := []bool{false, true} // true = fwimg
				if r%2 == 1 {
					order = []bool{true, false}
				}
				for _, ours := range order {
					var argv []string
					if ours {
						argv = append([]string{t.fwimg}, o.ours(o.src, out)...)
					} else {
						argv = o.ref(t, o.src, flat, out)
					}
					d, err := timeOne(argv)
					if err != nil {
						return fmt.Errorf("%s %s on %s: %w", argv[0], o.name, f.name, err)
					}
					if ours {
						to = append(to, d)
					} else {
						tr = append(tr, d)
					}
				}
			}
			mr, mo := median(tr), median(to)
			fmt.Fprintf(w, "| %s | `%s` | %s | %s | %.1fx |\n", f.name, o.name, mr.Round(10*time.Microsecond), mo.Round(10*time.Microsecond), float64(mr)/float64(mo))
		}
	}
	if err := verifyCost(w, t.fwimg, files, out, *rounds); err != nil {
		return err
	}
	if *hello != "" {
		return floor(w, t, *hello, *cobra, files[0].path, out, *rounds)
	}
	return nil
}

// verifyCost times each fwimg conversion with its default check of the written
// file against the same command with --no-verify, interleaved, and prints what
// the check adds: the table above includes it, this one says how much of it it
// is. The check reads the output back, so it grows with the file.
func verifyCost(w io.Writer, fwimg string, files []fixture, out string, rounds int) error {
	fmt.Fprintf(w, "\nCost of reading the output back and comparing it (the default) against `--no-verify`; median wall time per process; %d rounds, interleaved\n\n", rounds)
	fmt.Fprintln(w, "| file | operation | --no-verify | verified | cost |")
	fmt.Fprintln(w, "|---|---|---:|---:|---:|")
	for _, f := range files {
		for _, o := range ops {
			var off, on []time.Duration
			for r := 0; r < rounds; r++ {
				order := []bool{false, true} // true = with the check
				if r%2 == 1 {
					order = []bool{true, false}
				}
				for _, verified := range order {
					args := o.ours(f.path, out)
					if !verified {
						args = append([]string{"--no-verify"}, args...)
					}
					argv := append([]string{fwimg}, args...)
					d, err := timeOne(argv)
					if err != nil {
						return fmt.Errorf("%s %s on %s: %w", argv[0], o.name, f.name, err)
					}
					if verified {
						on = append(on, d)
					} else {
						off = append(off, d)
					}
				}
			}
			a, b := median(off), median(on)
			fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s (%+.0f%%) |\n", f.name, o.name,
				a.Round(10*time.Microsecond), b.Round(10*time.Microsecond), (b - a).Round(10*time.Microsecond), 100*float64(b-a)/float64(a))
		}
	}
	return nil
}

// floor times, on the first fixture, `objcopy -O binary`, fwimg, a cobra root
// that does nothing and an empty Go program, the four rotating through the
// start position every round, and prints what the Go runtime and cobra cost
// before fwimg does any work: fwimg minus cobra-only, with the noise of that
// paired difference (the median absolute deviation over the rounds).
func floor(w io.Writer, t tools, hello, cobra, in, out string, rounds int) error {
	// Each converter writes its own file: one shared name would hand the
	// second a file the first had just written.
	procs := [4][]string{
		ops[0].ref(t, in, "", out+".objcopy"),
		append([]string{t.fwimg}, ops[0].ours(in, out+".fwimg")...),
		{cobra},
		{hello},
	}
	var samples [4][]time.Duration
	for r := 0; r < rounds; r++ {
		for k := range procs {
			i := (k + r) % len(procs)
			d, err := timeOne(procs[i])
			if err != nil {
				return fmt.Errorf("%s: %w", procs[i][0], err)
			}
			samples[i] = append(samples[i], d)
		}
	}
	diff, noise := paired(samples[1], samples[2])
	fmt.Fprintf(w, "\nStart-up floor, 1 KiB, `-O binary`; median wall time per process; %d rounds, the start position rotating\n\n", rounds)
	fmt.Fprintln(w, "| objcopy | fwimg | cobra-only | hello | fwimg minus cobra-only | noise (MAD) |")
	fmt.Fprintln(w, "|---:|---:|---:|---:|---:|---:|")
	fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n",
		median(samples[0]).Round(time.Microsecond), median(samples[1]).Round(time.Microsecond),
		median(samples[2]).Round(time.Microsecond), median(samples[3]).Round(time.Microsecond),
		diff.Round(time.Microsecond), noise.Round(time.Microsecond))
	fmt.Fprintf(w, "\n%s\n", verdict(diff, noise))
	return nil
}

// paired is the median of a[i]-b[i] and the median absolute deviation of the
// differences around it. The inputs must be in round order and have the same
// length; they are not reordered.
func paired(a, b []time.Duration) (diff, noise time.Duration) {
	diffs := make([]time.Duration, len(a))
	for i := range diffs {
		diffs[i] = a[i] - b[i]
	}
	diff = median(slices.Clone(diffs))
	for i := range diffs {
		diffs[i] = max(diffs[i]-diff, diff-diffs[i])
	}
	return diff, median(diffs)
}

func verdict(diff, noise time.Duration) string {
	if max(diff, -diff) <= noise {
		return "fwimg minus cobra-only is within the noise of the rounds."
	}
	return fmt.Sprintf("fwimg minus cobra-only is %s, beyond the noise of %s.", diff.Round(time.Microsecond), noise.Round(time.Microsecond))
}

func median(d []time.Duration) time.Duration {
	slices.Sort(d)
	return d[len(d)/2]
}

func timeOne(argv []string) (time.Duration, error) {
	c := exec.Command(argv[0], argv[1:]...)
	start := time.Now()
	out, err := c.CombinedOutput()
	d := time.Since(start)
	if err != nil {
		return 0, fmt.Errorf("%v: %s", err, out)
	}
	return d, nil
}

type fixture struct{ name, path string }

const script = `ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
  . = 0x80000;
  .text : { *(.text*) *(.rodata*) } :text
  . = 0x90010;
  .data : AT(0x90010) { *(.data*) } :data
  .bss : { *(.bss*) *(COMMON) } :data
  /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) *(.riscv.attributes) *(.ARM.attributes) }
}
`

func fixtures(dir string) ([]fixture, error) {
	if err := os.WriteFile(filepath.Join(dir, "fw.ld"), []byte(script), 0o644); err != nil {
		return nil, err
	}
	var out []fixture
	for _, f := range []struct {
		name string
		kib  int
	}{{"small (1 KiB)", 1}, {"4 MiB", 4 << 10}, {"32 MiB", 32 << 10}} {
		blob := filepath.Join(dir, fmt.Sprintf("blob-%d", f.kib))
		chunk := make([]byte, 1024)
		for i := range chunk {
			chunk[i] = byte(i*131 + 7)
		}
		if err := os.WriteFile(blob, bytes.Repeat(chunk, f.kib), 0o644); err != nil {
			return nil, err
		}
		src := filepath.Join(dir, fmt.Sprintf("fw-%d.c", f.kib))
		body := fmt.Sprintf("__asm__(\".section .data\\n.incbin \\\"%s\\\"\\n\");\nint zeros[4096];\nvoid _start(void) { for (;;) zeros[0]++; }\n", blob)
		if err := os.WriteFile(src, []byte(body), 0o644); err != nil {
			return nil, err
		}
		bin := filepath.Join(dir, fmt.Sprintf("fixture-%d", f.kib))
		cc := exec.Command("gcc", "-O1", "-ffreestanding", "-nostdlib", "-nostartfiles", "-static", "-fno-pic", "-no-pie",
			"-Wl,--build-id=none", "-Wl,-T,"+filepath.Join(dir, "fw.ld"), "-o", bin, src)
		if b, err := cc.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("gcc: %v: %s", err, b)
		}
		out = append(out, fixture{f.name, bin})
	}
	return out, nil
}
