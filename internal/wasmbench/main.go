// Command wasmbench times the native fwimg against the same program built for
// GOOS=js GOARCH=wasm (run by node) and GOOS=wasip1 GOARCH=wasm (run by wazero
// or wasmtime), as processes, on ELF files of 1 KiB, 4 MiB and 32 MiB in two
// loadable segments, in interleaved rounds (the runner that goes first rotates
// every round), and prints a Markdown table of medians. Run it pinned to one
// core, from a quiet machine:
//
//	taskset -c 0 ./wasmbench -native ./fwimg -js ./fwimg-js.wasm -wasi ./fwimg-wasip1.wasm -rounds 15
//
// -js and -wasi are run through the Go distribution's own wrappers
// (lib/wasm/go_js_wasm_exec, go_wasip1_wasm_exec), the ones `go test` uses; the
// wasip1 runtime is named by -runtime (wazero by default). A wasm run pays for
// starting a runtime and compiling the module on every process, which is what
// the 1 KiB row shows; the 32 MiB row is the throughput.
package main

import (
	"bytes"
	"debug/elf"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wasmbench:", err)
		os.Exit(1)
	}
}

type runner struct {
	name string
	argv []string
	env  []string
}

type op struct {
	name string
	args func(in, out string) []string
}

var ops = []op{
	{"-O binary", func(in, out string) []string { return []string{"-O", "binary", "-o", out, in} }},
	{"-O srec", func(in, out string) []string { return []string{"-O", "srec", "-o", out, in} }},
	{"-O uimage", func(in, out string) []string { return []string{"-O", "uimage", "-o", out, in} }},
}

// sizes of the fixtures: the data of the two segments together.
var sizes = []struct {
	name string
	n    int
}{{"1 KiB", 1 << 10}, {"4 MiB", 4 << 20}, {"32 MiB", 32 << 20}}

// makeFixture is a variable so a test can make the fixture fail.
var makeFixture = fixture

func fixture(path string, n int) error {
	data := make([]byte, n/2)
	x := uint32(12345)
	for i := range data {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		if i%4 == 0 {
			data[i] = byte(x)
		} else {
			data[i] = byte(i)
		}
	}
	segs := []elfgen.Seg{
		{Paddr: 0x08000000, Vaddr: 0x08000000, Off: 0x1000, Filesz: uint64(len(data)), Memsz: uint64(len(data)), Data: data},
		{Paddr: 0x0c000000, Vaddr: 0x0c000000, Off: 0x1000 + uint64(len(data)), Filesz: uint64(len(data)), Memsz: uint64(len(data)), Data: data},
	}
	return os.WriteFile(path, elfgen.Build(elf.EM_ARM, 0x08000000, segs), 0o644)
}

func median(d []time.Duration) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[len(s)/2]
}

// once runs one conversion and returns its wall time; a non-zero exit is an
// error, so a runner that fails cannot post a fast time.
func once(r runner, args []string) (time.Duration, error) {
	c := exec.Command(r.argv[0], append(slices.Clone(r.argv[1:]), args...)...)
	c.Env = append(os.Environ(), r.env...)
	var e bytes.Buffer
	c.Stderr = &e
	t := time.Now()
	err := c.Run()
	d := time.Since(t)
	if err != nil {
		return 0, fmt.Errorf("%s %v: %w\n%s", r.name, args, err, e.String())
	}
	return d, nil
}

func run(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("wasmbench", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	native := fs.String("native", "", "the native fwimg")
	js := fs.String("js", "", "fwimg built with GOOS=js GOARCH=wasm")
	wasi := fs.String("wasi", "", "fwimg built with GOOS=wasip1 GOARCH=wasm")
	rt := fs.String("runtime", "wazero", "the wasip1 runtime: wazero, wasmtime, wasmer, wasmedge")
	goroot := fs.String("goroot", "", "GOROOT, for lib/wasm (default: go env GOROOT)")
	rounds := fs.Int("rounds", 15, "rounds per cell")
	big := fs.Bool("big", true, "include the 32 MiB row")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rounds < 1 {
		return fmt.Errorf("-rounds must be at least 1")
	}
	if *native == "" {
		return fmt.Errorf("-native is required")
	}
	if *goroot == "" {
		b, err := exec.Command("go", "env", "GOROOT").Output()
		if err != nil {
			return err
		}
		*goroot = string(bytes.TrimSpace(b))
	}
	lib := filepath.Join(*goroot, "lib", "wasm")
	rs := []runner{{name: "native", argv: []string{*native}}}
	if *js != "" {
		rs = append(rs, runner{name: "js (node)", argv: []string{filepath.Join(lib, "go_js_wasm_exec"), *js}})
	}
	if *wasi != "" {
		rs = append(rs, runner{name: "wasip1 (" + *rt + ")", argv: []string{filepath.Join(lib, "go_wasip1_wasm_exec"), *wasi}, env: []string{"GOWASIRUNTIME=" + *rt}})
	}
	dir, err := os.MkdirTemp("", "wasmbench")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	fmt.Fprintf(w, "| input | operation |")
	for _, r := range rs {
		fmt.Fprintf(w, " %s |", r.name)
		if r.name != "native" {
			fmt.Fprintf(w, " x native |")
		}
	}
	fmt.Fprintf(w, "\n|---|---|")
	for _, r := range rs {
		fmt.Fprintf(w, "---:|")
		if r.name != "native" {
			fmt.Fprintf(w, "---:|")
		}
	}
	fmt.Fprintln(w)
	for _, sz := range sizes {
		if sz.n > 4<<20 && !*big {
			continue
		}
		in := filepath.Join(dir, "in.elf")
		if err := makeFixture(in, sz.n); err != nil {
			return err
		}
		for _, o := range ops {
			out := filepath.Join(dir, "out")
			times := make([][]time.Duration, len(rs))
			for round := 0; round < *rounds+1; round++ { // round 0 warms caches (wazero's compile cache) and is dropped
				for k := range rs {
					i := (k + round) % len(rs)
					_ = os.Remove(out)
					d, err := once(rs[i], o.args(in, out))
					if err != nil {
						return err
					}
					if round > 0 {
						times[i] = append(times[i], d)
					}
				}
			}
			fmt.Fprintf(w, "| %s | %s |", sz.name, o.name)
			base := median(times[0])
			for i := range rs {
				m := median(times[i])
				fmt.Fprintf(w, " %s |", m.Round(10*time.Microsecond))
				if i > 0 {
					fmt.Fprintf(w, " %.1f |", float64(m)/float64(base))
				}
			}
			fmt.Fprintln(w)
		}
	}
	return nil
}
