//go:build !js && !wasip1

package main

import (
	"bytes"
	"debug/elf"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// The wasm builds must write the same bytes as the native one. This lane builds
// cmd/fwimg three ways (native, GOOS=js GOARCH=wasm, GOOS=wasip1 GOARCH=wasm),
// runs one corpus through each as a command (js under node, wasip1 under
// wazero or wasmtime) and compares exit status, standard output, standard error
// and the written file with the native run's, byte for byte. The same corpus
// then goes through the playground engine (playground/engine.js: the js build on
// an in-memory file system), the way the docs page runs it.
//
// FWIMG_REQUIRE_WASM=1 turns a missing node or wasm runtime into a failure, so
// that CI cannot go green by skipping.

// wcase is one command line of the corpus. {in} and {out} are the input and
// output paths; in names an input of wsbInputs.
type wcase struct {
	name string
	in   string
	args []string
	// opts, when set, is the same conversion as the playground's option object.
	opts map[string]any
}

type wsbInput struct {
	name string
	data []byte
}

// wsbData is deterministic pseudo-random data: compressible enough to exercise
// gzip and lz4 on something other than zeros, and different on every byte.
func wsbData(n int, seed uint32) []byte {
	b := make([]byte, n)
	x := seed | 1
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		if i%7 < 3 {
			b[i] = byte(i) // a run of structure
		} else {
			b[i] = byte(x)
		}
	}
	return b
}

func wsbSource(t *testing.T, native string, dir string) []wsbInput {
	t.Helper()
	small := elfgen.Build(elf.EM_ARM, 0x08000000, []elfgen.Seg{
		{Paddr: 0x08000000, Vaddr: 0x08000000, Off: 0x400, Filesz: 1024, Memsz: 1024, Data: wsbData(1024, 1)},
		{Paddr: 0x08004000, Vaddr: 0x08004000, Off: 0x800, Filesz: 512, Memsz: 640, Data: wsbData(512, 2)},
	})
	sections := elfgen.BuildSections(elf.EM_ARM, 0x08000000, []elfgen.Seg{
		{Paddr: 0x08000000, Vaddr: 0x08000000, Off: 0x400, Filesz: 256, Memsz: 256, Data: wsbData(256, 3)},
		{Paddr: 0x08000200, Vaddr: 0x08000200, Off: 0x500, Filesz: 256, Memsz: 256, Data: wsbData(256, 4)},
	}, []elfgen.Sec{
		{Name: ".text", Type: uint32(elf.SHT_PROGBITS), Flags: 6, Addr: 0x08000000, Off: 0x400, N: 256},
		{Name: ".data", Type: uint32(elf.SHT_PROGBITS), Flags: 3, Addr: 0x08000200, Off: 0x500, N: 256},
	})
	kernel := elfgen.Build(elf.EM_AARCH64, 0x80000, []elfgen.Seg{
		{Paddr: 0x80000, Vaddr: 0xffff000000080000, Off: 0x1000, Filesz: 8192, Memsz: 8192, Data: wsbData(8192, 5)},
	})
	big := elfgen.Build(elf.EM_RISCV, 0x20000000, []elfgen.Seg{
		{Paddr: 0x20000000, Vaddr: 0x20000000, Off: 0x1000, Filesz: 1 << 20, Memsz: 1 << 20, Data: wsbData(1<<20, 6)},
		{Paddr: 0x20200000, Vaddr: 0x20200000, Off: 0x101000, Filesz: 4096, Memsz: 4096, Data: wsbData(4096, 7)},
	})
	in := []wsbInput{
		{"small.elf", small}, {"sections.elf", sections}, {"kernel.elf", kernel}, {"big.elf", big},
		{"truncated.elf", small[:100]}, {"garbage.bin", wsbData(300, 8)},
		{"raw.bin", wsbData(2000, 9)},
	}
	// Inputs of the other formats are what the native build writes from an ELF:
	// the corpus holds exactly what the tool itself produces.
	mk := func(name, from string, args ...string) {
		p := filepath.Join(dir, name)
		a := append(append([]string{}, args...), "-o", p, filepath.Join(dir, from))
		if out, err := exec.Command(native, a...).CombinedOutput(); err != nil {
			t.Fatalf("making %s: %v\n%s", name, err, out)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		in = append(in, wsbInput{name, b})
	}
	for _, i := range in {
		if err := os.WriteFile(filepath.Join(dir, i.name), i.data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("small.hex", "small.elf", "-O", "ihex")
	mk("small.srec", "small.elf", "-O", "srec")
	mk("small.uimage", "small.elf", "-O", "uimage", "--uimage-comp", "gzip", "--name", "fw")
	mk("small.uf2", "small.elf", "-O", "uf2", "--uf2-family", "rp2040")
	mk("small.v", "small.elf", "-O", "verilog", "--verilog-data-width", "4")
	// A corrupt Intel HEX file: the checksum of the first record is wrong.
	hex := bytes.Clone(in[len(in)-5].data)
	if i := bytes.IndexByte(hex, '\n'); i > 2 {
		hex[i-1] ^= 1
	}
	in = append(in, wsbInput{"badsum.hex", hex})
	if err := os.WriteFile(filepath.Join(dir, "badsum.hex"), hex, 0o644); err != nil {
		t.Fatal(err)
	}
	return in
}

func wsbCases(inputs []wsbInput) []wcase {
	var cs []wcase
	add := func(name, in string, opts map[string]any, args ...string) {
		cs = append(cs, wcase{name, in, append(args, "-o", "{out}", "{in}"), opts})
	}
	for _, f := range []string{"binary", "srec", "ihex", "uimage", "uf2", "verilog"} {
		for _, i := range []string{"small.elf", "kernel.elf", "sections.elf", "big.elf"} {
			// uimage from an ELF needs nothing else: arch and entry come from it.
			add(f+" of "+i, i, map[string]any{"format": f}, "-O", f)
		}
	}
	add("uimage gzip", "small.elf", map[string]any{"format": "uimage", "uimageComp": "gzip", "name": "fw"}, "-O", "uimage", "--uimage-comp", "gzip", "--name", "fw")
	add("uimage lz4", "kernel.elf", map[string]any{"format": "uimage", "uimageComp": "lz4"}, "-O", "uimage", "--uimage-comp", "lz4")
	add("uimage arm64 load entry time", "kernel.elf", map[string]any{"format": "uimage", "load": "0x80000", "entry": "0x80000", "time": "1700000000", "name": "linux"},
		"-O", "uimage", "--load", "0x80000", "--entry", "0x80000", "--time", "1700000000", "--name", "linux")
	add("uf2 rp2040", "small.elf", map[string]any{"format": "uf2", "uf2Family": "rp2040"}, "-O", "uf2", "--uf2-family", "rp2040")
	add("verilog width 4 big", "small.elf", map[string]any{"format": "verilog", "verilogWidth": "4", "verilogEndian": "big"},
		"-O", "verilog", "--verilog-data-width", "4", "--verilog-endian", "big")
	add("binary pad ff", "small.elf", map[string]any{"format": "binary", "pad": "0xff"}, "-O", "binary", "--pad", "0xff")
	add("binary pad-to", "small.elf", map[string]any{"format": "binary", "gapFill": "0xaa", "padTo": "0x08004400"}, "-O", "binary", "--gap-fill", "0xaa", "--pad-to", "0x08004400")
	add("binary use-vaddr", "kernel.elf", map[string]any{"format": "binary", "useVaddr": true}, "-O", "binary", "--use-vaddr")
	add("binary only .text", "sections.elf", map[string]any{"format": "binary", "only": []string{".text"}}, "-O", "binary", "-j", ".text")
	add("binary remove .data", "sections.elf", map[string]any{"format": "binary", "remove": []string{".data"}}, "-O", "binary", "-R", ".data")
	add("ihex crlf objcopy mode", "small.elf", map[string]any{"format": "ihex", "crlf": true, "ihexMode": "objcopy"}, "-O", "ihex", "--crlf", "--ihex-mode", "objcopy")
	add("srec count auto", "small.elf", map[string]any{"format": "srec", "srecCount": true, "srecAddrLen": "auto"}, "-O", "srec", "--srec-count", "--srec-addr-len", "auto")
	add("srec change-addresses", "small.elf", map[string]any{"format": "srec", "changeAddresses": "0x1000"}, "-O", "srec", "--change-addresses", "0x1000")
	add("binary region ok", "small.elf", map[string]any{"format": "binary", "region": []string{"flash=0x08000000:64K"}}, "-O", "binary", "--region", "flash=0x08000000:64K")
	add("binary region overflow", "small.elf", map[string]any{"format": "binary", "region": []string{"flash=0x08000000:1K"}}, "-O", "binary", "--region", "flash=0x08000000:1K")
	add("binary max-size refused", "small.elf", map[string]any{"format": "binary", "maxSize": "16"}, "-O", "binary", "--max-size", "16")
	add("no-verify", "small.elf", nil, "-O", "srec", "--no-verify")
	// Other inputs, detected and forced.
	for _, i := range []string{"small.hex", "small.srec", "small.uimage", "small.uf2", "small.v"} {
		for _, f := range []string{"binary", "ihex", "srec", "uf2"} {
			args, o := []string{"-O", f}, map[string]any{"format": f}
			if i == "small.v" {
				// Verilog is not detected from its bytes: it is named, and so is its width.
				args = []string{"-O", f, "-I", "verilog", "--verilog-data-width", "4"}
				o = map[string]any{"format": f, "inputFormat": "verilog", "verilogWidth": "4"}
			}
			add(f+" of "+i, i, o, args...)
		}
	}
	add("raw binary with base", "raw.bin", map[string]any{"format": "ihex", "inputFormat": "binary", "base": "0x20000000"}, "-I", "binary", "--base", "0x20000000", "-O", "ihex")
	add("raw binary to uimage", "raw.bin", map[string]any{"format": "uimage", "inputFormat": "binary", "base": "0x8000", "entry": "0x8000", "uimageArch": "arm"},
		"-I", "binary", "--base", "0x8000", "--entry", "0x8000", "--uimage-arch", "arm", "-O", "uimage")
	// Refusals: the same status, the same words, and no file.
	add("raw binary without -I", "raw.bin", nil, "-O", "binary")
	add("garbage", "garbage.bin", nil, "-O", "binary")
	add("truncated elf", "truncated.elf", nil, "-O", "binary")
	add("bad checksum", "badsum.hex", nil, "-O", "binary")
	add("unknown format", "small.elf", nil, "-O", "elf")
	add("uimage comp on srec", "small.elf", nil, "-O", "srec", "--uimage-comp", "gzip")
	// info and its JSON, for every input.
	for _, i := range inputs {
		cs = append(cs, wcase{name: "info " + i.name, in: i.name, args: []string{"info", "{in}"}})
		cs = append(cs, wcase{name: "info --json " + i.name, in: i.name, args: []string{"info", "--json", "{in}"}})
	}
	cs = append(cs, wcase{name: "version", in: "small.elf", args: []string{"--version"}})
	return cs
}

// wsbRunner runs the command line of one build.
type wsbRunner struct {
	name string
	exec func(args []string) (code int, stdout, stderr string)
}

func wsbExec(name string, env []string, argv ...string) func([]string) (int, string, string) {
	return func(args []string) (int, string, string) {
		c := exec.Command(argv[0], append(append([]string{}, argv[1:]...), args...)...)
		c.Env = append(os.Environ(), env...)
		var o, e bytes.Buffer
		c.Stdout, c.Stderr = &o, &e
		err := c.Run()
		code := 0
		var ee *exec.ExitError
		switch {
		case errors.As(err, &ee):
			code = ee.ExitCode()
		case err != nil:
			return -1, o.String(), err.Error()
		}
		return code, o.String(), e.String()
	}
}

type wsbResult struct {
	code           int
	stdout, stderr string
	out            []byte // nil: no file
}

// wsbRun runs one case with one runner, in its own output directory.
func wsbRun(t *testing.T, r wsbRunner, c wcase, inDir, outDir string) wsbResult {
	t.Helper()
	in := filepath.Join(inDir, c.in)
	out := filepath.Join(outDir, "out")
	_ = os.Remove(out)
	args := make([]string, len(c.args))
	for i, a := range c.args {
		args[i] = strings.NewReplacer("{in}", in, "{out}", out).Replace(a)
	}
	code, so, se := r.exec(args)
	rep := strings.NewReplacer(out, "{out}", in, "{in}")
	res := wsbResult{code: code, stdout: rep.Replace(so), stderr: rep.Replace(se)}
	if b, err := os.ReadFile(out); err == nil {
		res.out = b
	}
	return res
}

func wsbBuild(t *testing.T, dir, goos, goarch, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	c := exec.Command("go", "build", "-trimpath", "-o", out, ".")
	c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("go build %s/%s: %v\n%s", goos, goarch, err, b)
	}
	return out
}

func wsbMissing(t *testing.T, what string) {
	t.Helper()
	if os.Getenv("FWIMG_REQUIRE_WASM") != "" {
		t.Fatalf("FWIMG_REQUIRE_WASM is set and %s is not available", what)
	}
	t.Skipf("%s is not available", what)
}

func TestWasmSameBytesAsNative(t *testing.T) {
	if r := os.Getenv("FWIMG_SKIP_DIFF"); r != "" {
		t.Skip(r) // emulated: the go tool and node cannot be exec'd from inside the emulator
	}
	root := t.TempDir()
	native := wsbBuild(t, root, "", "", "fwimg-native")
	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(strings.TrimSpace(string(goroot)), "lib", "wasm")
	if _, err := os.Stat(filepath.Join(lib, "go_js_wasm_exec")); err != nil {
		wsbMissing(t, "GOROOT/lib/wasm")
	}

	inDir := filepath.Join(root, "in")
	if err := os.Mkdir(inDir, 0o755); err != nil {
		t.Fatal(err)
	}
	inputs := wsbSource(t, native, inDir)
	cases := wsbCases(inputs)

	// What the native build does is the expectation.
	nativeRunner := wsbRunner{"native", wsbExec("native", nil, native)}
	nativeOut := filepath.Join(root, "out-native")
	if err := os.Mkdir(nativeOut, 0o755); err != nil {
		t.Fatal(err)
	}
	want := make([]wsbResult, len(cases))
	wrote, refused := 0, 0
	for i, c := range cases {
		want[i] = wsbRun(t, nativeRunner, c, inDir, nativeOut)
		if want[i].out != nil {
			wrote++
		}
		if want[i].code != 0 {
			refused++
		}
	}
	// A corpus that only refuses, or only writes, proves little.
	if wrote < 60 || refused < 6 {
		t.Fatalf("corpus too thin: %d cases wrote a file, %d were refused", wrote, refused)
	}
	t.Logf("corpus: %d cases, %d write a file, %d are refused", len(cases), wrote, refused)

	compare := func(t *testing.T, r wsbRunner, i int, got wsbResult) {
		t.Helper()
		w, c := want[i], cases[i]
		if got.code != w.code {
			t.Errorf("%s %q: exit status %d, native %d\nstderr: %s", r.name, c.name, got.code, w.code, got.stderr)
			return
		}
		if got.stdout != w.stdout {
			t.Errorf("%s %q: standard output differs from native", r.name, c.name)
		}
		if got.stderr != w.stderr {
			t.Errorf("%s %q: standard error differs\n got: %q\nwant: %q", r.name, c.name, got.stderr, w.stderr)
		}
		if !bytes.Equal(got.out, w.out) || (got.out == nil) != (w.out == nil) {
			t.Errorf("%s %q: the written file differs (%d bytes, native %d; nil=%v/%v)", r.name, c.name, len(got.out), len(w.out), got.out == nil, w.out == nil)
		}
	}

	runAll := func(t *testing.T, r wsbRunner) {
		out := filepath.Join(root, "out-"+strings.ReplaceAll(r.name, "/", "-"))
		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatal(err)
		}
		for i, c := range cases {
			compare(t, r, i, wsbRun(t, r, c, inDir, out))
		}
	}

	var jsWasm string
	t.Run("js under node", func(t *testing.T) {
		node, err := exec.LookPath("node")
		if err != nil {
			wsbMissing(t, "node")
		}
		_ = node
		jsWasm = wsbBuild(t, root, "js", "wasm", "fwimg-js.wasm")
		runAll(t, wsbRunner{"js/node", wsbExec("js", nil, filepath.Join(lib, "go_js_wasm_exec"), jsWasm)})
	})

	t.Run("wasip1", func(t *testing.T) {
		rt := os.Getenv("GOWASIRUNTIME")
		if rt == "" {
			for _, c := range []string{"wazero", "wasmtime"} {
				if _, err := exec.LookPath(c); err == nil {
					rt = c
					break
				}
			}
		}
		if rt == "" {
			wsbMissing(t, "wazero or wasmtime")
		}
		w := wsbBuild(t, root, "wasip1", "wasm", "fwimg-wasip1.wasm")
		runAll(t, wsbRunner{"wasip1/" + rt, wsbExec("wasip1", []string{"GOWASIRUNTIME=" + rt, "TMPDIR=" + root}, filepath.Join(lib, "go_wasip1_wasm_exec"), w)})
	})

	// The page's engine: the js build on an in-memory file system, the corpus
	// run as commands and the options of the page as conversions.
	t.Run("playground engine", func(t *testing.T) {
		node, err := exec.LookPath("node")
		if err != nil {
			wsbMissing(t, "node")
		}
		if jsWasm == "" {
			jsWasm = wsbBuild(t, root, "js", "wasm", "fwimg-js.wasm")
		}
		type mrun struct {
			Name       string   `json:"name"`
			Input      string   `json:"input"`
			Args       []string `json:"args"`
			WantCode   int      `json:"wantCode"`
			WantOut    string   `json:"wantOut"`
			WantStdout string   `json:"wantStdout"`
			WantStderr string   `json:"wantStderr"`
		}
		type mconv struct {
			Name     string         `json:"name"`
			Input    string         `json:"input"`
			Options  map[string]any `json:"options"`
			WantOut  string         `json:"wantOut"`
			WantInfo string         `json:"wantInfo"`
		}
		var m struct {
			Run     []mrun  `json:"run"`
			Convert []mconv `json:"convert"`
		}
		for i, c := range cases {
			w := want[i]
			mr := mrun{Name: c.name, Input: filepath.Join(inDir, c.in), Args: c.args, WantCode: w.code, WantStdout: w.stdout, WantStderr: w.stderr}
			if w.out != nil {
				mr.WantOut = filepath.Join(root, "want", strings.ReplaceAll(c.name, " ", "_")+".bin")
				if err := os.MkdirAll(filepath.Dir(mr.WantOut), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(mr.WantOut, w.out, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			m.Run = append(m.Run, mr)
			// A conversion that works natively, with the page's options.
			if c.opts != nil && w.out != nil && w.code == 0 {
				var info []byte
				// info is given the flags that say how the input is read.
				ia := []string{"info", "--json"}
				for j, a := range c.args {
					switch a {
					case "-I", "--base", "--verilog-data-width", "--verilog-endian":
						ia = append(ia, a, c.args[j+1])
					case "--use-vaddr":
						ia = append(ia, a)
					}
				}
				ic := wcase{in: c.in, args: append(ia, "{in}")}
				ir := wsbRun(t, nativeRunner, ic, inDir, nativeOut)
				if ir.code == 0 {
					info = []byte(ir.stdout)
				}
				m.Convert = append(m.Convert, mconv{c.name, mr.Input, c.opts, mr.WantOut, string(info)})
			}
		}
		mf := filepath.Join(root, "manifest.json")
		b, _ := json.Marshal(m)
		if err := os.WriteFile(mf, b, 0o644); err != nil {
			t.Fatal(err)
		}
		c := exec.Command(node, filepath.Join("..", "..", "playground", "check.js"), filepath.Join(lib, "wasm_exec.js"), jsWasm, mf)
		if o, err := c.CombinedOutput(); err != nil {
			t.Fatalf("playground engine differs from native: %v\n%s", err, o)
		} else {
			t.Logf("%s", o)
		}
	})
}
