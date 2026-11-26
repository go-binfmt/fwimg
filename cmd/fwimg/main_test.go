package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
	"github.com/go-binfmt/fwimg/internal/elfgen"
)

func runCmd(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := RootCmd()
	var o, e bytes.Buffer
	cmd.SetOut(&o)
	cmd.SetErr(&e)
	cmd.SetArgs(args)
	// A crash is reported as a failed assertion, so that a mutated guard fails
	// a test on the refusal it owes instead of ending the test binary.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%v: the command crashed instead of refusing: %v", args, r)
		}
	}()
	err = cmd.Execute()
	return o.String(), e.String(), err
}

func writeELF(t *testing.T, machine elf.Machine, entry uint64, segs ...elfgen.Seg) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.elf")
	if err := os.WriteFile(p, elfgen.Build(machine, entry, segs), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func simple(t *testing.T) string {
	return writeELF(t, elf.EM_AARCH64, 0x80004, elfgen.Seg{Paddr: 0x80000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("ABCD")})
}

func TestBinary(t *testing.T) {
	out := filepath.Join(t.TempDir(), "k.img")
	if _, _, err := runCmd(t, "-o", out, simple(t)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "ABCD" {
		t.Errorf("image = %q", b)
	}
}

func TestSRECIHEXAndUImage(t *testing.T) {
	in := simple(t)
	dir := t.TempDir()
	for _, f := range []string{"srec", "ihex"} {
		out := filepath.Join(dir, f)
		if _, _, err := runCmd(t, "-O", f, "--name", "fw", "-o", out, in); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		b, _ := os.ReadFile(out)
		if !strings.Contains(string(b), "41424344") {
			t.Errorf("%s output lacks the payload:\n%s", f, b)
		}
	}
	srec, _ := os.ReadFile(filepath.Join(dir, "srec"))
	if !strings.Contains(string(srec), "S70500080004") {
		t.Errorf("S7 does not carry the ELF entry:\n%s", srec)
	}
	out := filepath.Join(dir, "u")
	if _, _, err := runCmd(t, "-O", "uimage", "--name", "linux", "-o", out, in); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if len(b) != 68 || b[29] != fwimg.ArchARM64 {
		t.Errorf("uimage len=%d arch=%d, want 68 and arm64 from the ELF", len(b), b[29])
	}
	if binary.BigEndian.Uint32(b[16:]) != 0x80000 || binary.BigEndian.Uint32(b[20:]) != 0x80004 {
		t.Error("load/entry not taken from the ELF")
	}
}

func TestOverridesAndPad(t *testing.T) {
	in := writeELF(t, elf.EM_ARM, 0,
		elfgen.Seg{Paddr: 0x1000, Off: 0x200, Filesz: 1, Memsz: 1, Data: []byte("A")},
		elfgen.Seg{Paddr: 0x1003, Off: 0x300, Filesz: 1, Memsz: 1, Data: []byte("B")})
	out := filepath.Join(t.TempDir(), "o")
	if _, _, err := runCmd(t, "--pad", "0xff", "-o", out, in); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "A\xff\xffB" {
		t.Errorf("padded image = %q", b)
	}
	if _, _, err := runCmd(t, "-O", "uimage", "--load", "0x2000", "--entry", "4096", "--uimage-arch", "riscv", "--uimage-os", "17", "--uimage-type", "1", "-o", out, in); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if binary.BigEndian.Uint32(b[16:]) != 0x2000 || binary.BigEndian.Uint32(b[20:]) != 4096 || b[28] != 17 || b[29] != fwimg.ArchRISCV || b[30] != 1 {
		t.Errorf("overrides not honoured: % x", b[:32])
	}
}

func TestRefusals(t *testing.T) {
	good := simple(t)
	far := writeELF(t, elf.EM_X86_64, 0,
		elfgen.Seg{Paddr: 0, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
		elfgen.Seg{Paddr: 0x7fff_ffff_0000, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")})
	high := writeELF(t, elf.EM_X86_64, 0xffffffff80001000, elfgen.Seg{Paddr: 0xffffffff80000000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")})
	nearTop := writeELF(t, elf.EM_ARM, 0, elfgen.Seg{Paddr: 0xFFFFFFFE, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")})
	notELF := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(notELF, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "never")
	cases := []struct {
		name string
		args []string
		want string
		code int
	}{
		{"no output", []string{good}, "-o/--output is required", 2},
		{"no input", []string{"-o", out}, "accepts 1 arg", 2},
		{"bad format", []string{"-O", "elf", "-o", out, good}, "unknown --output-target", 2},
		{"bad arch", []string{"-O", "uimage", "--uimage-arch", "sparc", "-o", out, good}, "unknown uimage arch", 2},
		{"bad pad", []string{"--pad", "256", "-o", out, good}, "--pad", 2},
		{"bad load", []string{"--load", "0x100000000", "-o", out, good}, "--load", 2},
		{"bad max-size", []string{"--max-size", "x", "-o", out, good}, "--max-size", 2},
		{"missing file", []string{"-o", out, filepath.Join(t.TempDir(), "absent")}, "no such file", 1},
		{"bad entry", []string{"--entry", "0x100000000", "-o", out, good}, "--entry", 2},
		{"not an ELF", []string{"-o", out, notELF}, notELF + ": ", 1},
		{"distant segments", []string{"-o", out, far}, "larger than the allowed size", 1},
		{"max-size honoured", []string{"--max-size", "2", "-o", out, good}, "larger than the allowed size", 1},
		{"base above 32 bits", []string{"-O", "srec", "-o", out, high}, "image base", 1},
		{"entry above 32 bits", []string{"-O", "uimage", "--load", "0x1000", "-o", out, high}, "ELF entry", 1},
		{"srec past 4 GiB", []string{"-O", "srec", "-o", out, nearTop}, "past 4 GiB", 1},
		{"ihex past 4 GiB", []string{"-O", "ihex", "-o", out, nearTop}, "past 4 GiB", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := runCmd(t, c.args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to contain %q", err, c.want)
			}
			_, isUsage := err.(usageErr)
			if isUsage != (c.code == 2) {
				t.Errorf("usage error = %v, want %v", isUsage, c.code == 2)
			}
			if _, statErr := os.Stat(out); statErr == nil {
				t.Errorf("a refused run wrote %s", out)
			}
		})
	}
}

// The input limit and a failing Stat are driven through their seams: a 2 GiB
// ELF and a descriptor whose fstat fails are not available on demand.
func TestInputLimitAndStatFailure(t *testing.T) {
	in := simple(t)
	out := filepath.Join(t.TempDir(), "never")
	oldMax, oldStat := maxInput, statFile
	defer func() { maxInput, statFile = oldMax, oldStat }()

	size := int64(len(elfgen.Build(elf.EM_AARCH64, 0, []elfgen.Seg{{Paddr: 0x80000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("ABCD")}})))
	maxInput = size // exactly at the limit: accepted
	if _, _, err := runCmd(t, "-o", out, in); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if err := os.Remove(out); err != nil {
		t.Fatal(err)
	}
	maxInput = size - 1
	if _, _, err := runCmd(t, "-o", out, in); err == nil || !strings.Contains(err.Error(), "input limit") {
		t.Fatalf("one byte over the limit: err = %v", err)
	}
	maxInput = oldMax
	statFile = func(*os.File) (os.FileInfo, error) { return nil, os.ErrPermission }
	if _, _, err := runCmd(t, "-o", out, in); err == nil || !strings.Contains(err.Error(), in+": ") {
		t.Fatalf("failing stat: err = %v", err)
	}
	if _, err := os.Stat(out); err == nil {
		t.Errorf("a refused run wrote %s", out)
	}
}

// countReader counts Read calls: the sized read exists to make two of them on
// a file of the stated size, where io.ReadAll made five on 1 KiB.
type countReader struct {
	r     io.Reader
	calls int
	err   error
}

func (c *countReader) Read(p []byte) (int, error) {
	c.calls++
	if c.err != nil {
		return 0, c.err
	}
	return c.r.Read(p)
}

func TestReadSized(t *testing.T) {
	data := bytes.Repeat([]byte("xyz"), 700) // 2100 bytes
	for _, tc := range []struct {
		name  string
		size  int64
		calls int
	}{
		{"exact", int64(len(data)), 2},
		{"stat too small", 10, 0}, // the file grew: still read in full
		{"stat too large", int64(len(data)) + 4096, 2},
		{"zero", 0, 0},
	} {
		cr := &countReader{r: bytes.NewReader(data)}
		got, err := readSized(cr, tc.size)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%s: %d bytes, err %v", tc.name, len(got), err)
		}
		if tc.calls != 0 && cr.calls != tc.calls {
			t.Errorf("%s: %d reads, want %d", tc.name, cr.calls, tc.calls)
		}
	}
	sentinel := errors.New("boom")
	if _, err := readSized(&countReader{err: sentinel}, 8); !errors.Is(err, sentinel) {
		t.Errorf("read error: %v", err)
	}
	// The same failure after the stated size has been read.
	tail := io.MultiReader(bytes.NewReader(data), &countReader{err: sentinel})
	if _, err := readSized(tail, int64(len(data))); !errors.Is(err, sentinel) {
		t.Errorf("read error after the body: %v", err)
	}
	// A directory opens and stats but cannot be read: the error names it.
	dir := t.TempDir()
	if _, _, err := runCmd(t, "-o", filepath.Join(t.TempDir(), "never"), dir); err == nil || !strings.Contains(err.Error(), dir+": ") || !strings.Contains(err.Error(), "directory") {
		t.Errorf("a directory as input: err = %v", err)
	}
	// Past the limit the read stops at maxInput+1 bytes, which the caller's
	// stat check has already refused for a file of that size.
	old := maxInput
	defer func() { maxInput = old }()
	maxInput = 100
	got, err := readSized(bytes.NewReader(data), 5)
	if err != nil || len(got) != 101 {
		t.Errorf("limit: %d bytes, err %v", len(got), err)
	}
}

func TestHighBaseWithExplicitAddresses(t *testing.T) {
	high := writeELF(t, elf.EM_X86_64, 0xffffffff80001000, elfgen.Seg{Paddr: 0xffffffff80000000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")})
	out := filepath.Join(t.TempDir(), "u")
	if _, _, err := runCmd(t, "-O", "uimage", "--load", "0x1000", "--entry", "0x1000", "-o", out, high); err != nil {
		t.Fatal(err)
	}
}

func TestVersion(t *testing.T) {
	old := Version
	defer func() { Version = old }()
	Version = "v1.2.3"
	oldBI := readBuildInfo
	defer func() { readBuildInfo = oldBI }()
	// A stamped Version wins over the build info.
	readBuildInfo = func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}}, true }
	if o, _, err := runCmd(t, "--version"); err != nil || o != "fwimg v1.2.3\n" {
		t.Fatalf("out=%q err=%v", o, err)
	}
	Version = "dev"
	oldRBI := readBuildInfo
	defer func() { readBuildInfo = oldRBI }()
	readBuildInfo = func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: "v0.9.0"}}, true }
	if version() != "v0.9.0" {
		t.Errorf("stamped version = %q", version())
	}
	readBuildInfo = func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true }
	if version() != "dev" {
		t.Errorf("devel version = %q", version())
	}
	readBuildInfo = func() (*debug.BuildInfo, bool) { return nil, false }
	if version() != "dev" {
		t.Errorf("no build info = %q", version())
	}
}

func TestMainExitCodes(t *testing.T) {
	oldExit := osExit
	defer func() { osExit = oldExit }()
	var code int
	osExit = func(c int) { code = c }
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	for args, want := range map[string]int{"--version": 0, "x.elf": 2, "-o /nonexistent/dir/x /nonexistent/in": 1} {
		code = 0
		os.Args = append([]string{"fwimg"}, strings.Fields(args)...)
		main()
		if code != want {
			t.Errorf("args %q: exit %d, want %d", args, code, want)
		}
	}
}

// An existing output is replaced by a new file of the same permission bits
// (objcopy unlinks it too: truncating it in place makes ext4 write it all out
// at close, go-binfmt/fwimg#17); a file that cannot be unlinked is truncated.
func TestWriteOutputReplacesExisting(t *testing.T) {
	out := filepath.Join(t.TempDir(), "k.img")
	if err := os.WriteFile(out, bytes.Repeat([]byte("x"), 100), 0o600); err != nil {
		t.Fatal(err)
	}
	// Held open, the old file keeps its inode number: a freed one could be
	// handed to the new file.
	held, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	before, _ := held.Stat()
	if _, _, err := runCmd(t, "-o", out, simple(t)); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "ABCD" {
		t.Errorf("image = %q", b)
	}
	if after.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want the old 0600 kept", after.Mode().Perm())
	}
	if os.SameFile(before, after) {
		t.Error("the existing file was truncated in place, want it unlinked and created again")
	}

	// An unlink that is refused falls back to truncating the file.
	removeFile = func(string) error { return errors.New("refused") }
	defer func() { removeFile = os.Remove }()
	if err := os.WriteFile(out, bytes.Repeat([]byte("y"), 100), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ = os.Stat(out)
	if _, _, err := runCmd(t, "-o", out, simple(t)); err != nil {
		t.Fatal(err)
	}
	after, _ = os.Stat(out)
	if b, _ := os.ReadFile(out); string(b) != "ABCD" || !os.SameFile(before, after) {
		t.Errorf("image = %q, same file %v", b, os.SameFile(before, after))
	}
}

func TestWriteOutputRefusals(t *testing.T) {
	in := simple(t)
	if _, _, err := runCmd(t, "-o", filepath.Join(t.TempDir(), "none", "k.img"), in); err == nil || !strings.Contains(err.Error(), "none") {
		t.Errorf("an output in a directory that does not exist: %v", err)
	}
	// A refused size leaves no output file behind, nor touches an existing one.
	out := filepath.Join(t.TempDir(), "k.img")
	if err := os.WriteFile(out, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCmd(t, "-O", "binary", "--max-size", "2", "-o", out, in); !errors.Is(err, fwimg.ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "keep" {
		t.Errorf("a refused image replaced the output: %q", b)
	}
}
