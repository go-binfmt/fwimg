package fwimg

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The differential lane: link a real freestanding ELF with gcc and a linker
// script, convert it with GNU objcopy and U-Boot's mkimage, and compare with
// what this package produces from the same file. It needs Linux, gcc, objcopy
// and mkimage, so it SKIPS elsewhere (a macOS laptop has none of them) and is
// REQUIRED in CI: FWIMG_REQUIRE_DIFF turns every skip into a failure, so a
// runner image that loses u-boot-tools cannot turn the lane into a green tick.
// FWIMG_SKIP_DIFF=<reason> is for the one lane (qemu) that cannot exec host
// tools. Nothing binary is committed: the fixture is built at test time.

func need(t *testing.T, tools ...string) map[string]string {
	t.Helper()
	if why := os.Getenv("FWIMG_SKIP_DIFF"); why != "" {
		t.Skip("differential lane skipped: " + why)
	}
	missing := func(format string, a ...any) {
		t.Helper()
		if os.Getenv("FWIMG_REQUIRE_DIFF") != "" {
			t.Fatalf("differential lane is REQUIRED here but "+format, a...)
		}
		t.Skipf("differential lane needs "+format, a...)
	}
	if runtime.GOOS != "linux" {
		missing("Linux (gcc, objcopy, mkimage), this is %s", runtime.GOOS)
	}
	paths := map[string]string{}
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			missing("%s on PATH", tool)
		}
		paths[tool] = p
	}
	return paths
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	c := exec.Command(name, args...)
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	if err := c.Run(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out.String())
	}
}

const linkerScript = `ENTRY(_start)
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

// fixture links two loadable segments 0x10 bytes past a 64 KiB boundary
// apart, with initialised data in both and a .bss that objcopy must not emit.
func fixture(t *testing.T) (elfPath string, f *elf.File) {
	t.Helper()
	dir := t.TempDir()
	var blob strings.Builder
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&blob, "%d,", (i*131+7)&0xff)
	}
	var data strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&data, "%d,", uint64(i)*2654435761%100000+1)
	}
	src := fmt.Sprintf(`const unsigned char blob[] = {%s};
int words[] = {%s};
int zeros[4096];
void _start(void) { for (;;) { zeros[words[0] & 1023] += blob[words[1] %% 1500]; } }
`, blob.String(), data.String())
	srcPath := filepath.Join(dir, "fw.c")
	ldPath := filepath.Join(dir, "fw.ld")
	elfPath = filepath.Join(dir, "fw.elf")
	for p, c := range map[string]string{srcPath: src, ldPath: linkerScript} {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(t, "gcc", "-O1", "-ffreestanding", "-nostdlib", "-nostartfiles", "-static", "-fno-pic", "-no-pie",
		"-Wl,--build-id=none", "-Wl,-T,"+ldPath, "-o", elfPath, srcPath)
	f, err := elf.Open(elfPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return elfPath, f
}

func flattenFile(t *testing.T, path string, o FlattenOptions) ([]byte, uint64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out, base, err := Flatten(bytes.NewReader(b), int64(len(b)), o)
	if err != nil {
		t.Fatal(err)
	}
	return out, base
}

func TestDifferential_BinaryAgainstObjcopy(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, _ := fixture(t)
	for _, pad := range []byte{0x00, 0xff} {
		ref := filepath.Join(t.TempDir(), "ref.bin")
		run(t, "objcopy", "-O", "binary", fmt.Sprintf("--gap-fill=%d", pad), elfPath, ref)
		want, err := os.ReadFile(ref)
		if err != nil {
			t.Fatal(err)
		}
		got, base := flattenFile(t, elfPath, FlattenOptions{Pad: pad})
		if base != 0x80000 {
			t.Errorf("base = 0x%x, want 0x80000", base)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("pad 0x%02x: %d bytes, objcopy made %d; first difference at %d", pad, len(got), len(want), firstDiff(got, want))
		}
	}
}

func firstDiff(a, b []byte) int {
	for i := 0; i < min(len(a), len(b)); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// sameAsObjcopy: every byte objcopy records is at the same address in ours,
// and every byte of ours that objcopy did not record (the gap between the two
// segments, which objcopy leaves out of a text format) is the pad byte.
func sameAsObjcopy(t *testing.T, what string, ref map[uint32]byte, ours map[uint32]byte, pad byte) {
	t.Helper()
	if len(ref) == 0 {
		t.Fatalf("%s: objcopy recorded nothing", what)
	}
	for a, b := range ref {
		if got, ok := ours[a]; !ok || got != b {
			t.Fatalf("%s: byte at 0x%x is 0x%x (present %v), objcopy has 0x%x", what, a, got, ok, b)
		}
	}
	gap := 0
	for a, b := range ours {
		if _, ok := ref[a]; !ok {
			gap++
			if b != pad {
				t.Fatalf("%s: byte at 0x%x outside objcopy's records is 0x%x, want pad 0x%x", what, a, b, pad)
			}
		}
	}
	if gap == 0 {
		t.Errorf("%s: the fixture has no gap between segments, the pad is untested", what)
	}
}

func TestDifferential_SRECAgainstObjcopy(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, ef := fixture(t)
	ref := filepath.Join(t.TempDir(), "ref.srec")
	run(t, "objcopy", "-O", "srec", "--srec-forceS3", elfPath, ref)
	refBytes, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	refMem, refEntry, _ := parseSREC(t, refBytes)
	flat, base := flattenFile(t, elfPath, FlattenOptions{})
	out, err := SREC(uint32(base), flat, "fw", uint32(ef.Entry), 0)
	if err != nil {
		t.Fatal(err)
	}
	mem, entry, name := parseSREC(t, out)
	sameAsObjcopy(t, "srec", refMem, mem, 0)
	if entry != refEntry || uint64(entry) != ef.Entry {
		t.Errorf("entry 0x%x, objcopy 0x%x, ELF 0x%x", entry, refEntry, ef.Entry)
	}
	if name != "fw" {
		t.Errorf("name %q", name)
	}
}

func TestDifferential_IHEXAgainstObjcopy(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, _ := fixture(t)
	ref := filepath.Join(t.TempDir(), "ref.hex")
	run(t, "objcopy", "-O", "ihex", elfPath, ref)
	refBytes, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	refMem, refEOF := parseIHEX(t, refBytes)
	if !refEOF {
		t.Fatal("objcopy's file has no EOF record")
	}
	flat, base := flattenFile(t, elfPath, FlattenOptions{})
	out, err := IHEX(uint32(base), flat, 0)
	if err != nil {
		t.Fatal(err)
	}
	mem, eof := parseIHEX(t, out)
	if !eof {
		t.Error("no EOF record")
	}
	sameAsObjcopy(t, "ihex", refMem, mem, 0)
}

// mkimageArch names the architecture of the linked fixture (the machine
// gcc targets, which is not runtime.GOARCH in the 386 lane) for mkimage -A.
func mkimageArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_RISCV:
		return "riscv"
	}
	return ""
}

func TestDifferential_UImageAgainstMkimage(t *testing.T) {
	need(t, "gcc", "mkimage")
	elfPath, ef := fixture(t)
	arch := mkimageArch(ef.Machine)
	if arch == "" {
		t.Fatalf("no mkimage architecture name for ELF machine %v", ef.Machine)
	}
	flat, base := flattenFile(t, elfPath, FlattenOptions{})
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(payload, flat, 0o644); err != nil {
		t.Fatal(err)
	}
	// mkimage stamps the data file's mtime (or SOURCE_DATE_EPOCH): pin both.
	const stamp = 1700000000
	if err := os.Chtimes(payload, time.Unix(stamp, 0), time.Unix(stamp, 0)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", fmt.Sprint(stamp))
	for _, tc := range []struct {
		typ  string
		code byte
		comp string
		c    byte
	}{{"kernel", TypeKernel, "none", CompNone}, {"standalone", TypeStandalone, "none", CompNone}, {"firmware", TypeFirmware, "gzip", CompGzip}} {
		ref := filepath.Join(dir, "ref."+tc.typ)
		run(t, "mkimage", "-A", arch, "-O", "linux", "-T", tc.typ, "-C", tc.comp,
			"-a", fmt.Sprintf("0x%x", base), "-e", fmt.Sprintf("0x%x", ef.Entry),
			"-n", "firmware-image", "-d", payload, ref)
		want, err := os.ReadFile(ref)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := ArchFromName(arch)
		got, err := UImage(flat, UImageOptions{
			Load: uint32(base), Entry: uint32(ef.Entry), Name: "firmware-image",
			OS: OSLinux, Arch: a, Type: tc.code, Comp: tc.c, Time: stamp,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("type %s: %d bytes, mkimage made %d; first difference at %d\nours:    % x\nmkimage: % x",
				tc.typ, len(got), len(want), firstDiff(got, want), got[:min(64, len(got))], want[:min(64, len(want))])
		}
	}
}
