package fwimg

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The L3 differential lane: SOURCE_DATE_EPOCH against mkimage, the hole
// objcopy writes without a word, the overflow figure of ld's MEMORY command,
// and the verdict of srec_cmp. Same rules as differential_test.go.

// link builds src with gcc and the linker script, and returns the ELF and what
// the linker said.
func link(t *testing.T, name, src, script string) (elfPath, output string, err error) {
	t.Helper()
	dir := t.TempDir()
	srcPath, ldPath := filepath.Join(dir, name+".c"), filepath.Join(dir, name+".ld")
	elfPath = filepath.Join(dir, name+".elf")
	for p, c := range map[string]string{srcPath: src, ldPath: script} {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c := exec.Command("gcc", "-O1", "-ffreestanding", "-nostdlib", "-nostartfiles", "-static", "-fno-pic", "-no-pie",
		"-Wl,--build-id=none", "-Wl,-T,"+ldPath, "-o", elfPath, srcPath)
	var b bytes.Buffer
	c.Stdout, c.Stderr = &b, &b
	err = c.Run()
	return elfPath, b.String(), err
}

func TestDifferential_SourceDateEpochAgainstMkimage(t *testing.T) {
	need(t, "mkimage")
	dir := t.TempDir()
	payload := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(payload, []byte("0123456789abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	mk := func(t *testing.T, env string) ([]byte, error) {
		t.Helper()
		ref := filepath.Join(dir, "ref")
		os.Remove(ref)
		c := exec.Command("mkimage", "-A", "arm", "-O", "linux", "-T", "kernel", "-C", "none",
			"-a", "0x1000", "-e", "0x1000", "-n", "x", "-d", payload, ref)
		c.Env = append(os.Environ(), "SOURCE_DATE_EPOCH="+env)
		if out, err := c.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("%v: %s", err, out)
		}
		return os.ReadFile(ref)
	}
	flat := []byte("0123456789abcdef")
	for _, v := range []string{"0", "1", "86400", "1700000000", "4294967295", "007"} {
		want, err := mk(t, v)
		if err != nil {
			t.Fatal(err)
		}
		tm, err := ParseEpoch(v)
		if err != nil {
			t.Fatalf("ParseEpoch(%q): %v", v, err)
		}
		got, err := UImage(flat, UImageOptions{Load: 0x1000, Entry: 0x1000, Name: "x", OS: OSLinux, Arch: ArchARM, Type: TypeKernel, Time: tm})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("SOURCE_DATE_EPOCH=%q: first difference at %d\nours:    % x\nmkimage: % x", v, firstDiff(got, want), got[:64], want[:64])
		}
	}
	// A value that is not seconds: fwimg refuses where mkimage writes whatever
	// strtoull left (0 or a prefix). The mkimage side is logged, not asserted:
	// it is the behaviour being departed from, not one to pin.
	for _, v := range []string{"abc", "-1", "1.5", "", " 1", "4294967296", "0x10"} {
		if _, err := ParseEpoch(v); !errors.Is(err, ErrFormat) {
			t.Errorf("ParseEpoch(%q) = %v, want ErrFormat", v, err)
		}
		if b, err := mk(t, v); err != nil {
			t.Logf("mkimage with SOURCE_DATE_EPOCH=%q fails: %v", v, err)
		} else {
			t.Logf("mkimage with SOURCE_DATE_EPOCH=%q writes time %d", v, uint32(b[8])<<24|uint32(b[9])<<16|uint32(b[10])<<8|uint32(b[11]))
		}
	}
}

const holeSource = `const unsigned char a[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
int b[] = {1,2,3,4};
void _start(void) { for (;;) { if (a[b[0]] == b[1]) break; } }
`

// objcopy -O binary writes a 64 MiB file for a .data linked 64 MiB past the
// code, and says nothing. fwimg says what makes the hole.
const holeScript = `ENTRY(_start)
PHDRS { text PT_LOAD FLAGS(5); data PT_LOAD FLAGS(6); }
SECTIONS {
  . = 0x80000;
  .text : { *(.text*) *(.rodata*) } :text
  . = 0x4080000;
  .data : AT(0x4080000) { *(.data*) } :data
  /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) *(.riscv.attributes) *(.ARM.attributes) }
}
`

func TestDifferential_ObjcopyIsSilentOnAHole(t *testing.T) {
	need(t, "gcc", "objcopy")
	elfPath, msg, err := link(t, "hole", holeSource, holeScript)
	if err != nil {
		t.Fatalf("link: %v\n%s", err, msg)
	}
	ref := filepath.Join(t.TempDir(), "ref.bin")
	c := exec.Command("objcopy", "-O", "binary", elfPath, ref)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		t.Fatalf("objcopy: %v\n%s", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("objcopy said something about the hole (then the premise is gone): %q", stderr.String())
	}
	data, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatal(err)
	}
	im, err := ELFImage(data, FlattenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	flat, _, err := im.Flat(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(flat, want) {
		t.Fatalf("flat image %d bytes, objcopy %d", len(flat), len(want))
	}
	if len(flat) < 64<<20 {
		t.Fatalf("the fixture has no hole: %d bytes", len(flat))
	}
	expl := im.ExplainGap(ELFLayout(data, false))
	for _, w := range []string{"the largest hole is 0x", "PT_LOAD #0 LMA 0x80000", "PT_LOAD #1 LMA 0x4080000", ".data LMA 0x4080000"} {
		if !strings.Contains(expl, w) {
			t.Errorf("missing %q in\n%s", w, expl)
		}
	}
	if w := im.GapWarning(8); w == "" {
		t.Error("a 64 MiB hole for 36 bytes drew no warning")
	}
}

const regionSource = `const unsigned char blob[] = {%s};
void _start(void) { for (;;) { if (blob[blob[0]]) break; } }
`

const discard = `  /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) *(.riscv.attributes) *(.ARM.attributes) }`

func TestDifferential_RegionsAgainstLd(t *testing.T) {
	need(t, "gcc", "ld")
	var blob strings.Builder
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&blob, "%d,", (i*131+7)&0xff)
	}
	src := fmt.Sprintf(regionSource, blob.String())
	// ld, with the region: it refuses and says by how much.
	_, msg, err := link(t, "bound", src, `ENTRY(_start)
MEMORY { FLASH (rx) : ORIGIN = 0x80000, LENGTH = 0x400 }
SECTIONS {
  .text : { *(.text*) *(.rodata*) *(.data*) } > FLASH
`+discard+`
}
`)
	if err == nil {
		t.Fatalf("ld linked 1500 bytes into 0x400:\n%s", msg)
	}
	re := regexp.MustCompile("region `FLASH' overflowed by ([0-9]+) bytes")
	// ld words it "overflowed by N bytes" or, when the whole section does not
	// fit, "will not fit in region" with no number (binutils 2.4x).
	m := re.FindStringSubmatch(msg)
	var ldExcess uint64
	if m != nil {
		ldExcess, _ = strconv.ParseUint(m[1], 10, 64)
	} else if !strings.Contains(msg, "will not fit in region `FLASH'") {
		t.Fatalf("no overflow in ld's words:\n%s", msg)
	} else {
		t.Logf("ld gives no byte count:\n%s", msg)
	}

	// The same sections linked with no bound: fwimg measures the same excess.
	elfPath, msg, err := link(t, "free", src, `ENTRY(_start)
SECTIONS {
  . = 0x80000;
  .text : { *(.text*) *(.rodata*) *(.data*) }
`+discard+`
}
`)
	if err != nil {
		t.Fatalf("link: %v\n%s", err, msg)
	}
	data, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatal(err)
	}
	im, err := ELFImage(data, FlattenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	err = im.CheckRegions([]Region{{"FLASH", 0x80000, 0x400}}, ELFLayout(data, false).Describe)
	if !errors.Is(err, ErrRegion) {
		t.Fatalf("CheckRegions: %v", err)
	}
	m = re.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("no overflow in ours:\n%v", err)
	}
	ours, _ := strconv.ParseUint(m[1], 10, 64)
	if end := im.Base() + uint64(im.Span()); ours != end-0x80400 {
		t.Errorf("fwimg says %d bytes over, the image ends %d past the region\n%v", ours, end-0x80400, err)
	}
	if ldExcess != 0 && ours != ldExcess {
		t.Errorf("fwimg says %d bytes over, ld says %d\n%v", ours, ldExcess, err)
	}
	// And the region that holds it is not refused.
	if err := im.CheckRegions([]Region{{"FLASH", 0x80000, 0x1000}}, nil); err != nil {
		t.Errorf("a region of 4 KiB: %v", err)
	}
}

func TestDifferential_VerifyAgainstSrecCmp(t *testing.T) {
	need(t, "gcc", "objcopy", "srec_cmp")
	elfPath, _ := fixture(t)
	dir := t.TempDir()
	ref := filepath.Join(dir, "ref.srec")
	run(t, "objcopy", "-O", "srec", elfPath, ref)
	data, err := os.ReadFile(elfPath)
	if err != nil {
		t.Fatal(err)
	}
	im, err := ELFImage(data, FlattenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, im *Image) string {
		t.Helper()
		b, err := EncodeSRECOpts(im, SRECOptions{AddrBits: 32})
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cmp := func(a, b string) (string, bool) {
		out, err := exec.Command("srec_cmp", a, b).CombinedOutput()
		return string(out), err == nil
	}
	decoded := func(p string) *Image {
		t.Helper()
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeSREC(b, DecodeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// objcopy's file and ours: srec_cmp and CompareImages agree they are the same.
	ours := write("ours.srec", im)
	if out, same := cmp(ours, ref); !same {
		t.Errorf("srec_cmp says our file differs from objcopy's:\n%s", out)
	}
	if err := CompareImages(im, decoded(ref)); err != nil {
		t.Errorf("CompareImages on objcopy's file: %v", err)
	}
	if err := CompareImages(im, decoded(ours)); err != nil {
		t.Errorf("CompareImages on our file: %v", err)
	}

	// One byte changed in the last segment: both say so.
	bad := &Image{Entry: im.Entry, HasEntry: im.HasEntry}
	for _, s := range im.Segments {
		bad.Segments = append(bad.Segments, Segment{Addr: s.Addr, Data: bytes.Clone(s.Data)})
	}
	last := bad.Segments[len(bad.Segments)-1].Data
	last[len(last)/2] ^= 0x40
	badPath := write("bad.srec", bad)
	if out, same := cmp(badPath, ref); same {
		t.Errorf("srec_cmp found a changed byte equal:\n%s", out)
	}
	if err := CompareImages(im, decoded(badPath)); !errors.Is(err, ErrVerify) {
		t.Errorf("CompareImages on a changed byte: %v", err)
	}
	// A byte missing: the same.
	short := &Image{Entry: im.Entry, HasEntry: im.HasEntry, Segments: bad.Segments[:len(bad.Segments)-1]}
	shortPath := write("short.srec", short)
	if _, same := cmp(shortPath, ref); same {
		t.Error("srec_cmp found a missing segment equal")
	}
	if err := CompareImages(im, decoded(shortPath)); !errors.Is(err, ErrVerify) {
		t.Errorf("CompareImages on a missing segment: %v", err)
	}
}
