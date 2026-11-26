package main

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// holeFile links a .text of 16 bytes at 0x8000000 and a .data of 8 bytes whose
// load and virtual addresses are given, with its section headers.
func holeFile(t *testing.T, lma, vma uint64) string {
	t.Helper()
	segs := []elfgen.Seg{
		{Paddr: 0x8000000, Vaddr: 0x8000000, Off: 0x200, Filesz: 16, Memsz: 16, Data: []byte("0123456789abcdef")},
		{Paddr: lma, Vaddr: vma, Off: 0x300, Filesz: 8, Memsz: 8, Data: []byte("DATADATA")},
	}
	secs := []elfgen.Sec{
		{Name: ".text", Type: 1, Flags: 6, Addr: 0x8000000, Off: 0x200, N: 16},
		{Name: ".data", Type: 1, Flags: 3, Addr: vma, Off: 0x300, N: 8},
	}
	return put(t, "hole.elf", elfgen.BuildSections(elf.EM_ARM, 0x8000000, segs, secs))
}

func mustRefuse(t *testing.T, want error, wants []string, notWants []string, args ...string) {
	t.Helper()
	_, _, err := runCmd(t, args...)
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("%v: err = %v, want %v", args, err, want)
	}
	if err == nil {
		t.Fatalf("%v: no error", args)
	}
	for _, w := range wants {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%v: missing %q in\n%v", args, w, err)
		}
	}
	for _, w := range notWants {
		if strings.Contains(err.Error(), w) {
			t.Errorf("%v: %q in\n%v", args, w, err)
		}
	}
}

func absent(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); err == nil {
		t.Errorf("%s exists after a refusal", p)
	}
}

func TestL3_GapRefusalNamesTheSegments(t *testing.T) {
	o := out(t)
	// .data runs in RAM and is stored in flash: --use-vaddr makes a 384 MiB hole.
	in := holeFile(t, 0x8001000, 0x20000000)
	mustRefuse(t, fwimg.ErrTooLarge, []string{
		"PT_LOAD #0 LMA 0x8000000 VMA 0x8000000", "sections .text",
		"PT_LOAD #1 LMA 0x8001000 VMA 0x20000000", "sections .data LMA 0x8001000 VMA 0x20000000",
		"without --use-vaddr",
	}, nil, "--use-vaddr", "--max-size", "1048576", "-o", o, in)
	absent(t, o)
	// Placed by load address the same file is small: no refusal, no warning.
	_, stderr, err := runCmd(t, "-o", o, in)
	if err != nil || stderr != "" {
		t.Errorf("by load address: %v, %q", err, stderr)
	}

	// Load and virtual addresses that agree, far apart: -R names the part.
	o = out(t)
	far := holeFile(t, 0x20000000, 0x20000000)
	mustRefuse(t, fwimg.ErrTooLarge, []string{"-R .data", "AT>"}, nil, "--max-size", "1048576", "-o", o, far)
	absent(t, o)
	if _, _, err := runCmd(t, "--max-size", "1048576", "-R", ".data", "-o", o, far); err != nil {
		t.Fatalf("-R .data: %v", err)
	}
	if got := get(t, o); string(got) != "0123456789abcdef" {
		t.Errorf("image = %q", got)
	}

	// The same through the options that add bytes.
	o = out(t)
	mustRefuse(t, fwimg.ErrTooLarge, []string{"PT_LOAD #1"}, nil, "--use-vaddr", "--gap-fill", "0xff", "--max-size", "65536", "-o", o, in)
	absent(t, o)
	// A pad that is not a hole between segments has nothing to explain.
	mustRefuse(t, fwimg.ErrTooLarge, []string{"padding to"}, []string{"largest hole"}, "--pad-to", "0x40000000", "--max-size", "65536", "-o", o, simple(t))
	absent(t, o)
}

func TestL3_GapRefusalWithoutALayout(t *testing.T) {
	o := out(t)
	in := holeFile(t, 0x8001000, 0x20000000)
	// The addresses were moved: the segments are not where the ELF says, so
	// only the addresses are given.
	for _, args := range [][]string{
		{"--use-vaddr", "--load", "0x1000", "--max-size", "1048576", "-o", o, in},
		{"--use-vaddr", "--change-addresses", "0x10", "--max-size", "1048576", "-o", o, in},
	} {
		mustRefuse(t, fwimg.ErrTooLarge, []string{"the largest hole is 0x"}, []string{"PT_LOAD", "-R"}, args...)
		absent(t, o)
	}
	// A hole in a file that is not an ELF.
	b, err := fwimg.EncodeSRECOpts(&fwimg.Image{Segments: []fwimg.Segment{{Addr: 0x1000, Data: []byte("AB")}, {Addr: 0x101000, Data: []byte("CD")}}}, fwimg.SRECOptions{AddrBits: 32})
	if err != nil {
		t.Fatal(err)
	}
	s := put(t, "gap.srec", b)
	mustRefuse(t, fwimg.ErrTooLarge, []string{"the largest hole is 0x1002..0x101000", "below: 0x1000..0x1002 (2 bytes)\n"}, []string{"PT_LOAD"}, "--gap-fill", "0", "--max-size", "65536", "-o", o, s)
	absent(t, o)
}

func TestL3_GapWarning(t *testing.T) {
	o := out(t)
	in := holeFile(t, 0x8200000, 0x8200000) // a 2 MiB hole for 24 bytes
	_, stderr, err := runCmd(t, "-o", o, in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fwimg: warning: the flat image is ", "bytes of fill, more than 8 times the data", "PT_LOAD #1", "-R .data"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q in\n%s", want, stderr)
		}
	}
	if len(get(t, o)) != 0x200008 {
		t.Errorf("the warning changed the image: %d bytes", len(get(t, o)))
	}
	// A uImage is flat too.
	if _, stderr, err = runCmd(t, "-O", "uimage", "-o", o, in); err != nil || !strings.Contains(stderr, "warning") {
		t.Errorf("uimage: %v, %q", err, stderr)
	}
	// A text format leaves the hole out: nothing to say.
	for _, f := range []string{"srec", "ihex"} {
		if _, stderr, err = runCmd(t, "-O", f, "-o", o, in); err != nil || stderr != "" {
			t.Errorf("%s: %v, %q", f, err, stderr)
		}
	}
	// 0 turns it off, and a ratio the image does not reach is not warned.
	for _, n := range []string{"0", "100000000"} {
		if _, stderr, err = runCmd(t, "--gap-warn", n, "-o", o, in); err != nil || stderr != "" {
			t.Errorf("--gap-warn %s: %v, %q", n, err, stderr)
		}
	}
	// A hole under 64 KiB is not reported, however large against the data.
	if _, stderr, err = runCmd(t, "-o", o, twoSeg(t)); err != nil || stderr != "" {
		t.Errorf("small hole: %v, %q", err, stderr)
	}
	// The warning of a file with no layout still gives the numbers.
	if _, stderr, err = runCmd(t, "--load", "0x1000", "-o", o, in); err != nil || !strings.Contains(stderr, "warning") || strings.Contains(stderr, "PT_LOAD") {
		t.Errorf("moved: %v, %q", err, stderr)
	}
}

func TestL3_Regions(t *testing.T) {
	o := out(t)
	in := simple(t) // 4 bytes at 0x80000
	for _, args := range [][]string{
		{"--region", "FLASH=0x80000:4", "-o", o, in},
		{"--region", "FLASH=0x80000:1M", "--region", "RAM=0x20000000:128K", "-o", o, in},
		{"--region", "A=0x80000:2", "--region", "B=0x80002:2", "-O", "srec", "-o", o, in},
		{"--region", "FLASH=512K:4", "-O", "ihex", "-o", o, in},
	} {
		if _, _, err := runCmd(t, args...); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	o = out(t)
	mustRefuse(t, fwimg.ErrRegion, []string{"region `FLASH' overflowed by 1 bytes", "segment #0 0x80000..0x80004", "PT_LOAD #0"}, nil,
		"--region", "FLASH=0x80000:3", "-o", o, in)
	absent(t, o)
	mustRefuse(t, fwimg.ErrRegion, []string{"4 bytes at 0x1010"}, nil, "-O", "srec", "--region", "RAM=0x1000:16", "-o", o, twoSeg(t))
	absent(t, o)
	mustRefuse(t, fwimg.ErrRegion, []string{"are outside every declared region"}, nil, "--region", "RAM=0x1000:16", "-o", o, in)
	absent(t, o)
	// An ELF with no section headers is described by its segments alone.
	mustRefuse(t, fwimg.ErrRegion, []string{"PT_LOAD #0 LMA 0x80000 VMA 0x0"}, []string{"sections"}, "--region", "FLASH=0x80000:3", "-o", o, in)
	// Moved by --load: no layout to describe it.
	mustRefuse(t, fwimg.ErrRegion, []string{"overflowed by"}, []string{"PT_LOAD"}, "--load", "0x80000", "--region", "FLASH=0x80000:3", "-o", o, in)
	absent(t, o)

	for _, bad := range []string{"FLASH", "FLASH=1", "FLASH=1:0", "=1:2", "A=zz:2"} {
		_, _, err := runCmd(t, "--region", bad, "-o", o, in)
		if !errors.As(err, new(usageErr)) {
			t.Errorf("--region %q: %v, want a usage error", bad, err)
		}
	}
	_, _, err := runCmd(t, "--region", "A=0:16", "--region", "A=32:16", "-o", o, in)
	if !errors.As(err, new(usageErr)) || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a name twice: %v", err)
	}
	absent(t, o)
}

// corrupt makes afterWrite damage the output; the restore is the test's.
func corrupt(t *testing.T, f func(path string)) {
	t.Helper()
	afterWrite = f
	t.Cleanup(func() { afterWrite = func(string) {} })
}

func TestL3_VerifyCatchesAWrongFile(t *testing.T) {
	in := simple(t) // "ABCD" at 0x80000, entry 0x80004
	other := &fwimg.Image{Segments: []fwimg.Segment{{Addr: 0x80000, Data: []byte("ABXD")}}, Entry: 0x80004, HasEntry: true}
	srecOther, _ := fwimg.EncodeSRECOpts(other, fwimg.SRECOptions{AddrBits: 32})
	ihexOther, _ := fwimg.EncodeIHEXOpts(other, fwimg.IHEXOptions{})
	otherPayload, _ := fwimg.UImage([]byte("ABXD"), fwimg.UImageOptions{Load: 0x80000, Entry: 0x80004, Arch: fwimg.ArchARM64, OS: 5, Type: 2})
	for _, c := range []struct {
		format string
		bad    []byte
		want   string
	}{
		{"binary", []byte("ABXD"), "address 0x80002 holds 0x58"},
		{"binary", []byte("ABC"), "ends before"},
		{"binary", []byte("ABCDE"), "longer than the image"},
		{"srec", srecOther, "address 0x80002 holds 0x58"},
		{"srec", []byte("garbage\n"), "malformed input"},
		{"ihex", ihexOther, "address 0x80002 holds 0x58"},
		{"ihex", []byte("garbage\n"), "malformed input"},
		{"uimage", otherPayload, "address 0x80002 holds 0x58"},
		{"uimage", []byte("garbage"), "malformed input"},
	} {
		o := out(t)
		corrupt(t, func(p string) {
			if err := os.WriteFile(p, c.bad, 0o644); err != nil {
				t.Fatal(err)
			}
		})
		_, _, err := runCmd(t, "-O", c.format, "-o", o, in)
		if !errors.Is(err, fwimg.ErrVerify) || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "(the file was removed)") {
			t.Errorf("%s %q: %v", c.format, c.bad, err)
		}
		absent(t, o)
	}

	// --no-verify does not read the file back, so the hook is never reached.
	o := out(t)
	corrupt(t, func(string) { t.Error("the output was checked") })
	if _, _, err := runCmd(t, "--no-verify", "-o", o, in); err != nil {
		t.Fatal(err)
	}

	// A file that cannot be removed is reported with the mismatch.
	corrupt(t, func(p string) { _ = os.WriteFile(p, []byte("ABXD"), 0o644) })
	removeFile = func(string) error { return errors.New("refused") }
	defer func() { removeFile = os.Remove }()
	o = out(t)
	if _, _, err := runCmd(t, "-o", o, in); !errors.Is(err, fwimg.ErrVerify) || !strings.Contains(err.Error(), "refused") {
		t.Errorf("unremovable: %v", err)
	}
	removeFile = os.Remove

	// A file that is gone when it is read back is an error, for every format.
	// The error is the open or read error itself, not a mismatch.
	corrupt(t, func(p string) { _ = os.Remove(p) })
	removeFile = func(string) error { return nil }
	for _, f := range []string{"binary", "srec", "ihex", "uimage"} {
		_, _, err := runCmd(t, "-O", f, "-o", out(t), in)
		if !errors.Is(err, fs.ErrNotExist) || errors.Is(err, fwimg.ErrVerify) {
			t.Errorf("%s: a vanished output: %v", f, err)
		}
	}
	removeFile = os.Remove

	// A write that fails is reported as it is: nothing is read back or removed.
	corrupt(t, func(string) { t.Error("an output that was not written was checked") })
	_, _, err := runCmd(t, "-o", filepath.Join(t.TempDir(), "missing", "x"), in)
	if !errors.Is(err, fs.ErrNotExist) || strings.Contains(err.Error(), "removed") {
		t.Errorf("an unwritable output: %v", err)
	}
}

func TestL3_VerifyPassesEveryFormat(t *testing.T) {
	for _, f := range []string{"binary", "srec", "ihex", "uimage"} {
		o := out(t)
		corrupt(t, func(p string) {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("%s: written file: %v", f, err)
			}
		})
		if _, _, err := runCmd(t, "-O", f, "--pad", "0x11", "-o", o, twoSeg(t)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	// With the options that change the image, and a start address of its own.
	o := out(t)
	for _, f := range []string{"srec", "ihex"} {
		if _, _, err := runCmd(t, "-O", f, "--gap-fill", "0xff", "--pad-to", "0x1020", "--change-start", "4", "--srec-addr-len", "auto", "--srec-count", "--crlf", "-o", o, twoSeg(t)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestL3_VerifyOnlyRegularFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /dev/null, no symbolic links")
	}
	in := simple(t)
	corrupt(t, func(p string) { _ = os.WriteFile(p, []byte("XXXX"), 0o644) })
	// A device is written, never read back or removed.
	if _, _, err := runCmd(t, "-o", os.DevNull, in); err != nil {
		t.Errorf("%s: %v", os.DevNull, err)
	}
	// A symbolic link is followed to write and left alone after: its target is
	// the user's, and unlink+create would replace the link.
	dir := t.TempDir()
	target, link := filepath.Join(dir, "target"), filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if _, _, err := runCmd(t, "-o", link, in); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v, %v", st, err)
	}
	if got := get(t, target); string(got) != "XXXX" {
		t.Errorf("target = %q: the hook ran on it and nothing removed it", got)
	}
}

func TestL3_UImageTime(t *testing.T) {
	stamp := func(t *testing.T, args ...string) uint32 {
		t.Helper()
		o := out(t)
		if _, _, err := runCmd(t, append([]string{"-O", "uimage", "-o", o}, append(args, simple(t))...)...); err != nil {
			t.Fatal(err)
		}
		return binary.BigEndian.Uint32(get(t, o)[8:])
	}
	t.Setenv("SOURCE_DATE_EPOCH", "")
	os.Unsetenv("SOURCE_DATE_EPOCH")
	if got := stamp(t); got != 0 {
		t.Errorf("default time = %d, want 0", got)
	}
	if got := stamp(t, "--time", "1700000000"); got != 1700000000 {
		t.Errorf("--time = %d", got)
	}
	if got := stamp(t, "--time", "0x10"); got != 16 {
		t.Errorf("--time 0x10 = %d", got)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "86400")
	if got := stamp(t); got != 86400 {
		t.Errorf("SOURCE_DATE_EPOCH = %d", got)
	}
	if got := stamp(t, "--time", "5"); got != 5 {
		t.Errorf("--time over the environment = %d", got)
	}
	// The same command line makes the same file.
	a, b := out(t), out(t)
	for _, p := range []string{a, b} {
		if _, _, err := runCmd(t, "-O", "uimage", "-o", p, simple(t)); err != nil {
			t.Fatal(err)
		}
	}
	if string(get(t, a)) != string(get(t, b)) {
		t.Error("two runs differ")
	}

	// A value that is not seconds is refused where mkimage writes 0.
	for _, bad := range []string{"abc", "", "-1", "4294967296", "1.5"} {
		t.Setenv("SOURCE_DATE_EPOCH", bad)
		o := out(t)
		_, _, err := runCmd(t, "-O", "uimage", "-o", o, simple(t))
		if !errors.Is(err, fwimg.ErrFormat) || !strings.Contains(err.Error(), "SOURCE_DATE_EPOCH") {
			t.Errorf("SOURCE_DATE_EPOCH=%q: %v", bad, err)
		}
		absent(t, o)
		// ... but only a uImage has a time.
		if _, _, err := runCmd(t, "-o", o, simple(t)); err != nil {
			t.Errorf("SOURCE_DATE_EPOCH=%q, binary: %v", bad, err)
		}
		// ... and --time wins over it.
		if got := stamp(t, "--time", "7"); got != 7 {
			t.Errorf("--time over a bad environment = %d", got)
		}
	}

	o := out(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--time", "5", "-o", o, simple(t)}, "--time is only for -O uimage"},
		{[]string{"-O", "uimage", "--time", "x", "-o", o, simple(t)}, "--time"},
		{[]string{"-O", "uimage", "--time", "0x100000000", "-o", o, simple(t)}, "--time"},
	} {
		_, _, err := runCmd(t, c.args...)
		if !errors.As(err, new(usageErr)) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v", c.args, err)
		}
	}
	absent(t, o)
}

func TestL3_HelpListsTheFlags(t *testing.T) {
	stdout, _, err := runCmd(t, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"--region", "--gap-warn", "--no-verify", "--time"} {
		if !strings.Contains(stdout, f) {
			t.Errorf("--help lacks %s", f)
		}
	}
}
