package fwimg

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

type seg = elfgen.Seg

func buildELF(machine elf.Machine, segs []seg) []byte {
	return elfgen.Build(machine, 0, segs)
}

func flat(t *testing.T, img []byte, o FlattenOptions) ([]byte, uint64, error) {
	t.Helper()
	return Flatten(bytes.NewReader(img), int64(len(img)), o)
}

// --- Flatten ------------------------------------------------------------------

func TestFlatten_GapAndPad(t *testing.T) {
	img := buildELF(elf.EM_AARCH64, []seg{
		{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
		{Paddr: 0x1008, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")},
	})
	out, base, err := flat(t, img, FlattenOptions{Pad: 0xff})
	if err != nil {
		t.Fatal(err)
	}
	if base != 0x1000 {
		t.Errorf("base = 0x%x, want 0x1000", base)
	}
	want := []byte{'A', 'A', 'A', 'A', 0xff, 0xff, 0xff, 0xff, 'B', 'B', 'B', 'B'}
	if !bytes.Equal(out, want) {
		t.Errorf("flat = % x, want % x", out, want)
	}
}

func TestFlatten_SegmentsOutOfOrderInTable(t *testing.T) {
	img := buildELF(elf.EM_AARCH64, []seg{
		{Paddr: 0x1008, Off: 0x300, Filesz: 2, Memsz: 2, Data: []byte("BB")},
		{Paddr: 0x1000, Off: 0x200, Filesz: 2, Memsz: 2, Data: []byte("AA")},
	})
	out, base, err := flat(t, img, FlattenOptions{})
	if err != nil || base != 0x1000 || string(out[:2]) != "AA" || string(out[8:]) != "BB" {
		t.Fatalf("out=% x base=0x%x err=%v", out, base, err)
	}
}

func TestFlatten_UseVaddrZeroPad(t *testing.T) {
	img := buildELF(elf.EM_X86_64, []seg{
		{Paddr: 0x9000, Vaddr: 0x2000, Off: 0x200, Filesz: 2, Memsz: 2, Data: []byte("hi")},
	})
	out, base, err := flat(t, img, FlattenOptions{UseVaddr: true})
	if err != nil {
		t.Fatal(err)
	}
	if base != 0x2000 || !bytes.Equal(out, []byte("hi")) {
		t.Errorf("base=0x%x out=%q", base, out)
	}
}

func TestFlatten_NoLoadable(t *testing.T) {
	img := buildELF(elf.EM_AARCH64, []seg{{Paddr: 0x1000, Off: 0x200, Filesz: 0, Memsz: 8}})
	if _, _, err := flat(t, img, FlattenOptions{}); err == nil || !strings.Contains(err.Error(), "no PT_LOAD") {
		t.Fatalf("err = %v, want no-PT_LOAD", err)
	}
}

func TestFlatten_BadELF(t *testing.T) {
	noPanic(t, "Flatten of a file that is not an ELF", func() {
		if _, _, err := Flatten(bytes.NewReader([]byte("not elf")), 7, FlattenOptions{}); err == nil || !strings.Contains(err.Error(), "parse ELF") {
			t.Errorf("err = %v, want parse-ELF", err)
		}
	})
}

type failAt struct {
	r       *bytes.Reader
	failOff int64
}

func (f failAt) ReadAt(p []byte, off int64) (int, error) {
	if off == f.failOff {
		return 0, errors.New("synthetic failure")
	}
	return f.r.ReadAt(p, off)
}

func TestFlattenBytes_MatchesFlatten(t *testing.T) {
	img := buildELF(elf.EM_AARCH64, []seg{{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}})
	out, base, err := FlattenBytes(img, FlattenOptions{})
	if err != nil || base != 0x1000 || string(out) != "AAAA" {
		t.Fatalf("FlattenBytes = %q, 0x%x, %v", out, base, err)
	}
}

func TestFlatten_RefusesInputOver2GiBBeforeReading(t *testing.T) {
	// The reader would fail if it were read: nothing is allocated or read for
	// a size the parser cannot hold.
	r := failAt{r: bytes.NewReader(nil), failOff: 0}
	_, _, err := Flatten(r, 1<<31, FlattenOptions{})
	if !errors.Is(err, ErrRange) || strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("err = %v, want ErrRange without a read", err)
	}
	noPanic(t, "Flatten of a negative size", func() {
		if _, _, err := Flatten(bytes.NewReader(nil), -5, FlattenOptions{}); err == nil {
			t.Error("negative size accepted")
		}
	})
}

func TestFlatten_ReadError(t *testing.T) {
	img := buildELF(elf.EM_AARCH64, []seg{{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}})
	r := failAt{r: bytes.NewReader(img), failOff: 0}
	if _, _, err := Flatten(r, int64(len(img)), FlattenOptions{}); err == nil || !strings.Contains(err.Error(), "read ELF") {
		t.Fatalf("err = %v, want read-ELF", err)
	}
}

// --- Flatten: refusals --------------------------------------------------------

// Two segments 128 TiB apart used to ask make() for the whole distance.
// The bomb runs under a memory limit and must allocate next to nothing.
func TestFlatten_RefusesDistantSegments(t *testing.T) {
	old := debug.SetMemoryLimit(256 << 20)
	defer debug.SetMemoryLimit(old)
	img := buildELF(elf.EM_X86_64, []seg{
		{Paddr: 0, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
		{Paddr: 0x7fff_ffff_0000, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")},
	})
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, err := flat(t, img, FlattenOptions{})
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 4<<20 {
		t.Errorf("a refused image allocated %d bytes", grew)
	}
}

func TestFlatten_MaxSizeBoundary(t *testing.T) {
	img := buildELF(elf.EM_ARM, []seg{
		{Paddr: 0x1000, Off: 0x200, Filesz: 1, Memsz: 1, Data: []byte("A")},
		{Paddr: 0x1000 + 63, Off: 0x300, Filesz: 1, Memsz: 1, Data: []byte("B")},
	})
	if out, _, err := flat(t, img, FlattenOptions{MaxSize: 64}); err != nil || len(out) != 64 {
		t.Fatalf("exactly at the limit: len=%d err=%v", len(out), err)
	}
	if _, _, err := flat(t, img, FlattenOptions{MaxSize: 63}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one over the limit: err = %v, want ErrTooLarge", err)
	}
}

func TestFlatten_DefaultBoundIsTheConstant(t *testing.T) {
	// One byte past DefaultMaxSize in span, refused; the span itself is
	// built from the constant so raising it does not break the test.
	img := buildELF(elf.EM_ARM, []seg{
		{Paddr: 0, Off: 0x200, Filesz: 1, Memsz: 1, Data: []byte("A")},
		{Paddr: DefaultMaxSize, Off: 0x300, Filesz: 1, Memsz: 1, Data: []byte("B")},
	})
	if _, _, err := flat(t, img, FlattenOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestFlatten_RefusesFileRange(t *testing.T) {
	for name, s := range map[string]seg{
		"filesz larger than the file": {Paddr: 0x1000, Off: 0x200, Filesz: 1 << 40, Memsz: 1 << 40},
		"filesz near 2^63":            {Paddr: 0x1000, Off: 0x200, Filesz: math.MaxInt64 - 0x100, Memsz: 8},
		"offset near 2^63":            {Paddr: 0x1000, Off: math.MaxInt64 - 1, Filesz: 4, Memsz: 4},
		"offset past the end":         {Paddr: 0x1000, Off: 1 << 40, Filesz: 4, Memsz: 4},
		"ends one byte past":          {Paddr: 0x1000, Off: 0x3ff, Filesz: 2, Memsz: 2},
	} {
		t.Run(name, func(t *testing.T) {
			img := buildELF(elf.EM_X86_64, []seg{s})
			if _, _, err := flat(t, img, FlattenOptions{}); !errors.Is(err, ErrRange) {
				t.Fatalf("err = %v, want ErrRange", err)
			}
		})
	}
}

func TestFlatten_RefusesAddressWrap(t *testing.T) {
	img := buildELF(elf.EM_X86_64, []seg{
		{Paddr: math.MaxUint64 - 1, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
	})
	if _, _, err := flat(t, img, FlattenOptions{}); !errors.Is(err, ErrAddrOverflow) {
		t.Fatalf("err = %v, want ErrAddrOverflow", err)
	}
}

func TestFlatten_AcceptsTopOfAddressSpace(t *testing.T) {
	// The last byte of the 64-bit space: addr+filesz == 2^64 exactly would
	// wrap to 0, so one byte below it is the highest span that is legal.
	img := buildELF(elf.EM_X86_64, []seg{
		{Paddr: math.MaxUint64 - 4, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
	})
	out, base, err := flat(t, img, FlattenOptions{})
	if err != nil || base != math.MaxUint64-4 || string(out) != "AAAA" {
		t.Fatalf("out=%q base=0x%x err=%v", out, base, err)
	}
}

func TestFlatten_RefusesOverlap(t *testing.T) {
	img := buildELF(elf.EM_ARM, []seg{
		{Paddr: 0x1000, Off: 0x200, Filesz: 8, Memsz: 8, Data: []byte("AAAAAAAA")},
		{Paddr: 0x1004, Off: 0x300, Filesz: 8, Memsz: 8, Data: []byte("BBBBBBBB")},
	})
	if _, _, err := flat(t, img, FlattenOptions{}); !errors.Is(err, ErrOverlap) {
		t.Fatalf("err = %v, want ErrOverlap", err)
	}
	same := buildELF(elf.EM_ARM, []seg{
		{Paddr: 0x1000, Off: 0x200, Filesz: 8, Memsz: 8, Data: []byte("AAAAAAAA")},
		{Paddr: 0x1000, Off: 0x300, Filesz: 8, Memsz: 8, Data: []byte("BBBBBBBB")},
	})
	if _, _, err := flat(t, same, FlattenOptions{}); !errors.Is(err, ErrOverlap) {
		t.Fatalf("same address: err = %v, want ErrOverlap", err)
	}
	adjacent := buildELF(elf.EM_ARM, []seg{
		{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
		{Paddr: 0x1004, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")},
	})
	if out, _, err := flat(t, adjacent, FlattenOptions{}); err != nil || string(out) != "AAAABBBB" {
		t.Fatalf("adjacent segments: out=%q err=%v", out, err)
	}
}

// A reader that reports io.EOF together with a full read is legal for
// io.ReaderAt and must not be taken for a failure.
type eofWithData struct{ r *bytes.Reader }

func (e eofWithData) ReadAt(p []byte, off int64) (int, error) {
	n, err := e.r.ReadAt(p, off)
	if err == nil && off+int64(n) == e.r.Size() {
		err = io.EOF
	}
	return n, err
}

func TestFlatten_FullReadWithEOF(t *testing.T) {
	data := []byte("AAAA")
	img := buildELF(elf.EM_ARM, []seg{{Paddr: 0x1000, Off: 0x3fc, Filesz: 4, Memsz: 4, Data: data}})
	out, _, err := Flatten(eofWithData{bytes.NewReader(img)}, int64(len(img)), FlattenOptions{})
	if err != nil || string(out) != "AAAA" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

// --- SREC ---------------------------------------------------------------------

// parseSREC validates each record's checksum and returns the memory image
// (S1, S2 and S3 data records), the S7/S8/S9 entry and the S0 name.
func parseSREC(t *testing.T, b []byte) (mem map[uint32]byte, entry uint32, name string) {
	t.Helper()
	mem = map[uint32]byte{}
	for _, line := range strings.Split(strings.TrimRight(string(b), "\r\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if len(line) < 4 || line[0] != 'S' {
			t.Fatalf("bad SREC line %q", line)
		}
		typ := line[1]
		raw := hexBytes(t, line[2:])
		if int(raw[0])+1 != len(raw) {
			t.Fatalf("SREC count %d vs len %d in %q", raw[0], len(raw), line)
		}
		sum := 0
		for _, x := range raw[:len(raw)-1] {
			sum += int(x)
		}
		if byte(^sum&0xff) != raw[len(raw)-1] {
			t.Fatalf("SREC checksum mismatch in %q", line)
		}
		body := raw[1 : len(raw)-1]
		width := map[byte]int{'0': 2, '1': 2, '2': 3, '3': 4, '5': 2, '6': 3, '7': 4, '8': 3, '9': 2}[typ]
		if width == 0 || len(body) < width {
			t.Fatalf("unexpected SREC record %q", line)
		}
		var a uint32
		for _, x := range body[:width] {
			a = a<<8 | uint32(x)
		}
		payload := body[width:]
		switch typ {
		case '0':
			name = string(payload)
		case '1', '2', '3':
			for i, x := range payload {
				mem[a+uint32(i)] = x
			}
		case '7', '8', '9':
			entry = a
		}
	}
	return
}

func mustSREC(t *testing.T, addr uint32, data []byte, name string, entry uint32, n int) []byte {
	t.Helper()
	out, err := SREC(addr, data, name, entry, n)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSREC_RoundTrip(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	out := mustSREC(t, 0x08000000, in, "hello", 0x08000004, 2) // 2 bytes/line → 3 S3 records
	mem, entry, name := parseSREC(t, out)
	if entry != 0x08000004 || name != "hello" {
		t.Errorf("entry=0x%x name=%q", entry, name)
	}
	if len(mem) != len(in) {
		t.Fatalf("%d bytes decoded, want %d", len(mem), len(in))
	}
	for i, b := range in {
		if mem[0x08000000+uint32(i)] != b {
			t.Errorf("byte %d = 0x%x, want 0x%x", i, mem[0x08000000+uint32(i)], b)
		}
	}
	if n := strings.Count(string(out), "\nS3"); n != 3 {
		t.Errorf("%d S3 records, want 3", n)
	}
}

func TestSREC_DefaultLineLen(t *testing.T) {
	out := mustSREC(t, 0, bytes.Repeat([]byte{0xAB}, 40), "", 0, 0) // dataPerLine<=0 → 16
	mem, _, _ := parseSREC(t, out)
	if len(mem) != 40 {
		t.Errorf("len = %d, want 40", len(mem))
	}
	if n := strings.Count(string(out), "\nS3"); n != 3 {
		t.Errorf("%d S3 records for 40 bytes at 16/line, want 3", n)
	}
}

func TestSREC_Refusals(t *testing.T) {
	// The end of the address space is reachable...
	if out := mustSREC(t, 0xFFFFFFF0, make([]byte, 16), "", 0, 0); len(out) == 0 {
		t.Fatal("empty output")
	}
	// ...one byte further wraps to 0 and used to be written silently.
	if _, err := SREC(0xFFFFFFF0, make([]byte, 17), "", 0, 0); !errors.Is(err, ErrAddrOverflow) {
		t.Errorf("17 bytes at 0xFFFFFFF0: err = %v, want ErrAddrOverflow", err)
	}
	if _, err := SREC(math.MaxUint32, make([]byte, 2), "", 0, 0); !errors.Is(err, ErrAddrOverflow) {
		t.Errorf("2 bytes at 0xFFFFFFFF: err = %v, want ErrAddrOverflow", err)
	}
	if _, err := SREC(0, nil, strings.Repeat("n", 253), 0, 0); !errors.Is(err, ErrFormat) {
		t.Errorf("253-byte name: err = %v, want ErrFormat", err)
	}
	if out := mustSREC(t, 0, nil, strings.Repeat("n", 252), 0, 0); !strings.HasPrefix(string(out), "S0FF0000") {
		t.Errorf("252-byte name: %.12s", out)
	}
	if _, err := SREC(0, []byte{1}, "", 0, 251); !errors.Is(err, ErrFormat) {
		t.Errorf("251 bytes per record: err = %v, want ErrFormat", err)
	}
	if out := mustSREC(t, 0, bytes.Repeat([]byte{1}, 250), "", 0, 250); !strings.Contains(string(out), "\nS3FF") {
		t.Errorf("250 bytes per record not encoded in one S3FF record")
	}
}

// --- IHEX ---------------------------------------------------------------------

func parseIHEX(t *testing.T, b []byte) (out map[uint32]byte, sawEOF bool) {
	t.Helper()
	out = map[uint32]byte{}
	var upper uint32
	for _, line := range strings.Split(strings.TrimRight(string(b), "\r\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		if len(line) < 11 || line[0] != ':' {
			t.Fatalf("bad IHEX line %q", line)
		}
		raw := hexBytes(t, line[1:])
		ll := int(raw[0])
		if len(raw) != ll+5 {
			t.Fatalf("IHEX length mismatch %q", line)
		}
		sum := 0
		for _, x := range raw {
			sum += int(x)
		}
		if sum&0xff != 0 {
			t.Fatalf("IHEX checksum nonzero in %q", line)
		}
		addr := binary.BigEndian.Uint16(raw[1:3])
		payload := raw[4 : 4+ll]
		switch raw[3] {
		case 0x00:
			for i, x := range payload {
				// The 16-bit offset wraps inside the segment: a record that
				// crosses 64 KiB would land at the bottom of it.
				out[upper+uint32(addr+uint16(i))] = x
			}
		case 0x04:
			upper = uint32(binary.BigEndian.Uint16(payload)) << 16
		case 0x01:
			sawEOF = true
		case 0x02: // extended segment address (objcopy's choice): paragraph base
			upper = uint32(binary.BigEndian.Uint16(payload)) << 4
		case 0x03, 0x05: // start addresses: not data
		default:
			t.Fatalf("unexpected IHEX type 0x%02x", raw[3])
		}
	}
	return
}

func mustIHEX(t *testing.T, addr uint32, data []byte, n int) []byte {
	t.Helper()
	out, err := IHEX(addr, data, n)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func checkMem(t *testing.T, mem map[uint32]byte, start uint32, in []byte) {
	t.Helper()
	if len(mem) != len(in) {
		t.Fatalf("%d bytes decoded, want %d", len(mem), len(in))
	}
	for i, b := range in {
		if got, ok := mem[start+uint32(i)]; !ok || got != b {
			t.Fatalf("byte at 0x%x = 0x%x (present %v), want 0x%x", start+uint32(i), got, ok, b)
		}
	}
}

func counting(n int) []byte {
	in := make([]byte, n)
	for i := range in {
		in[i] = byte(i*7 + 1)
	}
	return in
}

func TestIHEX_CrossesLinearBoundary(t *testing.T) {
	// Start just below a 64 KiB boundary so a second type-04 record is needed.
	const start = 0x0001FFF0
	in := counting(64)
	mem, eof := parseIHEX(t, mustIHEX(t, start, in, 16))
	if !eof {
		t.Error("no EOF record")
	}
	checkMem(t, mem, start, in)
}

func TestIHEX_UnalignedRecordDoesNotCrossBoundary(t *testing.T) {
	const start = 0x0001FFFA // 6 bytes below the boundary, 16 per record
	in := counting(40)
	out := mustIHEX(t, start, in, 16)
	mem, _ := parseIHEX(t, out)
	checkMem(t, mem, start, in)
	if !strings.Contains(string(out), ":06FFFA00") {
		t.Errorf("first record not cut at the boundary:\n%s", out)
	}
}

func TestIHEX_LowAddrDefaultLineLen(t *testing.T) {
	in := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	out := mustIHEX(t, 0x10, in, 0) // addr>>16==0 path, default 16/line
	mem, eof := parseIHEX(t, out)
	if !eof {
		t.Error("no EOF")
	}
	checkMem(t, mem, 0x10, in)
	if strings.Contains(string(out), ":02000004") {
		t.Error("a type-04 record for an image in the first 64 KiB")
	}
}

// The upper half 0xFFFF equalled the "unset" marker, so an image in the last
// 64 KiB of the address space was emitted without its type-04 record and a
// loader would have written it at the bottom of memory.
func TestIHEX_TopOfAddressSpaceHasItsExtendedAddress(t *testing.T) {
	const start = 0xFFFF0010
	in := counting(48)
	out := mustIHEX(t, start, in, 16)
	if !strings.HasPrefix(string(out), ":02000004FFFF") {
		t.Fatalf("no type-04 FFFF record first:\n%s", out)
	}
	mem, _ := parseIHEX(t, out)
	checkMem(t, mem, start, in)
}

func TestIHEX_Refusals(t *testing.T) {
	if _, err := IHEX(0xFFFFFFF0, make([]byte, 16), 16); err != nil {
		t.Errorf("16 bytes ending at 4 GiB: %v", err)
	}
	if _, err := IHEX(0xFFFFFFF0, make([]byte, 17), 16); !errors.Is(err, ErrAddrOverflow) {
		t.Errorf("17 bytes at 0xFFFFFFF0: err = %v, want ErrAddrOverflow", err)
	}
	if _, err := IHEX(0, []byte{1}, 256); !errors.Is(err, ErrFormat) {
		t.Errorf("256 per record: err = %v, want ErrFormat", err)
	}
	out := mustIHEX(t, 0, bytes.Repeat([]byte{1}, 255), 255)
	if !strings.HasPrefix(string(out), ":FF0000") {
		t.Errorf("255-byte record: %.12s", out)
	}
}

// --- UImage -------------------------------------------------------------------

func mustUImage(t *testing.T, p []byte, o UImageOptions) []byte {
	t.Helper()
	img, err := UImage(p, o)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestUImage_DefaultsAndCRC(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 100)
	img := mustUImage(t, payload, UImageOptions{Load: 0x80000, Entry: 0x80000, Name: "vmlinuz"})
	if len(img) != 64+len(payload) {
		t.Fatalf("len = %d", len(img))
	}
	h := img[:64]
	if binary.BigEndian.Uint32(h[0:]) != uImageMagic {
		t.Error("bad magic")
	}
	if binary.BigEndian.Uint32(h[12:]) != uint32(len(payload)) {
		t.Error("bad size")
	}
	if binary.BigEndian.Uint32(h[16:]) != 0x80000 || binary.BigEndian.Uint32(h[20:]) != 0x80000 {
		t.Error("bad load/entry")
	}
	if binary.BigEndian.Uint32(h[24:]) != crc32.ChecksumIEEE(payload) {
		t.Error("bad data CRC")
	}
	if h[28] != OSLinux || h[29] != ArchARM || h[30] != TypeKernel || h[31] != CompNone {
		t.Errorf("defaults wrong: os=%d arch=%d type=%d comp=%d", h[28], h[29], h[30], h[31])
	}
	if !bytes.Equal(img[64:], payload) {
		t.Error("payload not appended")
	}
	// Header CRC: recompute over header with the hcrc field zeroed.
	hcrc := binary.BigEndian.Uint32(h[4:])
	check := append([]byte(nil), h...)
	binary.BigEndian.PutUint32(check[4:], 0)
	if crc32.ChecksumIEEE(check) != hcrc {
		t.Error("bad header CRC")
	}
}

func TestUImage_ExplicitFieldsAndNameTruncation(t *testing.T) {
	long := strings.Repeat("x", 40)
	img := mustUImage(t, []byte{1}, UImageOptions{
		OS: OSUBoot, Arch: ArchLoongArch, Type: TypeStandalone, Comp: CompGzip,
		Time: 12345, Name: long,
	})
	h := img[:64]
	if h[28] != OSUBoot || h[29] != ArchLoongArch || h[30] != TypeStandalone || h[31] != CompGzip {
		t.Error("explicit fields not honoured")
	}
	if binary.BigEndian.Uint32(h[8:]) != 12345 {
		t.Error("time not set")
	}
	name := string(bytes.TrimRight(h[32:63], "\x00"))
	if len(name) != 31 || name != long[:31] {
		t.Errorf("name = %q (len %d), want 31-char truncation", name, len(name))
	}
}

// The header's size field is 32 bits. The real bound is 4 GiB - 1, which a
// test cannot allocate (and a 32-bit build cannot even express), so the
// bound is lowered to a few bytes and UImage is driven to its edge.
func TestUImage_RefusesPayloadBeyondTheSizeField(t *testing.T) {
	if maxUImagePayload != math.MaxUint32 {
		t.Fatalf("maxUImagePayload = %d, want the 32-bit field's limit", maxUImagePayload)
	}
	old := maxUImagePayload
	defer func() { maxUImagePayload = old }()
	maxUImagePayload = 10
	if _, err := UImage(make([]byte, 11), UImageOptions{}); !errors.Is(err, ErrFormat) {
		t.Errorf("11 bytes over a 10 byte limit: err = %v, want ErrFormat", err)
	}
	img, err := UImage(make([]byte, 10), UImageOptions{})
	if err != nil || len(img) != 74 {
		t.Errorf("10 bytes at the limit: len=%d err=%v", len(img), err)
	}
}

// The text encoders preallocate; an output an int cannot index is refused
// (ErrTooLarge), which on 32 bits is reached by a 1 GiB input. The bound is
// lowered so every platform drives both sides of it.
func TestTextEncoders_RefuseWhatAnIntCannotIndex(t *testing.T) {
	if maxText != math.MaxInt {
		t.Fatalf("maxText = %d, want math.MaxInt", maxText)
	}
	old := maxText
	defer func() { maxText = old }()
	maxText = 200
	data := make([]byte, 100) // est = 2*100 + (100/16+3)*16 = 344
	if _, err := SREC(0, data, "", 0, 16); !errors.Is(err, ErrTooLarge) {
		t.Errorf("SREC: err = %v, want ErrTooLarge", err)
	}
	if _, err := IHEX(0, data, 16); !errors.Is(err, ErrTooLarge) {
		t.Errorf("IHEX: err = %v, want ErrTooLarge", err)
	}
	if n, err := textSize(10, 16); err != nil || n != 2*10+3*16 {
		t.Errorf("textSize(10,16) = %d, %v; want %d, nil", n, err, 2*10+3*16)
	}
	maxText = uint64(2*10 + 3*16) // exactly at the bound
	if _, err := textSize(10, 16); err != nil {
		t.Errorf("at the bound: err = %v", err)
	}
	maxText--
	if _, err := textSize(10, 16); !errors.Is(err, ErrTooLarge) {
		t.Errorf("one past the bound: err = %v, want ErrTooLarge", err)
	}
}

// --- architecture names -------------------------------------------------------

func TestArchFromName(t *testing.T) {
	for name, want := range map[string]byte{
		"": 0, "arm": ArchARM, "arm64": ArchARM64, "aarch64": ArchARM64,
		"x86_64": ArchX86_64, "amd64": ArchX86_64, "riscv": ArchRISCV,
		"riscv64": ArchRISCV, "loongarch": ArchLoongArch, "loong64": ArchLoongArch,
	} {
		if got, err := ArchFromName(name); err != nil || got != want {
			t.Errorf("ArchFromName(%q) = %d, %v; want %d", name, got, err, want)
		}
	}
	if _, err := ArchFromName("sparc"); err == nil {
		t.Error("sparc accepted")
	}
}

func TestArchFromELF(t *testing.T) {
	for m, want := range map[elf.Machine]byte{
		elf.EM_ARM: ArchARM, elf.EM_AARCH64: ArchARM64, elf.EM_X86_64: ArchX86_64,
		elf.EM_RISCV: ArchRISCV, elf.EM_LOONGARCH: ArchLoongArch, elf.EM_MIPS: 0,
	} {
		if got := ArchFromELF(uint16(m)); got != want {
			t.Errorf("ArchFromELF(%v) = %d, want %d", m, got, want)
		}
	}
}

// --- hex helpers --------------------------------------------------------------

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	if len(s)%2 != 0 {
		t.Fatalf("odd hex %q", s)
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			t.Fatalf("bad hex %q: %v", s, err)
		}
		out[i] = byte(v)
	}
	return out
}

func TestAppendHexHelpers(t *testing.T) {
	if got := string(appendHexByte(nil, 0xAB)); got != "AB" {
		t.Errorf("appendHexByte = %q", got)
	}
	if got := string(appendHex(nil, []byte{0x01, 0xFE})); got != "01FE" {
		t.Errorf("appendHex = %q", got)
	}
}
