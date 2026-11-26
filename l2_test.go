package fwimg

import (
	"bytes"
	"debug/elf"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/go-binfmt/elfpatch"
	"github.com/go-binfmt/fwimg/internal/elfgen"
)

func TestWildcard(t *testing.T) {
	for _, tc := range []struct {
		pat, name string
		want      bool
	}{
		{"", "", true}, {"", "a", false}, {"a", "", false}, {"a", "a", true}, {"a", "b", false},
		{"*", "", true}, {"*", ".text", true}, {".t*", ".text", true}, {".t*", ".data", false},
		{"*xt", ".text", true}, {"*xt", ".texts", false}, {".?ext", ".text", true}, {".?ext", ".ext", false},
		{"*a*b*", "xxaxxbxx", true}, {"*a*b*", "xxbxxaxx", false}, {"**", "q", true},
		{".text", ".text.x", false}, {"?", "ab", false},
		{"*a", "aaab", false}, {"a*a", "aba", true},
	} {
		if got := wildcard(tc.pat, tc.name); got != tc.want {
			t.Errorf("wildcard(%q, %q) = %v, want %v", tc.pat, tc.name, got, tc.want)
		}
	}
	// No exponential blow-up on the classic bad case.
	if wildcard(strings.Repeat("*a", 40)+"b", strings.Repeat("a", 200)) {
		t.Error("matched")
	}
}

func TestSectionSelect(t *testing.T) {
	for _, tc := range []struct {
		sel  SectionSelect
		name string
		keep bool
	}{
		{SectionSelect{Only: []string{".text"}}, ".text", true},
		{SectionSelect{Only: []string{".text"}}, ".data", false},
		{SectionSelect{Only: []string{".*", "!.data"}}, ".data", false},
		{SectionSelect{Only: []string{"!.data", ".*"}}, ".data", false}, // a negative wins, in either order
		{SectionSelect{Only: []string{"!.data", ".*"}}, ".text", true},
		{SectionSelect{Only: []string{"!.data"}}, ".text", false}, // no positive pattern: nothing is kept
		{SectionSelect{Remove: []string{".data"}}, ".data", false},
		{SectionSelect{Remove: []string{".data"}}, ".text", true},
		{SectionSelect{Remove: []string{".*", "!.text"}}, ".text", true},
		{SectionSelect{Remove: []string{".*", "!.text"}}, ".data", false},
		{SectionSelect{}, ".text", true},
	} {
		if got := tc.sel.keep(tc.name); got != tc.keep {
			t.Errorf("%+v keep(%q) = %v, want %v", tc.sel, tc.name, got, tc.keep)
		}
	}
}

func mem(segs ...Segment) *Image { return &Image{Segments: segs} }

// noPanic runs f and reports a panic as a failed assertion: a refusal that is
// only held by a crash further down is not a test of the refusal.
func noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panicked: %v", what, r)
		}
	}()
	f()
}

func TestGapFillAndPadTo(t *testing.T) {
	im := mem(Segment{0x10, []byte("ab")}, Segment{0x14, []byte("cd")}, Segment{0x16, []byte("ef")})
	if err := im.GapFill(0xff, 0); err != nil {
		t.Fatal(err)
	}
	// The fill is a segment of its own, as objcopy's records are per section.
	if len(im.Segments) != 4 || im.Segments[1].Addr != 0x12 || !bytes.Equal(im.Segments[1].Data, []byte("\xff\xff")) ||
		!bytes.Equal(im.Segments[0].Data, []byte("ab")) || !bytes.Equal(im.Segments[3].Data, []byte("ef")) {
		t.Errorf("GapFill: %+v", im.Segments)
	}
	if err := im.PadTo(0x1a, 0x01, 0); err != nil {
		t.Fatal(err)
	}
	if last := im.Segments[4]; len(im.Segments) != 5 || last.Addr != 0x18 || !bytes.Equal(last.Data, []byte("\x01\x01")) {
		t.Errorf("PadTo: %+v", im.Segments)
	}
	if err := im.PadTo(0x1a, 0x01, 0); err != nil || len(im.Segments) != 5 { // already there
		t.Errorf("PadTo at the end: %v, %d segments", err, len(im.Segments))
	}
	if err := im.PadTo(0x10, 0x01, 0); err != nil || len(im.Segments) != 5 { // below the end: no-op
		t.Errorf("PadTo below: %v", err)
	}
	empty := &Image{}
	var perr error
	noPanic(t, "PadTo on an empty image", func() { perr = empty.PadTo(100, 0, 0) })
	if perr != nil || len(empty.Segments) != 0 {
		t.Errorf("PadTo on an empty image: %v", perr)
	}
	if err := empty.GapFill(0, 0); err != nil {
		t.Error(err)
	}
	// An in-place append must not write into a neighbour's backing array.
	buf := []byte("abXX")
	im = mem(Segment{0, buf[:2]}, Segment{4, []byte("z")})
	if err := im.GapFill(0, 0); err != nil || string(buf) != "abXX" {
		t.Errorf("GapFill wrote into the caller's slice: %q %v", buf, err)
	}
}

func TestGapFillAndPadToBounds(t *testing.T) {
	im := mem(Segment{0, []byte("a")}, Segment{100, []byte("b")}, Segment{300, []byte("c")})
	if err := im.GapFill(0, 150); !errors.Is(err, ErrTooLarge) { // 99 + 199 > 150
		t.Errorf("GapFill: %v", err)
	}
	if len(im.Segments[0].Data) != 1 {
		t.Error("a refused GapFill changed the image")
	}
	if err := im.GapFill(0, 298); err != nil { // exactly 298 bytes of gap
		t.Errorf("GapFill at the bound: %v", err)
	}
	im = mem(Segment{0, []byte("a")})
	if err := im.PadTo(100, 0, 98); !errors.Is(err, ErrTooLarge) { // 99 bytes
		t.Errorf("PadTo: %v", err)
	}
	if err := im.PadTo(100, 0, 99); err != nil || im.Len() != 100 {
		t.Errorf("PadTo at the bound: %v", err)
	}
	if maxFill(0) != DefaultMaxSize || maxFill(math.MaxUint64) != math.MaxInt || maxFill(7) != 7 {
		t.Error("maxFill")
	}
}

func TestOffset(t *testing.T) {
	im := mem(Segment{0x10, []byte("ab")}, Segment{0x20, []byte("c")})
	im.Entry, im.HasEntry = 0x10, true
	if err := im.Offset(0x100); err != nil || im.Segments[0].Addr != 0x110 || im.Segments[1].Addr != 0x120 || im.Entry != 0x10 {
		t.Errorf("up: %v %+v", err, im)
	}
	if err := im.Offset(-0x110); err != nil || im.Segments[0].Addr != 0 || im.Segments[1].Addr != 0x10 {
		t.Errorf("down: %v %+v", err, im)
	}
	if err := im.Offset(-1); !errors.Is(err, ErrAddrOverflow) || im.Segments[0].Addr != 0 { // first segment would go below 0
		t.Errorf("below zero: %v", err)
	}
	top := mem(Segment{math.MaxUint64 - 5, []byte("abcd")})
	if err := top.Offset(1); err != nil { // End() becomes MaxUint64: fits
		t.Errorf("to the top: %v", err)
	}
	if err := top.Offset(1); !errors.Is(err, ErrAddrOverflow) {
		t.Errorf("past the top: %v", err)
	}
	if err := top.Offset(0); err != nil {
		t.Error(err)
	}
}

// sectioned builds an ELF with one segment (vaddr 0x9000, paddr 0x1000, 8 bytes)
// and the sections the objcopy semantics have to sort out.
func sectioned(extra ...elfgen.Sec) []byte {
	segs := []elfgen.Seg{{Paddr: 0x1000, Vaddr: 0x9000, Off: 0x200, Filesz: 8, Memsz: 0x20, Data: []byte("AAAABBBB")}}
	secs := []elfgen.Sec{
		{Name: ".text", Type: 1, Flags: 6, Addr: 0x9000, Off: 0x200, N: 4},
		{Name: ".rodata", Type: 1, Flags: 2, Addr: 0x9004, Off: 0x204, N: 4},
		{Name: ".bss", Type: 8, Flags: 3, Addr: 0x9008, Off: 0x208, N: 0x18},
		{Name: ".comment", Type: 1, Flags: 0, Off: 0x200, N: 4},
		{Name: ".empty", Type: 1, Flags: 2, Addr: 0x9008, Off: 0x208, N: 0},
	}
	return elfgen.BuildSections(elf.EM_ARM, 0x9000, segs, append(secs, extra...))
}

func TestELFSections(t *testing.T) {
	all, err := ELFSections(sectioned(), SectionSelect{Remove: []string{"nothing"}}, FlattenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Segments) != 2 || all.Segments[0].Addr != 0x1000 || string(all.Segments[0].Data) != "AAAA" ||
		all.Segments[1].Addr != 0x1004 || string(all.Segments[1].Data) != "BBBB" || all.Entry != 0x9000 || !all.HasEntry {
		t.Errorf("by load address: %+v", all)
	}
	v, err := ELFSections(sectioned(), SectionSelect{Remove: []string{"nothing"}}, FlattenOptions{UseVaddr: true})
	if err != nil || v.Segments[0].Addr != 0x9000 || v.Segments[1].Addr != 0x9004 {
		t.Errorf("by virtual address: %+v %v", v, err)
	}
	one, err := ELFSections(sectioned(), SectionSelect{Only: []string{".rod*"}}, FlattenOptions{})
	if err != nil || len(one.Segments) != 1 || one.Segments[0].Addr != 0x1004 {
		t.Errorf("-j: %+v %v", one, err)
	}
	rm, err := ELFSections(sectioned(), SectionSelect{Remove: []string{".text"}}, FlattenOptions{})
	if err != nil || len(rm.Segments) != 1 || string(rm.Segments[0].Data) != "BBBB" {
		t.Errorf("-R: %+v %v", rm, err)
	}
	// A section that no segment holds keeps its own address; the result is sorted.
	orphan, err := ELFSections(sectioned(elfgen.Sec{Name: ".orphan", Type: 1, Flags: 2, Addr: 0x500, Off: 0x300, N: 2}),
		SectionSelect{Remove: []string{"nothing"}}, FlattenOptions{})
	if err != nil || orphan.Segments[0].Addr != 0x500 || len(orphan.Segments) != 3 {
		t.Errorf("orphan: %+v %v", orphan, err)
	}
	// A section that starts below the segment's vaddr, or runs past its bytes, is not "in" it.
	below, err := ELFSections(sectioned(elfgen.Sec{Name: ".below", Type: 1, Flags: 2, Addr: 0x8000, Off: 0x200, N: 4}),
		SectionSelect{Only: []string{".below"}}, FlattenOptions{})
	if err != nil || below.Segments[0].Addr != 0x8000 {
		t.Errorf("below: %+v %v", below, err)
	}
	past, err := ELFSections(sectioned(elfgen.Sec{Name: ".past", Type: 1, Flags: 2, Addr: 0x9006, Off: 0x206, N: 4}),
		SectionSelect{Only: []string{".past"}}, FlattenOptions{})
	if err != nil || past.Segments[0].Addr != 0x9006 {
		t.Errorf("past: %+v %v", past, err)
	}
	before, err := ELFSections(sectioned(elfgen.Sec{Name: ".before", Type: 1, Flags: 2, Addr: 0x9000, Off: 0x100, N: 4}),
		SectionSelect{Only: []string{".before"}}, FlattenOptions{})
	if err != nil || before.Segments[0].Addr != 0x9000 {
		t.Errorf("before: %+v %v", before, err)
	}
	fromEnd, err := ELFSections(sectioned(elfgen.Sec{Name: ".end", Type: 1, Flags: 2, Addr: 0x9008, Off: 0x208, N: 1}),
		SectionSelect{Only: []string{".end"}}, FlattenOptions{})
	if err != nil || fromEnd.Segments[0].Addr != 0x9008 {
		t.Errorf("end: %+v %v", fromEnd, err)
	}

	for _, tc := range []struct {
		name string
		img  []byte
		sel  SectionSelect
		is   error
	}{
		{"both", sectioned(), SectionSelect{Only: []string{"a"}, Remove: []string{"b"}}, ErrFormat},
		{"nothing kept", sectioned(), SectionSelect{Only: []string{"nomatch"}}, ErrNoSections},
		{"no section table", elfgen.Build(elf.EM_ARM, 0, []elfgen.Seg{{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}}), SectionSelect{Only: []string{".text"}}, elfpatch.ErrUnsupported},
		{"overlap", sectioned(elfgen.Sec{Name: ".dup", Type: 1, Flags: 2, Addr: 0x9002, Off: 0x202, N: 4}), SectionSelect{Remove: []string{"nothing"}}, ErrOverlap},
		{"wraps", sectioned(elfgen.Sec{Name: ".top", Type: 1, Flags: 2, Addr: math.MaxUint64 - 1, Off: 0x300, N: 4}), SectionSelect{Only: []string{".top"}}, ErrAddrOverflow},
		{"not an ELF", []byte("nope"), SectionSelect{Only: []string{"a"}}, nil},
		{"segment outside", elfgen.Build(elf.EM_ARM, 0, []elfgen.Seg{{Paddr: 0x1000, Off: 0x200, Filesz: 0x10000, Memsz: 4, Data: []byte("A")}}), SectionSelect{Only: []string{"a"}}, ErrRange},
	} {
		var got *Image
		var err error
		noPanic(t, tc.name, func() { got, err = ELFSections(tc.img, tc.sel, FlattenOptions{}) })
		if err == nil || got != nil || tc.is != nil && !errors.Is(err, tc.is) {
			t.Errorf("%s: %v, %v", tc.name, got, err)
		}
		if tc.name == "not an ELF" && !strings.Contains(err.Error(), "parse ELF") {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestELFImage(t *testing.T) {
	segs := []elfgen.Seg{
		{Paddr: 0x2000, Vaddr: 0xa000, Off: 0x300, Filesz: 2, Memsz: 2, Data: []byte("CC")},
		{Paddr: 0x1000, Vaddr: 0x9000, Off: 0x200, Filesz: 4, Memsz: 8, Data: []byte("AAAA")},
		{Paddr: 0x3000, Vaddr: 0xb000, Off: 0x380, Filesz: 0, Memsz: 8}, // .bss only: not emitted
	}
	img := elfgen.Build(elf.EM_ARM, 0x1004, segs)
	im, err := ELFImage(img, FlattenOptions{})
	if err != nil || len(im.Segments) != 2 || im.Segments[0].Addr != 0x1000 || im.Segments[1].Addr != 0x2000 ||
		string(im.Segments[1].Data) != "CC" || im.Entry != 0x1004 || !im.HasEntry {
		t.Fatalf("%+v %v", im, err)
	}
	im.Segments[0].Data[0] = 'X' // a copy: the input is untouched
	if img[0x200] != 'A' {
		t.Error("ELFImage aliases its input")
	}
	v, err := ELFImage(img, FlattenOptions{UseVaddr: true})
	if err != nil || v.Segments[0].Addr != 0x9000 {
		t.Errorf("UseVaddr: %+v %v", v, err)
	}
	for _, tc := range []struct {
		name string
		img  []byte
		is   error
	}{
		{"overlap", elfgen.Build(elf.EM_ARM, 0, []elfgen.Seg{{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}, {Paddr: 0x1002, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")}}), ErrOverlap},
		{"wraps", elfgen.Build(elf.EM_ARM, 0, []elfgen.Seg{{Paddr: math.MaxUint64 - 1, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}}), ErrAddrOverflow},
		{"no content", elfgen.Build(elf.EM_ARM, 0, []elfgen.Seg{{Paddr: 0x1000, Off: 0x200, Filesz: 0, Memsz: 4}}), nil},
		{"outside", elfgen.Build(elf.EM_ARM, 0, []elfgen.Seg{{Paddr: 0x1000, Off: 0x200, Filesz: 0x10000, Memsz: 4, Data: []byte("A")}}), ErrRange},
		{"not an ELF", []byte("nope"), nil},
	} {
		var got *Image
		var err error
		noPanic(t, tc.name, func() { got, err = ELFImage(tc.img, FlattenOptions{}) })
		if err == nil || got != nil || tc.is != nil && !errors.Is(err, tc.is) {
			t.Errorf("%s: %v, %v", tc.name, got, err)
		}
		if tc.name == "not an ELF" && !strings.Contains(err.Error(), "parse ELF") {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// --- encoders -----------------------------------------------------------------

func TestEncodeSRECOpts(t *testing.T) {
	im := &Image{Segments: []Segment{{0x1000, []byte{1, 2, 3, 4}}}, Entry: 0x1002, HasEntry: true}
	for _, bits := range []int{16, 24, 32, 0, SRECAuto} {
		out, err := EncodeSRECOpts(im, SRECOptions{Name: "n", AddrBits: bits})
		if err != nil {
			t.Fatalf("bits %d: %v", bits, err)
		}
		back, err := DecodeSREC(out, DecodeOptions{})
		if err != nil || back.Entry != 0x1002 || len(back.Segments) != 1 || back.Segments[0].Addr != 0x1000 || !bytes.Equal(back.Segments[0].Data, []byte{1, 2, 3, 4}) {
			t.Errorf("bits %d: %v %+v\n%s", bits, err, back, out)
		}
		first := map[int]string{16: "S1", 24: "S2", 32: "S3", 0: "S3", SRECAuto: "S1"}[bits]
		if !strings.Contains(string(out), "\n"+first) {
			t.Errorf("bits %d: no %s record:\n%s", bits, first, out)
		}
		last := map[int]string{16: "S9", 24: "S8", 32: "S7", 0: "S7", SRECAuto: "S9"}[bits]
		if !strings.Contains(string(out), "\n"+last) {
			t.Errorf("bits %d: no %s record:\n%s", bits, last, out)
		}
	}
	// objcopy's choice follows the highest address, written byte included.
	for _, tc := range []struct {
		hi   uint64
		want string
	}{{0xffff, "S1"}, {0x10000, "S2"}, {0xffffff, "S2"}, {0x1000000, "S3"}} {
		out, err := EncodeSRECOpts(&Image{Segments: []Segment{{tc.hi, []byte{9}}}}, SRECOptions{AddrBits: SRECAuto})
		if err != nil || !strings.Contains(string(out), "\n"+tc.want) {
			t.Errorf("auto at 0x%x: %v\n%s", tc.hi, err, out)
		}
	}
	// An empty image is auto-16.
	if out, err := EncodeSRECOpts(&Image{}, SRECOptions{AddrBits: SRECAuto}); err != nil || !strings.Contains(string(out), "S9") {
		t.Errorf("empty: %v %s", err, out)
	}
	// CRLF, and the count record.
	out, err := EncodeSRECOpts(im, SRECOptions{DataPerLine: 2, Count: true, CRLF: true})
	if err != nil || strings.Count(string(out), "\r\n") != 5 || strings.Count(string(out), "\n") != 5 || !strings.Contains(string(out), "\r\nS5030002") {
		t.Errorf("crlf/count: %v\n%q", err, out)
	}
	// S6 above 65535 records.
	big := &Image{Segments: []Segment{{0, make([]byte, 65536)}}}
	out, err = EncodeSRECOpts(big, SRECOptions{DataPerLine: 1, Count: true, AddrBits: 24})
	if err != nil || !strings.Contains(string(out), "\nS604010000") {
		t.Errorf("S6: %v", err)
	}
	if _, err := DecodeSREC(out, DecodeOptions{}); err != nil {
		t.Errorf("S6 does not decode: %v", err)
	}
	old := maxS6
	maxS6 = 70000
	defer func() { maxS6 = old }()
	if _, err := EncodeSRECOpts(&Image{Segments: []Segment{{0, make([]byte, 70001)}}}, SRECOptions{DataPerLine: 1, Count: true, AddrBits: 24}); !errors.Is(err, ErrFormat) {
		t.Errorf("S6 overflow: %v", err)
	}
	maxS6 = old

	for _, tc := range []struct {
		name string
		im   *Image
		o    SRECOptions
		is   error
	}{
		{"per line", im, SRECOptions{DataPerLine: 251}, ErrFormat},
		{"name", im, SRECOptions{Name: strings.Repeat("n", 253)}, ErrFormat},
		{"bits", im, SRECOptions{AddrBits: 8}, ErrFormat},
		{"span 16", &Image{Segments: []Segment{{0xfffe, []byte{1, 2, 3}}}}, SRECOptions{AddrBits: 16}, ErrAddrOverflow},
		{"span 24", &Image{Segments: []Segment{{0xfffffe, []byte{1, 2, 3}}}}, SRECOptions{AddrBits: 24}, ErrAddrOverflow},
		{"span 32", &Image{Segments: []Segment{{0xfffffffe, []byte{1, 2, 3}}}}, SRECOptions{}, ErrAddrOverflow},
		{"entry 16", &Image{Entry: 0x10000, HasEntry: true}, SRECOptions{AddrBits: 16}, ErrAddrOverflow},
		{"entry auto", &Image{Segments: []Segment{{0, []byte{1}}}, Entry: 0x10000, HasEntry: true}, SRECOptions{AddrBits: SRECAuto}, ErrAddrOverflow},
		{"entry 32", &Image{Entry: 1 << 32, HasEntry: true}, SRECOptions{}, ErrAddrOverflow},
	} {
		if out, err := EncodeSRECOpts(tc.im, tc.o); !errors.Is(err, tc.is) || out != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// The full 16-bit space is writable, and the last byte of the 32-bit one too.
	if _, err := EncodeSRECOpts(&Image{Segments: []Segment{{0xfffe, []byte{1, 2}}}}, SRECOptions{AddrBits: 16}); err != nil {
		t.Errorf("up to 64 KiB: %v", err)
	}
	if _, err := EncodeSRECOpts(&Image{Segments: []Segment{{0xfffffffe, []byte{1, 2}}}}, SRECOptions{}); err != nil {
		t.Errorf("up to 4 GiB: %v", err)
	}
	// textSize's refusal is reached through the options too.
	oldText := maxText
	maxText = 10
	defer func() { maxText = oldText }()
	if _, err := EncodeSRECOpts(im, SRECOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("text size: %v", err)
	}
	if _, err := EncodeIHEXOpts(im, IHEXOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("ihex text size: %v", err)
	}
}

func TestEncodeIHEXModes(t *testing.T) {
	im := &Image{Segments: []Segment{
		{0x00fff0, bytes.Repeat([]byte{1}, 0x20)},   // crosses 0x10000 inside the 1 MiB window
		{0x0f0000, []byte{2, 2}},                    // 64 KiB bank 15
		{0x100000, []byte{3, 3}},                    // first byte above 1 MiB
		{0x1fffff0, []byte{4, 4}},                   // far above
		{0x2000010, []byte{5}},                      // same 64 KiB bank as the previous end? no: next bank
		{0xfffffff0, bytes.Repeat([]byte{6}, 0x10)}, // up to 4 GiB
	}, Entry: 0x000a3456, HasEntry: true}
	for _, mode := range []IHEXMode{IHEXLinear, IHEXObjcopy} {
		for _, crlf := range []bool{false, true} {
			out, err := EncodeIHEXOpts(im, IHEXOptions{Mode: mode, CRLF: crlf})
			if err != nil {
				t.Fatal(err)
			}
			if crlf && strings.Count(string(out), "\n") != strings.Count(string(out), "\r\n") || !crlf && strings.Contains(string(out), "\r") {
				t.Errorf("crlf=%v: line endings:\n%q", crlf, out)
			}
			text := strings.ReplaceAll(string(out), "\r\n", "\n")
			mem, eof := parseIHEXBase(t, []byte(text))
			if !eof {
				t.Error("no EOF")
			}
			want := map[uint32]byte{}
			for _, s := range im.Segments {
				for i, b := range s.Data {
					want[uint32(s.Addr)+uint32(i)] = b
				}
			}
			if len(mem) != len(want) {
				t.Fatalf("mode %d: %d bytes decoded, want %d", mode, len(mem), len(want))
			}
			for a, b := range want {
				if mem[a] != b {
					t.Fatalf("mode %d: byte at 0x%x = %d, want %d", mode, a, mem[a], b)
				}
			}
			start := ":04000005000A3456" // type 05
			if mode == IHEXObjcopy {
				start = ":04000003A0003456" // type 03: [(start&0xf0000)>>12, 0, hi, lo]
			}
			if !strings.Contains(text, start) {
				t.Errorf("mode %d: start record %q missing:\n%s", mode, start, text)
			}
		}
	}
	// objcopy mode: 02 records below 1 MiB, 04 above; linear: 04 only.
	lin, _ := EncodeIHEXOpts(im, IHEXOptions{})
	obj, _ := EncodeIHEXOpts(im, IHEXOptions{Mode: IHEXObjcopy})
	if strings.Contains(string(lin), ":02000002") || !strings.Contains(string(lin), ":020000040001") {
		t.Errorf("linear:\n%s", lin)
	}
	if !strings.Contains(string(obj), ":020000020000") || !strings.Contains(string(obj), ":02000002F000") || !strings.Contains(string(obj), ":020000040010") {
		t.Errorf("objcopy:\n%s", obj)
	}
	// A start address above 1 MiB is type 05 in both modes; none (or 0) writes nothing.
	hi := &Image{Entry: 0x200000, HasEntry: true}
	if out, err := EncodeIHEXOpts(hi, IHEXOptions{Mode: IHEXObjcopy}); err != nil || !strings.Contains(string(out), ":0400000500200000") {
		t.Errorf("start above 1 MiB: %v %s", err, out)
	}
	if out, _ := EncodeIHEXOpts(&Image{Entry: 0, HasEntry: true}, IHEXOptions{Mode: IHEXObjcopy}); string(out) != ":00000001FF\n" {
		t.Errorf("zero start: %q", out)
	}
	// Going back to a lower bank after a high one clears the segment base.
	back, err := EncodeIHEXOpts(&Image{Segments: []Segment{{0x20000, []byte{1}}, {0x2000000, []byte{2}}, {0x30000, []byte{3}}}}, IHEXOptions{Mode: IHEXObjcopy})
	if err != nil || !strings.Contains(string(back), ":020000020000") {
		t.Errorf("segment base not cleared: %v\n%s", err, back)
	}
	for _, tc := range []struct {
		name string
		im   *Image
		o    IHEXOptions
	}{
		{"per line", &Image{}, IHEXOptions{DataPerLine: 256}},
		{"mode", &Image{}, IHEXOptions{Mode: 7}},
		{"span", &Image{Segments: []Segment{{0xfffffffe, []byte{1, 2, 3}}}}, IHEXOptions{}},
		{"entry", &Image{Entry: 1 << 32, HasEntry: true}, IHEXOptions{}},
	} {
		if out, err := EncodeIHEXOpts(tc.im, tc.o); err == nil || out != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// parseIHEXBase is parseIHEX for files that use type 02 and type 04 records.
func parseIHEXBase(t *testing.T, b []byte) (map[uint32]byte, bool) {
	t.Helper()
	mem := map[uint32]byte{}
	var base uint32
	eof := false
	hexv := func(s string) []byte {
		out := make([]byte, len(s)/2)
		if !unhex(out, []byte(s)) {
			t.Fatalf("bad hex %q", s)
		}
		return out
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		rec := hexv(line[1:])
		var sum byte
		for _, x := range rec {
			sum += x
		}
		if sum != 0 {
			t.Fatalf("checksum of %q", line)
		}
		n, addr, typ, data := int(rec[0]), uint32(rec[1])<<8|uint32(rec[2]), rec[3], rec[4:len(rec)-1]
		if len(data) != n {
			t.Fatalf("length of %q", line)
		}
		switch typ {
		case 0:
			for i, x := range data {
				mem[base+addr+uint32(i)] = x
			}
		case 1:
			eof = true
		case 2:
			base = (uint32(data[0])<<8 | uint32(data[1])) << 4
		case 4:
			base = (uint32(data[0])<<8 | uint32(data[1])) << 16
		}
	}
	return mem, eof
}
