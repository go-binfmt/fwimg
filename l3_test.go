package fwimg

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

func sg(addr uint64, s string) Segment { return Segment{Addr: addr, Data: []byte(s)} }

func TestLargestGapAndWarning(t *testing.T) {
	if _, ok := mem().LargestGap(); ok {
		t.Error("an empty image has a hole")
	}
	if _, ok := mem(sg(0x100, "ab")).LargestGap(); ok {
		t.Error("one segment has a hole")
	}
	if _, ok := mem(sg(0x100, "ab"), sg(0x102, "cd")).LargestGap(); ok {
		t.Error("touching segments have a hole")
	}
	im := mem(sg(0x100, "ab"), sg(0x110, "cd"), sg(0x400, "ef"), sg(0x410, "gh"))
	g, ok := im.LargestGap()
	if !ok {
		t.Fatal("no hole found")
	}
	if g.Lo != 0x112 || g.Hi != 0x400 || g.Below != 1 || g.Above != 2 || g.Size() != 0x400-0x112 {
		t.Errorf("largest gap = %+v", g)
	}
	// Ties keep the first hole.
	g, _ = mem(sg(0, "a"), sg(5, "b"), sg(10, "c")).LargestGap()
	if g.Below != 0 {
		t.Errorf("tie: %+v", g)
	}

	big := mem(sg(0, "abcd"), sg(0x20000, "efgh")) // 8 bytes of data, a hole of 0x20000-4
	for _, c := range []struct {
		ratio uint64
		warn  bool
	}{{0, false}, {8, true}, {16383, true}, {16384, false}, {1 << 40, false}} {
		got := big.GapWarning(c.ratio)
		if (got != "") != c.warn {
			t.Errorf("ratio %d: %q", c.ratio, got)
		}
	}
	if w := big.GapWarning(8); !strings.Contains(w, "131076 bytes for 8 bytes of data") || !strings.Contains(w, "131068 bytes of fill") {
		t.Errorf("warning text: %q", w)
	}
	// A hole under 64 KiB is never reported, whatever the ratio; 64 KiB is.
	if w := mem(sg(0, "a"), sg(0xffff, "b")).GapWarning(1); w != "" {
		t.Errorf("hole of 0xfffd: %q", w)
	}
	if w := mem(sg(0, "a"), sg(0x10001, "b")).GapWarning(1); w == "" {
		t.Error("hole of exactly 64 KiB was not reported")
	}
	if w := mem(sg(0, "a")).GapWarning(1); w != "" {
		t.Errorf("no hole: %q", w)
	}
}

// holeELF links a .text at 0x8000000 and a .data whose LMA and VMA are given,
// with the sections objcopy would see.
func holeELF(lma, vma uint64, withSections bool) []byte {
	segs := []elfgen.Seg{
		{Paddr: 0x8000000, Vaddr: 0x8000000, Off: 0x200, Filesz: 16, Memsz: 16, Data: []byte("0123456789abcdef")},
		{Paddr: lma, Vaddr: vma, Off: 0x300, Filesz: 8, Memsz: 0x40, Data: []byte("DATADATA")},
	}
	if !withSections {
		return elfgen.Build(elf.EM_ARM, 0x8000000, segs)
	}
	return elfgen.BuildSections(elf.EM_ARM, 0x8000000, segs, []elfgen.Sec{
		{Name: ".text", Type: 1, Flags: 6, Addr: 0x8000000, Off: 0x200, N: 16},
		{Name: ".data", Type: 1, Flags: 3, Addr: vma, Off: 0x300, N: 8},
		{Name: ".bss", Type: 8, Flags: 3, Addr: vma + 8, Off: 0x308, N: 0x38},
		{Name: ".comment", Type: 1, Flags: 0, Off: 0x200, N: 4},
	})
}

func imageOf(t *testing.T, data []byte, useVaddr bool) *Image {
	t.Helper()
	im, err := ELFImage(data, FlattenOptions{UseVaddr: useVaddr})
	if err != nil {
		t.Fatal(err)
	}
	return im
}

func TestExplainGap(t *testing.T) {
	// .data runs in RAM and is stored in flash: placed by LMA there is no hole,
	// placed by VMA (--use-vaddr) there is one, and by LMA fixes it.
	data := holeELF(0x8001000, 0x20000000, true)
	got := imageOf(t, data, false).ExplainGap(ELFLayout(data, false))
	if !strings.Contains(got, "the largest hole is 0x8000010..0x8001000, 4080 bytes") {
		t.Errorf("by LMA: %q", got)
	}
	got = imageOf(t, data, true).ExplainGap(ELFLayout(data, true))
	for _, want := range []string{
		"the largest hole is 0x8000010..0x20000000, 402653168 bytes, between",
		"below: 0x8000000..0x8000010 (16 bytes): PT_LOAD #0 LMA 0x8000000 VMA 0x8000000; sections .text LMA 0x8000000 VMA 0x8000000",
		"above: 0x20000000..0x20000008 (8 bytes): PT_LOAD #1 LMA 0x8001000 VMA 0x20000000; sections .data LMA 0x8001000 VMA 0x20000000",
		"without --use-vaddr) the span is 4104 bytes",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, ".bss") || strings.Contains(got, ".comment") {
		t.Errorf("a section with no bytes in the file is named:\n%s", got)
	}

	// Load addresses far apart and virtual addresses together: the other way round.
	data = holeELF(0x20000000, 0x8001000, true)
	got = imageOf(t, data, false).ExplainGap(ELFLayout(data, false))
	if !strings.Contains(got, "by virtual address (--use-vaddr) the span is 4104 bytes") {
		t.Errorf("reverse:\n%s", got)
	}

	// LMA = VMA, far apart: neither placement helps; -R names the smaller side.
	data = holeELF(0x20000000, 0x20000000, true)
	got = imageOf(t, data, false).ExplainGap(ELFLayout(data, false))
	if !strings.Contains(got, "AT>") || !strings.HasSuffix(got, "-R .data") {
		t.Errorf("same address:\n%s", got)
	}
	// ... and without section headers it can only say -R SECTION, and the
	// segments are still named.
	data = holeELF(0x20000000, 0x20000000, false)
	got = imageOf(t, data, true).ExplainGap(ELFLayout(data, true))
	if !strings.HasSuffix(got, "-R SECTION") || !strings.Contains(got, "PT_LOAD #1 LMA 0x20000000 VMA 0x20000000") || strings.Contains(got, "sections") {
		t.Errorf("no sections:\n%s", got)
	}
	// The smaller side is the one named: make .text the smaller.
	im := mem(sg(0x8000000, "ab"), sg(0x20000000, "abcdef"))
	got = im.ExplainGap(ELFLayout(holeELF(0x20000000, 0x20000000, true), false))
	if !strings.HasSuffix(got, "-R .text") {
		t.Errorf("smaller side:\n%s", got)
	}

	// Without a layout the addresses are all there is.
	got = imageOf(t, data, true).ExplainGap(nil)
	if !strings.Contains(got, "below: 0x8000000..0x8000010 (16 bytes)\n") || strings.Contains(got, "PT_LOAD") || strings.Contains(got, "-R") {
		t.Errorf("nil layout:\n%s", got)
	}
	if got := mem(sg(0, "a")).ExplainGap(nil); got != "" {
		t.Errorf("no hole: %q", got)
	}
	// A layout of an ELF with no PT_LOAD of its own gives no hint.
	if got := (&Layout{}).hint(0, 1); got != "" {
		t.Errorf("empty layout hint: %q", got)
	}
}

func TestELFLayoutAndDescribe(t *testing.T) {
	func() {
		// A recovered panic is reported as the assertion it stands for.
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ELFLayout of garbage panics: %v", r)
			}
		}()
		if ELFLayout([]byte("not an elf"), false) != nil {
			t.Error("a layout of garbage")
		}
	}()
	var nilLayout *Layout
	if nilLayout.Describe(0, 1<<63) != "" || nilLayout.hint(0, 1) != "" {
		t.Error("a nil layout describes something")
	}
	data := holeELF(0x8001000, 0x20000000, true)
	l := ELFLayout(data, false)
	for _, c := range []struct {
		lo, hi uint64
		want   string
	}{
		{0x8000000, 0x8000001, "PT_LOAD #0 LMA 0x8000000 VMA 0x8000000; sections .text LMA 0x8000000 VMA 0x8000000"},
		{0x8000010, 0x8001000, ""}, // between the two: the hole
		{0x8000fff, 0x8001001, "PT_LOAD #1 LMA 0x8001000 VMA 0x20000000; sections .data LMA 0x8001000 VMA 0x20000000"},
		{0x8001008, 0x9000000, ""}, // one past .data
		{0, 0x8000000, ""},         // one before .text
	} {
		if got := l.Describe(c.lo, c.hi); got != c.want {
			t.Errorf("Describe(%#x, %#x) = %q, want %q", c.lo, c.hi, got, c.want)
		}
	}
	// By VMA the same ELF is described at the virtual addresses.
	if got := ELFLayout(data, true).Describe(0x20000000, 0x20000001); !strings.Contains(got, "PT_LOAD #1") {
		t.Errorf("by VMA: %q", got)
	}
	// A segment whose end would pass 2^64 stops there instead of wrapping.
	if !overlaps(^uint64(0)-1, 100, ^uint64(0)-1, ^uint64(0)) || overlaps(^uint64(0)-1, 100, 0, 5) {
		t.Error("overlaps at the top of the address space")
	}
	// Many sections: eight are named, the rest counted.
	var secs []elfgen.Sec
	for i := 0; i < 11; i++ {
		secs = append(secs, elfgen.Sec{Name: fmt.Sprintf(".s%d", i), Type: 1, Flags: 2, Addr: 0x8000000, Off: 0x200, N: 4})
	}
	many := elfgen.BuildSections(elf.EM_ARM, 0, []elfgen.Seg{{Paddr: 0x8000000, Vaddr: 0x8000000, Off: 0x200, Filesz: 16, Memsz: 16, Data: make([]byte, 16)}}, secs)
	d := ELFLayout(many, false).Describe(0x8000000, 0x8000004)
	if !strings.Contains(d, ".s7 LMA") || strings.Contains(d, ".s8 LMA") || !strings.HasSuffix(d, "and 3 more") {
		t.Errorf("many sections: %q", d)
	}
}

func TestParseRegion(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Region
	}{
		{"FLASH=0x8000000:1M", Region{"FLASH", 0x8000000, 1 << 20}},
		{"RAM=0x20000000:128k", Region{"RAM", 0x20000000, 128 << 10}},
		{"R=4K:2G", Region{"R", 4 << 10, 2 << 30}},
		{"r2=0:64", Region{"r2", 0, 64}},
		{"g=1g:1m", Region{"g", 1 << 30, 1 << 20}},
		{"top=0xfffffffffffffff0:15", Region{"top", 0xfffffffffffffff0, 15}},
	} {
		got, err := ParseRegion(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseRegion(%q) = %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
	if r := (Region{"X", 0x100, 0x20}); r.End() != 0x120 {
		t.Errorf("End = %#x", r.End())
	}
	for _, in := range []string{
		"", "FLASH", "FLASH=1", "FLASH=1:", "FLASH=:1", "=1:2", "a b=1:2", "A=1:2:3",
		"A=zz:2", "A=1:K", "A=1:-2", "A=1:0", "A=1:0K",
		"A=0:18446744073709551615K", // the K overflows
		"A=0xffffffffffffffff:2",    // the region passes 2^64
		"A=0xffffffffffffffff:1",    // ... and one that only reaches it
	} {
		if r, err := ParseRegion(in); !errors.Is(err, ErrFormat) {
			t.Errorf("ParseRegion(%q) = %+v, %v; want ErrFormat", in, r, err)
		}
	}
	rs, err := ParseRegions([]string{"A=0:16", "B=16:16"})
	if err != nil || len(rs) != 2 || rs[1].Name != "B" {
		t.Errorf("ParseRegions = %+v, %v", rs, err)
	}
	if _, err := ParseRegions([]string{"A=0:16", "A=32:16"}); !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a region declared twice: %v", err)
	}
	if _, err := ParseRegions([]string{"A=0:16", "oops"}); !errors.Is(err, ErrFormat) {
		t.Errorf("a bad spec: %v", err)
	}
	if rs, err := ParseRegions(nil); err != nil || len(rs) != 0 {
		t.Errorf("no regions: %+v, %v", rs, err)
	}
}

func TestCheckRegions(t *testing.T) {
	flash := Region{"FLASH", 0x1000, 0x100}
	ram := Region{"RAM", 0x2000, 0x100}
	next := Region{"NEXT", 0x1100, 0x100} // touches FLASH
	none := func(lo, hi uint64) string { return "" }
	named := func(lo, hi uint64) string { return fmt.Sprintf("at %#x", lo) }
	fit := mem(Segment{0x1000, make([]byte, 0x100)}, Segment{0x2010, make([]byte, 0x20)})
	for _, d := range []func(lo, hi uint64) string{nil, none, named} {
		if err := fit.CheckRegions([]Region{flash, ram}, d); err != nil {
			t.Errorf("an image that fits: %v", err)
		}
	}
	if err := mem().CheckRegions(nil, nil); err != nil {
		t.Errorf("empty image: %v", err)
	}

	// One byte over the end of FLASH, ld's words.
	err := mem(Segment{0x1000, make([]byte, 0x101)}).CheckRegions([]Region{flash, ram}, named)
	if !errors.Is(err, ErrRegion) {
		t.Fatalf("overflow: %v", err)
	}
	for _, want := range []string{
		"region `FLASH' overflowed by 1 bytes",
		"segment #0 0x1000..0x1101 (at 0x1000) runs past it to 0x1101",
		"regions: FLASH 0x1000..0x1100, RAM 0x2000..0x2100",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in\n%v", want, err)
		}
	}
	// Outside every region: below, between, above.
	for _, c := range []struct {
		seg  Segment
		want string
	}{
		{Segment{0x800, make([]byte, 0x10)}, "segment #0 0x800..0x810: 16 bytes at 0x800 are outside every declared region"},
		{Segment{0x1800, make([]byte, 0x10)}, "16 bytes at 0x1800 are outside"},
		{Segment{0x3000, make([]byte, 0x10)}, "16 bytes at 0x3000 are outside"},
	} {
		err := mem(c.seg).CheckRegions([]Region{flash, ram}, nil)
		if !errors.Is(err, ErrRegion) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("outside %#x: %v", c.seg.Addr, err)
		}
	}
	// Starting before a region and running into it: the head is outside, once.
	err = mem(Segment{0xff0, make([]byte, 0x20)}).CheckRegions([]Region{flash}, nil)
	if err == nil || !strings.Contains(err.Error(), "16 bytes at 0xff0 are outside") || strings.Count(err.Error(), "bytes at") != 1 {
		t.Errorf("head outside: %v", err)
	}
	// Touching regions hold a segment across them; past the last it overflows
	// the last, and a gap between two regions is outside both.
	if err := mem(Segment{0x1080, make([]byte, 0x100)}).CheckRegions([]Region{next, flash}, nil); err != nil {
		t.Errorf("across touching regions: %v", err)
	}
	err = mem(Segment{0x1080, make([]byte, 0x200)}).CheckRegions([]Region{flash, next}, nil)
	if err == nil || !strings.Contains(err.Error(), "region `NEXT' overflowed by 128 bytes") {
		t.Errorf("past the last of two: %v", err)
	}
	gap := []Region{{"A", 0x1000, 0x10}, {"B", 0x1020, 0x10}}
	err = mem(Segment{0x1008, make([]byte, 0x30)}).CheckRegions(gap, nil)
	if err == nil || !strings.Contains(err.Error(), "region `A' overflowed by 16 bytes") || !strings.Contains(err.Error(), "region `B' overflowed by 8 bytes") {
		t.Errorf("across a gap: %v", err)
	}
	// Every violation is listed up to eight; the rest are counted.
	var segs []Segment
	for i := 0; i < 11; i++ {
		segs = append(segs, Segment{0x5000 + uint64(i)*0x10, make([]byte, 4)})
	}
	err = mem(segs...).CheckRegions([]Region{flash}, nil)
	if err == nil || strings.Count(err.Error(), "are outside") != 8 || !strings.Contains(err.Error(), "and 3 more") {
		t.Errorf("many violations: %v", err)
	}
	// Exactly eight say nothing of the rest.
	err = mem(segs[:8]...).CheckRegions([]Region{flash}, nil)
	if err == nil || strings.Contains(err.Error(), "more") {
		t.Errorf("eight violations: %v", err)
	}
	// A region at the top of the address space does not wrap.
	top := Region{"TOP", 0xffffffffffffff00, 0xff}
	if err := mem(Segment{0xffffffffffffff00, make([]byte, 0xff)}).CheckRegions([]Region{top}, nil); err != nil {
		t.Errorf("top region: %v", err)
	}
	if err := mem(Segment{0x10, make([]byte, 4)}).CheckRegions([]Region{{"WRAP", 0xfffffffffffffff0, 0x20}}, nil); err == nil {
		t.Error("a region that wraps held a low segment")
	}
}

type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func flatOf(t *testing.T, im *Image, pad byte) []byte {
	t.Helper()
	b, _, err := im.Flat(pad, 0)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyFlat(t *testing.T) {
	im := mem(sg(0x1000, "abcd"), sg(0x1010, "efgh"), sg(0x1020, "ij"))
	good := flatOf(t, im, 0xA5)
	if err := VerifyFlat(bytes.NewReader(good), im, 0xA5); err != nil {
		t.Fatalf("the image's own flat file: %v", err)
	}
	if err := VerifyFlat(bytes.NewReader(good), im, 0x00); err == nil || !strings.Contains(err.Error(), "address 0x1004 holds 0xa5, the image has 0x00") {
		t.Errorf("wrong fill: %v", err)
	}
	for i := range good {
		bad := bytes.Clone(good)
		bad[i] ^= 1
		err := VerifyFlat(bytes.NewReader(bad), im, 0xA5)
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), fmt.Sprintf("address 0x%x holds", 0x1000+i)) {
			t.Errorf("byte %d flipped: %v", i, err)
		}
	}
	for n := 0; n < len(good); n++ {
		if err := VerifyFlat(bytes.NewReader(good[:n]), im, 0xA5); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "ends before") {
			t.Errorf("truncated to %d: %v", n, err)
		}
	}
	if err := VerifyFlat(bytes.NewReader(append(bytes.Clone(good), 0)), im, 0xA5); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "longer than the image, which ends at address 0x1022") {
		t.Errorf("one byte too many: %v", err)
	}
	// An empty image is an empty file.
	if err := VerifyFlat(bytes.NewReader(nil), mem(), 0); err != nil {
		t.Errorf("empty: %v", err)
	}
	if err := VerifyFlat(bytes.NewReader([]byte{0}), mem(), 0); !errors.Is(err, ErrVerify) {
		t.Errorf("empty image, a byte: %v", err)
	}
	// A failing read is the reader's error, not a mismatch, in the body and at the end.
	boom := errors.New("boom")
	if err := VerifyFlat(&failingReader{good[:5], boom}, im, 0xA5); err != boom {
		t.Errorf("read error in the body: %v", err)
	}
	if err := VerifyFlat(&failingReader{good, boom}, im, 0xA5); err != boom {
		t.Errorf("read error at the end: %v", err)
	}
	// A file that ends inside a hole, and a reader that fails there.
	holey := mem(sg(0x1000, "ab"), sg(0x1000+2+3*verifyChunk, "c"))
	hfile := flatOf(t, holey, 0x22)
	for _, cut := range []int{3, 2 + verifyChunk, 2 + 2*verifyChunk + 1} {
		if err := VerifyFlat(bytes.NewReader(hfile[:cut]), holey, 0x22); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "ends before") {
			t.Errorf("cut inside the hole at %d: %v", cut, err)
		}
		if err := VerifyFlat(&failingReader{hfile[:cut], boom}, holey, 0x22); err != boom {
			t.Errorf("read error inside the hole at %d: %v", cut, err)
		}
	}
	// Several chunks, and a hole longer than one chunk.
	n := 3*verifyChunk + 123
	body := make([]byte, n)
	for i := range body {
		body[i] = byte(i * 7)
	}
	big := mem(Segment{0x100, body}, Segment{0x100 + uint64(n) + 2*verifyChunk + 5, body[:1000]})
	file := flatOf(t, big, 0x11)
	if err := VerifyFlat(bytes.NewReader(file), big, 0x11); err != nil {
		t.Fatalf("big image: %v", err)
	}
	for _, at := range []int{0, n - 1, n, n + verifyChunk + 1, n + 2*verifyChunk + 4, len(file) - 1} {
		bad := bytes.Clone(file)
		bad[at] ^= 0x80
		err := VerifyFlat(bytes.NewReader(bad), big, 0x11)
		if !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), fmt.Sprintf("address 0x%x holds", 0x100+at)) {
			t.Errorf("big image, byte %d flipped: %v", at, err)
		}
	}
	// A small image does not allocate a chunk bigger than itself.
	if got := testing.AllocsPerRun(1, func() { VerifyFlat(bytes.NewReader(good), im, 0xA5) }); got > 8 {
		t.Errorf("%v allocations", got)
	}
}

func TestCompareImages(t *testing.T) {
	want := &Image{Segments: []Segment{sg(0x10, "abcd"), sg(0x20, "ef")}, Entry: 0x10, HasEntry: true}
	split := &Image{Segments: []Segment{sg(0x10, "ab"), sg(0x12, ""), sg(0x12, "cd"), sg(0x20, "e"), sg(0x21, "f")}, Entry: 0x10, HasEntry: true}
	if err := CompareImages(want, split); err != nil {
		t.Errorf("the same bytes in other segments: %v", err)
	}
	if err := CompareImages(split, want); err != nil {
		t.Errorf("and back: %v", err)
	}
	for _, c := range []struct {
		name string
		got  *Image
		msg  string
	}{
		{"missing tail", &Image{Segments: []Segment{sg(0x10, "abcd")}, Entry: 0x10, HasEntry: true}, "address 0x20 is in the image and not in the output"},
		{"missing middle", &Image{Segments: []Segment{sg(0x10, "ab"), sg(0x20, "ef")}, Entry: 0x10, HasEntry: true}, "address 0x12 is in the image and not in the output"},
		{"nothing", &Image{}, "address 0x10 is in the image and not in the output"},
		{"extra tail", &Image{Segments: []Segment{sg(0x10, "abcd"), sg(0x20, "ef"), sg(0x30, "g")}, Entry: 0x10, HasEntry: true}, "address 0x30 is in the output and not in the image"},
		{"extra before", &Image{Segments: []Segment{sg(0x08, "x"), sg(0x10, "abcd"), sg(0x20, "ef")}, Entry: 0x10, HasEntry: true}, "address 0x8 is in the output and not in the image"},
		{"extra inside", &Image{Segments: []Segment{sg(0x10, "abcd"), sg(0x16, "x"), sg(0x20, "ef")}, Entry: 0x10, HasEntry: true}, "address 0x16 is in the output and not in the image"},
		{"other byte", &Image{Segments: []Segment{sg(0x10, "abXd"), sg(0x20, "ef")}, Entry: 0x10, HasEntry: true}, "address 0x12 holds 0x58, the image has 0x63"},
		{"other byte, last", &Image{Segments: []Segment{sg(0x10, "abcd"), sg(0x20, "eX")}, Entry: 0x10, HasEntry: true}, "address 0x21 holds 0x58, the image has 0x66"},
		{"other start", &Image{Segments: want.Segments, Entry: 0x11, HasEntry: true}, "the start address is 0x11, the image has 0x10"},
		{"no start", &Image{Segments: want.Segments}, "the start address is 0x0, the image has 0x10"},
	} {
		if err := CompareImages(want, c.got); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %v, want %q", c.name, err, c.msg)
		}
	}
	// No start address and a start address of 0 are the same to a text format.
	a := &Image{Segments: want.Segments}
	b := &Image{Segments: want.Segments, HasEntry: true}
	if CompareImages(a, b) != nil || CompareImages(b, a) != nil {
		t.Error("no start and start 0 differ")
	}
	if err := CompareImages(&Image{}, &Image{}); err != nil {
		t.Errorf("two empty images: %v", err)
	}
}

func TestVerifyUImage(t *testing.T) {
	im := mem(sg(0x8000, "abcd"), sg(0x8008, "ef"))
	opts := UImageOptions{Load: 0x8000, Entry: 0x8004, Time: 1700000000, Name: "x"}
	good, err := UImage(flatOf(t, im, 0xA5), opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyUImage(good, im, 0xA5, opts); err != nil {
		t.Fatalf("our own uImage: %v", err)
	}
	for _, c := range []struct {
		name string
		mod  func(UImageOptions) UImageOptions
	}{
		{"load", func(o UImageOptions) UImageOptions { o.Load++; return o }},
		{"entry", func(o UImageOptions) UImageOptions { o.Entry++; return o }},
		{"time", func(o UImageOptions) UImageOptions { o.Time++; return o }},
	} {
		if err := VerifyUImage(good, im, 0xA5, c.mod(opts)); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "the header has load") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	other, _ := UImage(flatOf(t, mem(sg(0x8000, "abXd"), sg(0x8008, "ef")), 0xA5), opts)
	if err := VerifyUImage(other, im, 0xA5, opts); !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "address 0x8002 holds") {
		t.Errorf("other payload: %v", err)
	}
	bad := bytes.Clone(good)
	bad[len(bad)-1] ^= 1
	if err := VerifyUImage(bad, im, 0xA5, opts); !errors.Is(err, ErrVerify) || !errors.Is(err, ErrVerify) || !strings.Contains(err.Error(), "CRC") {
		t.Errorf("a flipped byte: %v", err)
	}
	if err := VerifyUImage([]byte("junk"), im, 0xA5, opts); !errors.Is(err, ErrVerify) {
		t.Errorf("junk: %v", err)
	}
}

func TestParseEpoch(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
	}{{"0", 0}, {"1700000000", 1700000000}, {"4294967295", 4294967295}, {"007", 7}} {
		if got, err := ParseEpoch(c.in); err != nil || got != c.want {
			t.Errorf("ParseEpoch(%q) = %d, %v", c.in, got, err)
		}
	}
	for _, in := range []string{"", " 1", "1 ", "+1", "-1", "1.5", "0x10", "abc", "12abc", "4294967296", "1_0", "99999999999999999999"} {
		if _, err := ParseEpoch(in); !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "SOURCE_DATE_EPOCH") {
			t.Errorf("ParseEpoch(%q): %v", in, err)
		}
	}
}

var _ io.Reader = (*failingReader)(nil)
