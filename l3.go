package fwimg

// L3, the safety lot: the explanation of a giant gap, memory regions, the
// check of what was written, and SOURCE_DATE_EPOCH. docs/spec-notes.md 1.2, 1.3
// and 5.4 are the sources.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/go-binfmt/elfpatch"
)

// Refusals of this lot. Test with errors.Is.
var (
	// ErrRegion: a segment leaves the declared memory regions.
	ErrRegion = errors.New("fwimg: image does not fit the memory regions")
	// ErrVerify: what was written does not read back as the image.
	ErrVerify = errors.New("fwimg: the written output does not match the image")
)

// --- the giant gap ------------------------------------------------------------

// Gap is the largest hole between two neighbouring segments: [Lo, Hi), with the
// indexes of the segment that ends at Lo and the one that starts at Hi.
type Gap struct {
	Lo, Hi       uint64
	Below, Above int
}

// Size is the length of the hole.
func (g Gap) Size() uint64 { return g.Hi - g.Lo }

// LargestGap finds the largest hole between two segments. ok is false when the
// image has no hole (at most one segment, or segments that touch).
func (im *Image) LargestGap() (g Gap, ok bool) {
	for i := 1; i < len(im.Segments); i++ {
		lo, hi := im.Segments[i-1].End(), im.Segments[i].Addr
		if hi-lo > g.Size() {
			g, ok = Gap{Lo: lo, Hi: hi, Below: i - 1, Above: i}, true
		}
	}
	return g, ok
}

// gapWarnMin is the smallest hole GapWarning reports: alignment padding of a
// few kilobytes is not what the warning is for.
const gapWarnMin = 64 << 10

// GapWarning returns a sentence when the flat image of im holds more than ratio
// times its data as filler (a hole of at least 64 KiB), "" otherwise and
// always for a ratio of 0.
func (im *Image) GapWarning(ratio uint64) string {
	data, span := im.Len(), im.Span()
	hole := span - data
	if ratio == 0 || hole < gapWarnMin || (hole-1)/ratio < data {
		return ""
	}
	return fmt.Sprintf("the flat image is %d bytes for %d bytes of data: %d bytes of fill, more than %d times the data", span, data, hole, ratio)
}

// ExplainGap says where the largest hole of im is and what lies on each side of
// it. With the Layout of the ELF the image came from it names the PT_LOAD
// segments and the sections there, with their LMA and VMA, and suggests what
// closes the hole. It is "" for an image without a hole.
func (im *Image) ExplainGap(l *Layout) string {
	g, ok := im.LargestGap()
	if !ok {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "the largest hole is 0x%x..0x%x, %d bytes, between", g.Lo, g.Hi, g.Size())
	side := func(name string, s Segment) {
		fmt.Fprintf(&b, "\n  %s: 0x%x..0x%x (%d bytes)", name, s.Addr, s.End(), len(s.Data))
		if d := l.Describe(s.Addr, s.End()); d != "" {
			b.WriteString(": " + d)
		}
	}
	below, above := im.Segments[g.Below], im.Segments[g.Above]
	side("below", below)
	side("above", above)
	small := below
	if len(above.Data) < len(below.Data) {
		small = above
	}
	if h := l.hint(small.Addr, small.End()); h != "" {
		b.WriteString("\n  " + h)
	}
	return b.String()
}

// Layout is where the PT_LOAD segments and the allocated sections of an ELF
// lie: the load address (LMA) and the virtual address (VMA) of each, and the
// one the image is placed by.
type Layout struct {
	useVaddr bool
	loads    []layoutLoad
	secs     []layoutSec
}

type layoutLoad struct {
	index          int
	vma, lma, size uint64
}
type layoutSec struct {
	name           string
	vma, lma, size uint64
}

// ELFLayout reads the layout of an ELF that Parse accepts, nil for any other
// input. An ELF without section headers has segments only. useVaddr is the
// placement the image used.
func ELFLayout(data []byte, useVaddr bool) *Layout {
	ef, err := elfpatch.Parse(data)
	if err != nil {
		return nil
	}
	l := &Layout{useVaddr: useVaddr}
	progs := ef.Progs()
	for i := range progs {
		if p := &progs[i]; p.Type == ptLoad && p.Filesz > 0 {
			l.loads = append(l.loads, layoutLoad{i, p.Vaddr, p.Paddr, p.Filesz})
		}
	}
	secs, _ := ef.Sections() // none without a table: the segments still speak
	for i := range secs {
		if s := &secs[i]; s.Flags&shfAlloc != 0 && s.Type != shtNobits && s.Type != 0 && s.Size != 0 {
			l.secs = append(l.secs, layoutSec{s.Name, s.Addr, sectionAddr(progs, s, false), s.Size})
		}
	}
	return l
}

func (l *Layout) at(vma, lma uint64) uint64 {
	if l.useVaddr {
		return vma
	}
	return lma
}

// overlaps reports whether [a, a+size) meets [lo, hi); an end past 2^64 stops
// there.
func overlaps(a, size, lo, hi uint64) bool {
	end := uint64(math.MaxUint64)
	if size <= end-a {
		end = a + size
	}
	return a < hi && end > lo
}

// maxNamed bounds the sections one description lists.
const maxNamed = 8

// Describe names the PT_LOAD segments and the sections whose placed bytes meet
// [lo, hi), each with its LMA and VMA. It is "" when none does, and for a nil
// Layout.
func (l *Layout) Describe(lo, hi uint64) string {
	if l == nil {
		return ""
	}
	var parts, names []string
	for _, p := range l.loads {
		if overlaps(l.at(p.vma, p.lma), p.size, lo, hi) {
			parts = append(parts, fmt.Sprintf("PT_LOAD #%d LMA 0x%x VMA 0x%x", p.index, p.lma, p.vma))
		}
	}
	for _, s := range l.secs {
		if overlaps(l.at(s.vma, s.lma), s.size, lo, hi) {
			names = append(names, fmt.Sprintf("%s LMA 0x%x VMA 0x%x", s.name, s.lma, s.vma))
		}
	}
	if len(names) > maxNamed {
		names = append(names[:maxNamed], fmt.Sprintf("and %d more", len(names)-maxNamed))
	}
	if len(names) > 0 {
		parts = append(parts, "sections "+strings.Join(names, ", "))
	}
	return strings.Join(parts, "; ")
}

// spans is the distance from the lowest to the highest byte of the segments
// placed by LMA, and placed by VMA.
func (l *Layout) spans() (byLMA, byVMA uint64) {
	span := func(at func(layoutLoad) uint64) uint64 {
		lo, hi := uint64(math.MaxUint64), uint64(0)
		for _, p := range l.loads {
			lo = min(lo, at(p))
			hi = max(hi, at(p)+min(p.size, math.MaxUint64-at(p)))
		}
		return hi - lo
	}
	return span(func(p layoutLoad) uint64 { return p.lma }), span(func(p layoutLoad) uint64 { return p.vma })
}

// hint says what would close the hole, for the smaller side [lo, hi) of it.
func (l *Layout) hint(lo, hi uint64) string {
	if l == nil || len(l.loads) == 0 {
		return ""
	}
	byLMA, byVMA := l.spans()
	switch {
	case l.useVaddr && byLMA < byVMA:
		return fmt.Sprintf("--use-vaddr places each segment where it runs; by load address (without --use-vaddr) the span is %d bytes, so a section stored next to the code and linked to run elsewhere (.data in RAM) is the cause", byLMA)
	case !l.useVaddr && byVMA < byLMA:
		return fmt.Sprintf("by virtual address (--use-vaddr) the span is %d bytes: the load addresses are far apart and the virtual ones are not", byVMA)
	}
	var names []string
	for _, s := range l.secs {
		if overlaps(l.at(s.vma, s.lma), s.size, lo, hi) {
			names = append(names, "-R "+s.name)
		}
	}
	if len(names) == 0 {
		names = []string{"-R SECTION"}
	}
	return "both addresses agree, so two parts are linked far apart (a .data at its RAM address with no AT> into flash): link the far one AT> next to the rest, or leave it out of the file with " + strings.Join(names, " ")
}

// --- memory regions -----------------------------------------------------------

// Region is a named range of the address space, like an entry of a linker
// script's MEMORY command.
type Region struct {
	Name        string
	Start, Size uint64
}

// End is the address one past the region; ParseRegions refuses one that would
// pass 2^64.
func (r Region) End() uint64 { return r.Start + r.Size }

// ParseRegion reads NAME=START:SIZE. START and SIZE are numbers in decimal or
// 0x-hex, SIZE (and START) with an optional K, M or G suffix for 1024, 1024^2
// and 1024^3.
func ParseRegion(s string) (Region, error) {
	name, rest, ok1 := strings.Cut(s, "=")
	start, size, ok2 := strings.Cut(rest, ":")
	if !ok1 || !ok2 || name == "" || strings.ContainsAny(name, " \t") {
		return Region{}, fmt.Errorf("%w: region %q: want NAME=START:SIZE", ErrFormat, s)
	}
	a, err1 := parseSized(start)
	n, err2 := parseSized(size)
	if err1 != nil || err2 != nil {
		return Region{}, fmt.Errorf("%w: region %q: START and SIZE are numbers (decimal or 0x-hex) with an optional K, M or G", ErrFormat, s)
	}
	if n == 0 || n > math.MaxUint64-a {
		return Region{}, fmt.Errorf("%w: region %q: the size is zero or the region passes 2^64", ErrFormat, s)
	}
	return Region{Name: name, Start: a, Size: n}, nil
}

// parseSized reads a number with an optional K, M or G suffix. No hex digit is
// one of them, so the suffix is unambiguous.
func parseSized(s string) (uint64, error) {
	mult := uint64(1)
	if s != "" {
		if i := strings.IndexByte("kKmMgG", s[len(s)-1]); i >= 0 {
			mult = 1 << (10 * (uint(i)/2 + 1))
			s = s[:len(s)-1]
		}
	}
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint64/mult {
		return 0, strconv.ErrRange
	}
	return v * mult, nil
}

// ParseRegions reads every region and refuses a name given twice.
func ParseRegions(specs []string) ([]Region, error) {
	rs := make([]Region, 0, len(specs))
	for _, s := range specs {
		r, err := ParseRegion(s)
		if err != nil {
			return nil, err
		}
		for _, o := range rs {
			if o.Name == r.Name {
				return nil, fmt.Errorf("%w: region %q is declared twice", ErrFormat, r.Name)
			}
		}
		rs = append(rs, r)
	}
	return rs, nil
}

// maxReported bounds the violations one CheckRegions error lists.
const maxReported = 8

// CheckRegions refuses an image with a byte outside the regions rs (as
// ParseRegions returns them): a segment that runs past the end of the region it
// starts in ("region `X' overflowed by N bytes", ld's words), and a segment that
// starts outside every region. Regions that touch hold a segment across them.
// describe, when it is not nil, adds what lies at the segment, for instance
// Layout.Describe; the error wraps ErrRegion.
func (im *Image) CheckRegions(rs []Region, describe func(lo, hi uint64) string) error {
	var lines []string
	more := 0
	report := func(format string, a ...any) {
		if len(lines) == maxReported {
			more++
			return
		}
		lines = append(lines, fmt.Sprintf(format, a...))
	}
	for i, s := range im.Segments {
		label := fmt.Sprintf("segment #%d 0x%x..0x%x", i, s.Addr, s.End())
		if describe != nil {
			if d := describe(s.Addr, s.End()); d != "" {
				label += " (" + d + ")"
			}
		}
		cur, end := s.Addr, s.End()
		prev := ""
		for cur < end {
			var in *Region
			for k := range rs {
				if rs[k].Start <= cur && cur < rs[k].End() {
					in = &rs[k]
					break
				}
			}
			if in != nil {
				cur, prev = min(end, in.End()), in.Name
				continue
			}
			next := end
			for k := range rs {
				if rs[k].Start > cur && rs[k].Start < next {
					next = rs[k].Start
				}
			}
			if prev != "" {
				report("region `%s' overflowed by %d bytes: %s runs past it to 0x%x", prev, next-cur, label, next)
			} else {
				report("%s: %d bytes at 0x%x are outside every declared region", label, next-cur, cur)
			}
			cur, prev = next, ""
		}
	}
	if len(lines) == 0 {
		return nil
	}
	if more > 0 {
		lines = append(lines, fmt.Sprintf("and %d more", more))
	}
	var names []string
	for _, r := range rs {
		names = append(names, fmt.Sprintf("%s 0x%x..0x%x", r.Name, r.Start, r.End()))
	}
	return fmt.Errorf("%w:\n  %s\n  regions: %s", ErrRegion, strings.Join(lines, "\n  "), strings.Join(names, ", "))
}

// --- verify after write -------------------------------------------------------

// verifyChunk is the buffer VerifyFlat reads the output in.
const verifyChunk = 256 << 10

func mismatch(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrVerify, fmt.Sprintf(format, a...))
}

// VerifyFlat reads a flat binary from r and compares it, byte for byte, with
// what WriteFlat writes for im and pad: the segments at their offsets from the
// lowest address and pad in the gaps, and nothing more. The first difference is
// reported with its address; the error wraps ErrVerify, or is the read error of r.
func VerifyFlat(r io.Reader, im *Image, pad byte) error {
	var buf, fill []byte
	if im.Span() > 0 {
		buf = make([]byte, min(im.Span(), verifyChunk))
	}
	at := im.Base()
	expect := func(want []byte) error {
		for len(want) > 0 {
			got := buf[:min(len(want), len(buf))]
			if _, err := io.ReadFull(r, got); err == io.EOF || err == io.ErrUnexpectedEOF {
				return mismatch("the file ends before address 0x%x", at)
			} else if err != nil {
				return err
			}
			if !bytes.Equal(got, want[:len(got)]) {
				i := 0
				for got[i] == want[i] {
					i++
				}
				return mismatch("address 0x%x holds 0x%02x, the image has 0x%02x", at+uint64(i), got[i], want[i])
			}
			at += uint64(len(got))
			want = want[len(got):]
		}
		return nil
	}
	for _, s := range im.Segments {
		for gap := s.Addr - at; gap > 0; gap = s.Addr - at {
			if fill == nil {
				fill = bytes.Repeat([]byte{pad}, len(buf))
			}
			if err := expect(fill[:min(gap, uint64(len(fill)))]); err != nil {
				return err
			}
		}
		if err := expect(s.Data); err != nil {
			return err
		}
	}
	switch n, err := r.Read(make([]byte, 1)); {
	case n > 0:
		return mismatch("the file is longer than the image, which ends at address 0x%x", at)
	case err != io.EOF:
		return err
	}
	return nil
}

// CompareImages is nil when got holds the same bytes at the same addresses as
// want and the same start address (none counting as 0, which is what a text
// format that cannot say "no start" reads back); adjacent segments are the same
// as one. The first difference is reported by address; the error wraps ErrVerify.
func CompareImages(want, got *Image) error {
	type cursor struct {
		segs []Segment
		i    int
		off  int
	}
	// peek is the address and the bytes at the cursor, skipping empty segments.
	peek := func(c *cursor) (uint64, []byte, bool) {
		for c.i < len(c.segs) && c.off == len(c.segs[c.i].Data) {
			c.i, c.off = c.i+1, 0
		}
		if c.i == len(c.segs) {
			return 0, nil, false
		}
		s := c.segs[c.i]
		return s.Addr + uint64(c.off), s.Data[c.off:], true
	}
	w, g := &cursor{segs: want.Segments}, &cursor{segs: got.Segments}
	for {
		wa, wd, wok := peek(w)
		ga, gd, gok := peek(g)
		switch {
		case !wok && !gok:
			return compareStart(want, got)
		case !gok || wok && wa < ga:
			return mismatch("address 0x%x is in the image and not in the output", wa)
		case !wok || ga < wa:
			return mismatch("address 0x%x is in the output and not in the image", ga)
		}
		n := min(len(wd), len(gd))
		if !bytes.Equal(wd[:n], gd[:n]) {
			i := 0
			for wd[i] == gd[i] {
				i++
			}
			return mismatch("address 0x%x holds 0x%02x, the image has 0x%02x", wa+uint64(i), gd[i], wd[i])
		}
		w.off += n
		g.off += n
	}
}

func compareStart(want, got *Image) error {
	start := func(im *Image) uint64 {
		if im.HasEntry {
			return im.Entry
		}
		return 0
	}
	if a, b := start(want), start(got); a != b {
		return mismatch("the start address is 0x%x, the image has 0x%x", b, a)
	}
	return nil
}

// VerifyUImage reads the uImage in written and compares it with what UImage
// makes of im (flattened with pad) and want: the data is VerifyFlat's, the load
// address, entry point and time are want's. The CRCs are checked on the way.
func VerifyUImage(written []byte, im *Image, pad byte, want UImageOptions) error {
	h, payload, err := ParseUImage(written)
	if err != nil {
		return mismatch("%v", err)
	}
	if h.Load != want.Load || h.Entry != want.Entry || h.Time != want.Time {
		return mismatch("the header has load 0x%x, entry 0x%x, time %d; wanted 0x%x, 0x%x, %d", h.Load, h.Entry, h.Time, want.Load, want.Entry, want.Time)
	}
	return VerifyFlat(bytes.NewReader(payload), im, pad)
}

// --- SOURCE_DATE_EPOCH --------------------------------------------------------

// ParseEpoch reads a SOURCE_DATE_EPOCH value for the uImage time field: decimal
// seconds, 0 to 4294967295. mkimage reads it with strtol and writes 0 for what
// it cannot use (and the low 32 bits of a larger value); a time that is not the
// one asked for is a lie in a header, so this refuses it (ErrFormat).
func ParseEpoch(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("%w: SOURCE_DATE_EPOCH %q is not decimal seconds between 0 and 4294967295", ErrFormat, s)
	}
	return uint32(v), nil
}
