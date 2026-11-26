package fwimg

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"

	"github.com/go-binfmt/elfpatch"
)

// maxFill resolves a size bound: zero is DefaultMaxSize, and nothing above
// the largest int can be allocated.
func maxFill(maxSize uint64) uint64 {
	if maxSize == 0 {
		maxSize = DefaultMaxSize
	}
	return min(maxSize, math.MaxInt)
}

// fillBytes returns n bytes of pad.
func fillBytes(n uint64, pad byte) []byte {
	b := make([]byte, n)
	if pad != 0 {
		for i := range b {
			b[i] = pad
		}
	}
	return b
}

// GapFill extends every segment up to the start of the next one with pad, as
// `objcopy --gap-fill` does: the output then holds the filled gap as data
// (text formats otherwise leave it out). The segments stay separate, since
// objcopy writes its records per section. The bytes added in all may not pass
// maxSize (zero means DefaultMaxSize): a larger fill is refused with
// ErrTooLarge before anything is allocated. The segments must be sorted and
// disjoint, as every constructor in this package makes them.
func (im *Image) GapFill(pad byte, maxSize uint64) error {
	limit := maxFill(maxSize)
	var total uint64
	for i := 0; i+1 < len(im.Segments); i++ {
		if next, end := im.Segments[i+1].Addr, im.Segments[i].End(); next > end {
			total += next - end
			if total > limit {
				return fmt.Errorf("%w: filling the gaps adds more than %d bytes", ErrTooLarge, limit)
			}
		}
	}
	for i := 0; i+1 < len(im.Segments); i++ {
		s := &im.Segments[i]
		if next := im.Segments[i+1].Addr; next > s.End() {
			s.Data = append(slices.Clip(s.Data), fillBytes(next-s.End(), pad)...)
		}
	}
	return nil
}

// PadTo extends the last segment with pad up to addr, as `objcopy --pad-to`
// does. An image that already ends at or past addr, or an empty one, is left
// as it is. The bytes added may not pass maxSize (zero means DefaultMaxSize):
// ErrTooLarge.
func (im *Image) PadTo(addr uint64, pad byte, maxSize uint64) error {
	if len(im.Segments) == 0 {
		return nil
	}
	s := &im.Segments[len(im.Segments)-1]
	end := s.End()
	if end >= addr {
		return nil
	}
	if addr-end > maxFill(maxSize) {
		return fmt.Errorf("%w: padding to 0x%x adds %d bytes, limit %d", ErrTooLarge, addr, addr-end, maxFill(maxSize))
	}
	s.Data = append(slices.Clip(s.Data), fillBytes(addr-end, pad)...)
	return nil
}

// Offset adds delta to the address of every segment, as
// `objcopy --change-addresses` does; the entry address stays where it is. A
// move below 0 or past 2^64 is refused (ErrAddrOverflow) and nothing moves.
func (im *Image) Offset(delta int64) error {
	for _, s := range im.Segments {
		if delta < 0 && s.Addr < uint64(-delta) || delta > 0 && s.End() > math.MaxUint64-uint64(delta) {
			return fmt.Errorf("%w: moving the segment at 0x%x by %d", ErrAddrOverflow, s.Addr, delta)
		}
	}
	for i := range im.Segments {
		im.Segments[i].Addr += uint64(delta)
	}
	return nil
}

// SectionSelect picks sections by name the way objcopy's -j (Only) and -R
// (Remove) do. A pattern is a shell wildcard (* and ?); a leading ! makes it
// negative, and a section a negative pattern matches is never selected,
// whatever the order. A section is kept by Only iff a positive pattern
// matches it, and dropped by Remove iff one does. Giving both is refused:
// objcopy calls the combination undefined.
type SectionSelect struct {
	Only, Remove []string
}

// keep reports whether a section of this name is kept.
func (s SectionSelect) keep(name string) bool {
	if len(s.Only) > 0 {
		return matchSection(s.Only, name)
	}
	return !matchSection(s.Remove, name)
}

// matchSection reports whether some positive pattern matches name and no
// negative one does.
func matchSection(patterns []string, name string) bool {
	found := false
	for _, p := range patterns {
		if neg := len(p) > 0 && p[0] == '!'; neg {
			if wildcard(p[1:], name) {
				return false
			}
		} else if wildcard(p, name) {
			found = true
		}
	}
	return found
}

// wildcard matches name against pattern, where * is any run of bytes and ? is
// any one byte. It runs in time proportional to len(pattern)*len(name) at
// worst, never exponentially.
func wildcard(pattern, name string) bool {
	p, n := 0, 0
	star, mark := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]) && pattern[p] != '*':
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, n
			p++
		case star >= 0:
			mark++
			p, n = star+1, mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

const (
	shfAlloc  = 2 // SHF_ALLOC
	shtNobits = 8 // SHT_NOBITS
)

// ELFImage reads the loadable segments of an ELF executable as an Image: one
// Segment per PT_LOAD that has file content, in address order, placed by load
// address (or by virtual address with opts.UseVaddr), with the ELF entry as
// the start address. Unlike Flatten it keeps the gaps between segments as
// gaps, which is what objcopy's text formats do; Flat lays them out when a
// flat binary is wanted. The same refusals as FlattenBytes apply (ErrRange,
// ErrOverlap, ErrAddrOverflow); opts.Pad is not used here, and opts.MaxSize
// bounds the span, as it does in Flat. The segments are copied out of data.
func ELFImage(data []byte, opts FlattenOptions) (*Image, error) {
	ef, err := elfpatch.Parse(data)
	if errors.Is(err, elfpatch.ErrSegmentRange) {
		return nil, fmt.Errorf("%w: %w", ErrRange, err)
	}
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	addr := func(p *elfpatch.Prog) uint64 {
		if opts.UseVaddr {
			return p.Vaddr
		}
		return p.Paddr
	}
	var loads []*elfpatch.Prog
	progs := ef.Progs()
	for i := range progs {
		if p := &progs[i]; p.Type == ptLoad && p.Filesz > 0 {
			loads = append(loads, p)
		}
	}
	if len(loads) == 0 {
		return nil, fmt.Errorf("no PT_LOAD segments with file content")
	}
	for i, p := range loads {
		// elfpatch.Parse has already refused a segment whose file range
		// leaves the input (ErrSegmentRange, above): only the address span is
		// left to check.
		if p.Filesz > math.MaxUint64-addr(p) {
			return nil, fmt.Errorf("%w: segment %d address 0x%x size 0x%x", ErrAddrOverflow, i, addr(p), p.Filesz)
		}
	}
	sort.SliceStable(loads, func(i, j int) bool { return addr(loads[i]) < addr(loads[j]) })
	im := &Image{Entry: ef.Entry, HasEntry: true, Segments: make([]Segment, len(loads))}
	var end uint64
	for i, p := range loads {
		if i > 0 && addr(p) < end {
			return nil, fmt.Errorf("%w: segment at 0x%x starts before 0x%x", ErrOverlap, addr(p), end)
		}
		end = addr(p) + p.Filesz
		im.Segments[i] = Segment{Addr: addr(p), Data: slices.Clone(data[p.Off : p.Off+p.Filesz])}
	}
	return im, nil
}

// ELFSections reads the loadable sections of an ELF executable that sel keeps
// as an Image, one Segment per section, the way objcopy writes them to a text
// format: the sections that occupy memory (SHF_ALLOC) and bytes in the file
// (not SHT_NOBITS), with a size, sorted by load address. A section's load
// address is its virtual address moved by the offset between the virtual and
// physical address of the segment that holds its bytes (objcopy's LMA), or
// its virtual address with opts.UseVaddr or when no segment holds it. The ELF
// entry is the start address. An ELF without section headers is refused
// (elfpatch.ErrUnsupported), a selection of both Only and Remove
// (ErrFormat), a selection that keeps nothing (ErrNoSections), and sections
// that overlap (ErrOverlap). The bytes are copied out of data.
func ELFSections(data []byte, sel SectionSelect, opts FlattenOptions) (*Image, error) {
	if len(sel.Only) > 0 && len(sel.Remove) > 0 {
		return nil, fmt.Errorf("%w: -j and -R together are undefined", ErrFormat)
	}
	ef, err := elfpatch.Parse(data)
	if errors.Is(err, elfpatch.ErrSegmentRange) {
		return nil, fmt.Errorf("%w: %w", ErrRange, err)
	}
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	secs, err := ef.Sections()
	if err != nil {
		return nil, fmt.Errorf("sections: %w", err)
	}
	progs := ef.Progs()
	type sec struct {
		addr uint64
		data []byte
	}
	var keep []sec
	for _, s := range secs {
		if s.Flags&shfAlloc == 0 || s.Type == shtNobits || s.Type == 0 || s.Size == 0 || !sel.keep(s.Name) {
			continue
		}
		lma := s.Addr
		if !opts.UseVaddr {
			for i := range progs {
				p := &progs[i]
				if p.Type == ptLoad && s.Off >= p.Off && s.Off-p.Off <= p.Filesz && s.Size <= p.Filesz-(s.Off-p.Off) && s.Addr >= p.Vaddr {
					lma = s.Addr - p.Vaddr + p.Paddr
					break
				}
			}
		}
		if s.Size > math.MaxUint64-lma {
			return nil, fmt.Errorf("%w: section %s address 0x%x size 0x%x", ErrAddrOverflow, s.Name, lma, s.Size)
		}
		keep = append(keep, sec{lma, slices.Clone(data[s.Off : s.Off+s.Size])})
	}
	if len(keep) == 0 {
		return nil, ErrNoSections
	}
	sort.SliceStable(keep, func(i, j int) bool { return keep[i].addr < keep[j].addr })
	im := &Image{Entry: ef.Entry, HasEntry: true, Segments: make([]Segment, len(keep))}
	var end uint64
	for i, k := range keep {
		if i > 0 && k.addr < end {
			return nil, fmt.Errorf("%w: section at 0x%x starts before 0x%x", ErrOverlap, k.addr, end)
		}
		end = k.addr + uint64(len(k.data))
		im.Segments[i] = Segment{Addr: k.addr, Data: k.data}
	}
	return im, nil
}

// ErrNoSections reports a section selection that left nothing to write.
var ErrNoSections = errors.New("no loadable section is selected")
