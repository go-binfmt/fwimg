package fwimg

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"slices"
)

// Segment is a run of bytes loaded at Addr.
type Segment struct {
	Addr uint64
	Data []byte
}

// End is the address one past the last byte of s. It cannot wrap: every
// constructor in this package refuses a segment whose end passes 2^64.
func (s Segment) End() uint64 { return s.Addr + uint64(len(s.Data)) }

// Image is a memory image: sparse segments sorted by address and disjoint
// (adjacent runs are merged), plus the start address the file declared. The
// text decoders (DecodeIHEX, DecodeSREC) and RawImage build one; the text
// encoders (EncodeIHEX, EncodeSREC) and Flat read one.
type Image struct {
	Segments []Segment
	// Entry is the start (execution) address; meaningful only when HasEntry.
	Entry    uint64
	HasEntry bool
	// Name is the S0 header text of an S-record file, or the name field of a
	// uImage; empty when the input has none.
	Name string
	// UImage is the header of the uImage the image was read from, nil for
	// every other source.
	UImage *UImageHeader
}

// Len is the number of data bytes in the image, gaps excluded.
func (im *Image) Len() uint64 {
	var n uint64
	for _, s := range im.Segments {
		n += uint64(len(s.Data))
	}
	return n
}

// Base is the lowest address of the image, 0 for an empty one.
func (im *Image) Base() uint64 {
	if len(im.Segments) == 0 {
		return 0
	}
	return im.Segments[0].Addr
}

// Span is the distance from the lowest to the highest address, gaps included
// (the size of the flat binary).
func (im *Image) Span() uint64 {
	if len(im.Segments) == 0 {
		return 0
	}
	return im.Segments[len(im.Segments)-1].End() - im.Segments[0].Addr
}

// Flat lays the image out as a flat binary, like `objcopy -O binary`: it
// starts at the lowest address and gaps are filled with pad. maxSize bounds
// the span (0 means DefaultMaxSize); a longer image is refused with
// ErrTooLarge before anything is allocated. An image of one segment is
// returned without a copy.
func (im *Image) Flat(pad byte, maxSize uint64) ([]byte, uint64, error) {
	base, err := im.CheckFlat(maxSize)
	if err != nil || len(im.Segments) == 0 {
		return nil, 0, err
	}
	if len(im.Segments) == 1 {
		return im.Segments[0].Data, base, nil
	}
	out := make([]byte, im.Span())
	if pad != 0 {
		for i := range out {
			out[i] = pad
		}
	}
	for _, s := range im.Segments {
		copy(out[s.Addr-base:], s.Data)
	}
	return out, base, nil
}

// CheckFlat is the size check Flat and WriteFlat make before they do anything:
// it returns the base address, or ErrTooLarge when the span passes maxSize (0
// means DefaultMaxSize). A command that creates its output file calls it first,
// so that a refusal leaves no file behind.
func (im *Image) CheckFlat(maxSize uint64) (uint64, error) {
	if len(im.Segments) == 0 {
		return 0, nil
	}
	limit := maxSize
	if limit == 0 {
		limit = DefaultMaxSize
	}
	if limit > math.MaxInt {
		limit = math.MaxInt
	}
	base := im.Base()
	if span := im.Span(); span > limit {
		return 0, fmt.Errorf("%w: 0x%x..0x%x is %d bytes, limit %d", ErrTooLarge, base, base+span, span, limit)
	}
	return base, nil
}

// flatChunk is the buffer WriteFlat coalesces small pieces in; a piece at least
// that long goes to the writer as it is.
const flatChunk = 64 << 10

// WriteFlat writes what Flat would return to w without building it: each
// segment goes to w straight from its own bytes, and a gap is written from one
// small block of pad. No copy of the image is made, and a flat binary of
// several segments costs the writer one pass instead of an assembled buffer
// plus one. It makes the CheckFlat refusal itself.
func (im *Image) WriteFlat(w io.Writer, pad byte, maxSize uint64) (uint64, error) {
	base, err := im.CheckFlat(maxSize)
	if err != nil || len(im.Segments) == 0 {
		return 0, err
	}
	if len(im.Segments) == 1 {
		_, err := w.Write(im.Segments[0].Data)
		return base, err
	}
	bw := bufio.NewWriterSize(w, int(min(im.Span(), flatChunk)))
	var fill []byte // the gap block, made when the first gap needs it
	at := base
	for _, s := range im.Segments {
		for gap := s.Addr - at; gap > 0; {
			if fill == nil {
				fill = bytes.Repeat([]byte{pad}, int(min(im.Span(), flatChunk)))
			}
			n := int(min(gap, uint64(len(fill))))
			if _, err := bw.Write(fill[:n]); err != nil {
				return 0, err
			}
			gap -= uint64(n)
		}
		if _, err := bw.Write(s.Data); err != nil {
			return 0, err
		}
		at = s.End()
	}
	return base, bw.Flush()
}

// Shift moves every segment so that the lowest byte is at base; the entry
// address stays where it is. A shift that would pass 2^64 is refused
// (ErrAddrOverflow).
func (im *Image) Shift(base uint64) error {
	if len(im.Segments) == 0 {
		return nil
	}
	old := im.Base()
	if base > old && base-old > math.MaxUint64-im.Segments[len(im.Segments)-1].End() {
		return fmt.Errorf("%w: moving the image to 0x%x", ErrAddrOverflow, base)
	}
	for i := range im.Segments {
		im.Segments[i].Addr = im.Segments[i].Addr - old + base
	}
	return nil
}

// RawImage is the image of a raw binary loaded at base: `objcopy -I binary`
// needs the address given the same way, and nothing here guesses it. The
// bytes are used as they are, not copied. An empty input is an empty image;
// an address range past 2^64 is refused (ErrAddrOverflow).
func RawImage(data []byte, base uint64) (*Image, error) {
	if len(data) == 0 {
		return &Image{}, nil
	}
	if uint64(len(data)) > math.MaxUint64-base {
		return nil, fmt.Errorf("%w: %d bytes at 0x%x", ErrAddrOverflow, len(data), base)
	}
	return &Image{Segments: []Segment{{Addr: base, Data: data}}}, nil
}

// Input format names, as Detect returns them and the CLI's -I takes them.
const (
	FormatELF    = "elf"
	FormatIHEX   = "ihex"
	FormatSREC   = "srec"
	FormatUImage = "uimage"
	// FormatBinary is never detected: a raw file has no magic, and guessing
	// would turn any file into a firmware image.
	FormatBinary = "binary"
)

// Detect names the format of data from its magic bytes or syntax, or returns
// "" when it is none of ELF (\x7fELF), uImage (0x27051956 first), Intel HEX
// (first non-blank byte ':') or S-record (first non-blank byte 'S' and a
// digit). It never returns FormatBinary.
func Detect(data []byte) string {
	if len(data) >= 4 && string(data[:4]) == "\x7fELF" {
		return FormatELF
	}
	if len(data) >= 4 && data[0] == 0x27 && data[1] == 0x05 && data[2] == 0x19 && data[3] == 0x56 {
		return FormatUImage
	}
	i := 0
	for i < len(data) && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n') {
		i++
	}
	if i < len(data) && data[i] == ':' {
		return FormatIHEX
	}
	if i+1 < len(data) && data[i] == 'S' && data[i+1] >= '0' && data[i+1] <= '9' {
		return FormatSREC
	}
	return ""
}

// collector gathers the pieces a text decoder reads and turns them into an
// Image. Bytes go into one buffer in arrival order; a piece that continues the
// previous one extends it. The budget counts the data bytes plus 16 bytes per
// piece, so neither a big file nor a file of one-byte records at alternating
// addresses can ask for more than the limit.
type collector struct {
	limit  uint64
	spent  uint64
	buf    []byte
	pieces []piece
}

type piece struct {
	addr uint64
	off  int
	n    int
}

const pieceCost = 16

func newCollector(limit uint64) *collector {
	if limit == 0 {
		limit = DefaultMaxSize
	}
	if limit > math.MaxInt32 {
		limit = math.MaxInt32
	}
	return &collector{limit: limit}
}

// add records data at addr. The caller has checked addr+len(data) <= 2^32.
func (c *collector) add(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	cost := uint64(len(data))
	last := len(c.pieces) - 1
	extend := last >= 0 && c.pieces[last].addr+uint64(c.pieces[last].n) == addr
	if !extend {
		cost += pieceCost
	}
	if cost > c.limit-c.spent {
		return fmt.Errorf("%w: the file holds more than %d bytes of data", ErrTooLarge, c.limit)
	}
	c.spent += cost
	if extend {
		c.pieces[last].n += len(data)
	} else {
		c.pieces = append(c.pieces, piece{addr: addr, off: len(c.buf), n: len(data)})
	}
	c.buf = append(c.buf, data...)
	return nil
}

// image sorts the pieces, refuses overlaps (ErrOverlap) and merges
// neighbours into segments.
func (c *collector) image() (*Image, error) {
	sorted := slices.IsSortedFunc(c.pieces, func(a, b piece) int { return cmpU64(a.addr, b.addr) })
	pieces := c.pieces
	if !sorted {
		pieces = slices.Clone(pieces)
		slices.SortFunc(pieces, func(a, b piece) int { return cmpU64(a.addr, b.addr) })
	}
	for i := 1; i < len(pieces); i++ {
		if end := pieces[i-1].addr + uint64(pieces[i-1].n); pieces[i].addr < end {
			return nil, fmt.Errorf("%w: data at 0x%x starts before 0x%x", ErrOverlap, pieces[i].addr, end)
		}
	}
	data := c.buf
	if !sorted {
		// Arrival order is not address order: lay the bytes out in address
		// order, once.
		data = make([]byte, 0, len(c.buf))
		for i := range pieces {
			p := &pieces[i]
			from := p.off
			p.off = len(data)
			data = append(data, c.buf[from:from+p.n]...)
		}
	}
	// Merge neighbours: runs that touch in address are adjacent in data too
	// (both orders are address order), so a segment is one span of data.
	var runs []piece
	for _, p := range pieces {
		if n := len(runs); n > 0 && runs[n-1].addr+uint64(runs[n-1].n) == p.addr {
			runs[n-1].n += p.n
			continue
		}
		runs = append(runs, p)
	}
	im := &Image{Segments: make([]Segment, len(runs))}
	for i, p := range runs {
		im.Segments[i] = Segment{Addr: p.addr, Data: data[p.off : p.off+p.n : p.off+p.n]}
	}
	return im, nil
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// unhex decodes the hex digits of s into dst (len(dst) == len(s)/2) and
// reports whether s was all hex digits, upper or lower case.
func unhex(dst, s []byte) bool {
	for i := range dst {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return false
		}
		dst[i] = hi<<4 | lo
	}
	return true
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// nextLine returns the next line of text without its terminator ("\n" or
// "\r\n") and the rest, and skips blank lines. ok is false at the end.
func nextLine(text []byte) (line, rest []byte, n int, ok bool) {
	for len(text) > 0 {
		i := 0
		for i < len(text) && text[i] != '\n' {
			i++
		}
		line = text[:i]
		if i < len(text) {
			i++
		}
		text = text[i:]
		n++
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) > 0 {
			return line, text, n, true
		}
	}
	return nil, nil, n, false
}
