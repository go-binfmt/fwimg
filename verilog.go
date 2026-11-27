package fwimg

import (
	"fmt"
	"math"
)

// Verilog hex memory files, as `objcopy -O verilog` writes them (bfd/verilog.c,
// docs/spec-notes.md 4): one "@ADDR" line per contiguous run, ADDR being the
// byte address divided by the data width, then lines of at most 16 bytes.
// The oracle is objcopy, quirks included: with a width above 1 and big-endian
// data a complete word is followed by a space even at the end of the line.

// VerilogOptions controls EncodeVerilog and DecodeVerilog.
type VerilogOptions struct {
	// DataWidth is the word size in bytes, 1 to 8 as objcopy accepts
	// (--verilog-data-width). Zero means 1.
	DataWidth int
	// BigEndian writes the bytes of a word in memory order; the default writes
	// them last first (VerilogDataEndianness = little, what objcopy uses for a
	// little-endian ELF).
	BigEndian bool
}

func (o VerilogOptions) width() (int, error) {
	switch w := o.DataWidth; {
	case w == 0:
		return 1, nil
	case w < 0 || w > 8:
		return 0, fmt.Errorf("%w: verilog data width %d, want 1 to 8 bytes", ErrFormat, w)
	default:
		return w, nil
	}
}

// verilogLine is the number of data bytes in a line, as in verilog_write_section.
const verilogLine = 16

// EncodeVerilog writes the segments of im in address order, as objcopy writes
// the sections of an ELF: each is one "@ADDR" line (8 hex digits, 16 when the
// address divided by the width is 2^32 or more) and its lines of 16 bytes, all
// ended by CR LF. A segment whose address is not a multiple of the width is
// refused (ErrFormat), as objcopy refuses it with bfd_error_invalid_operation.
// Where objcopy writes one record per section, this writes one per segment: two
// sections that touch are one segment here.
func EncodeVerilog(im *Image, opts VerilogOptions) ([]byte, error) {
	w, err := opts.width()
	if err != nil {
		return nil, err
	}
	var est uint64
	for _, s := range im.Segments {
		if s.Addr%uint64(w) != 0 && len(s.Data) > 0 {
			return nil, fmt.Errorf("%w: verilog segment at 0x%x is not a multiple of the data width %d", ErrFormat, s.Addr, w)
		}
		est += 20 + uint64(len(s.Data))*3 + (uint64(len(s.Data))/verilogLine+1)*2
		if est > maxText {
			return nil, fmt.Errorf("%w: %d data bytes encode to more than %d bytes of Verilog", ErrTooLarge, im.Len(), maxText)
		}
	}
	out := make([]byte, 0, est)
	for _, s := range im.Segments {
		if len(s.Data) == 0 {
			continue
		}
		out = append(out, '@')
		a := s.Addr / uint64(w)
		if a >= 1<<32 {
			out = appendHexByte(appendHexByte(appendHexByte(appendHexByte(out, byte(a>>56)), byte(a>>48)), byte(a>>40)), byte(a>>32))
		}
		out = appendHexByte(appendHexByte(appendHexByte(appendHexByte(out, byte(a>>24)), byte(a>>16)), byte(a>>8)), byte(a))
		out = append(out, '\r', '\n')
		for data := s.Data; len(data) > 0; {
			n := min(len(data), verilogLine)
			out = appendVerilogLine(out, data[:n], w, opts.BigEndian)
			out = append(out, '\r', '\n')
			data = data[n:]
		}
	}
	return out, nil
}

// appendVerilogLine is verilog_write_record. For w > 1 and little-endian data
// the loop stops at "src < end - width", so the last word, complete or not, is
// written by the tail code: reversed, with no space after it.
func appendVerilogLine(out, line []byte, w int, big bool) []byte {
	switch {
	case w == 1:
		for i, b := range line {
			if i > 0 {
				out = append(out, ' ')
			}
			out = appendHexByte(out, b)
		}
	case !big:
		src := 0
		for ; src < len(line)-w; src += w {
			for i := w - 1; i >= 0; i-- {
				out = appendHexByte(out, line[src+i])
			}
			out = append(out, ' ')
		}
		for end := len(line); end > src; {
			end--
			out = appendHexByte(out, line[end])
		}
	default:
		for i, b := range line {
			out = appendHexByte(out, b)
			if (i+1)%w == 0 {
				out = append(out, ' ') // objcopy's FIXME: also at the end of the line
			}
		}
	}
	return out
}

// DecodeVerilog reads a Verilog hex memory file: tokens separated by white
// space, // and /* */ comments, "@ADDR" tokens that set the address in words
// (the byte address is ADDR times the data width), and data tokens of 2 to
// 2*width hex digits, each a word of the data width (or its tail) whose bytes
// are in memory order for big-endian data and last-first otherwise. Underscores
// inside a token are ignored, as the IEEE standard allows. Data before the
// first address starts at address 0. Digits other than hex (x and z) are
// refused. The start address is not recorded: the format has none.
//
// Refusals: ErrSyntax (a bad token, an unterminated comment), ErrAddrOverflow
// (a byte address past 2^64), ErrOverlap (two tokens write one address),
// ErrTooLarge (more data than opts.MaxSize), ErrFormat (a bad data width).
func DecodeVerilog(text []byte, vo VerilogOptions, opts DecodeOptions) (*Image, error) {
	w, err := vo.width()
	if err != nil {
		return nil, err
	}
	c := newCollector(opts.MaxSize)
	var (
		addr   uint64
		word   [8]byte
		digits [16]byte
		line   = 1
	)
	for i := 0; i < len(text); {
		switch b := text[i]; {
		case b == '\n':
			line++
			i++
		case b == ' ' || b == '\t' || b == '\r' || b == '\f' || b == '\v':
			i++
		case b == '/' && i+1 < len(text) && text[i+1] == '/':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		case b == '/' && i+1 < len(text) && text[i+1] == '*':
			end := i + 2
			for end+1 < len(text) && !(text[end] == '*' && text[end+1] == '/') {
				if text[end] == '\n' {
					line++
				}
				end++
			}
			if end+1 >= len(text) {
				return nil, fmt.Errorf("verilog line %d: %w: unterminated comment", line, ErrSyntax)
			}
			i = end + 2
		default:
			j := i
			for j < len(text) && !isVerilogSpace(text[j]) && !(text[j] == '/' && j+1 < len(text) && (text[j+1] == '/' || text[j+1] == '*')) {
				j++
			}
			tok := text[i:j]
			i = j
			fail := func(why string) error { return fmt.Errorf("verilog line %d: %w: %s", line, ErrSyntax, why) }
			isAddr := tok[0] == '@'
			if isAddr {
				tok = tok[1:]
			}
			n := 0
			for _, ch := range tok {
				if ch == '_' {
					continue
				}
				if _, ok := hexVal(ch); !ok {
					return nil, fail(fmt.Sprintf("%q is not a hex digit", ch))
				}
				if isAddr && n == 16 || !isAddr && n == len(digits) {
					return nil, fail("token too long")
				}
				digits[n] = ch
				n++
			}
			switch {
			case n == 0:
				return nil, fail("empty token")
			case isAddr:
				var a uint64
				for _, ch := range digits[:n] {
					v, _ := hexVal(ch)
					a = a<<4 | uint64(v)
				}
				if a > math.MaxUint64/uint64(w) {
					return nil, fmt.Errorf("verilog line %d: %w: word address 0x%x", line, ErrAddrOverflow, a)
				}
				addr = a * uint64(w)
			default:
				if n%2 != 0 || n > 2*w {
					return nil, fail(fmt.Sprintf("a data token of %d digits is not 1 to %d whole bytes", n, w))
				}
				k := n / 2
				if !unhex(word[:k], digits[:n]) {
					return nil, fail("not a hex digit")
				}
				if !vo.BigEndian {
					for l, r := 0, k-1; l < r; l, r = l+1, r-1 {
						word[l], word[r] = word[r], word[l]
					}
				}
				if uint64(k) > math.MaxUint64-addr {
					return nil, fmt.Errorf("verilog line %d: %w: %d bytes at 0x%x", line, ErrAddrOverflow, k, addr)
				}
				if err := c.add(addr, word[:k]); err != nil {
					return nil, err
				}
				addr += uint64(k)
			}
		}
	}
	return c.image()
}

func isVerilogSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' || b == '\v'
}
