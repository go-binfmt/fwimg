package fwimg

import (
	"errors"
	"fmt"
)

// Refusals of the decoders, in addition to those in fwimg.go.
var (
	// ErrSyntax: the input is not well-formed for its format (a bad record,
	// a missing end record, a record after the end).
	ErrSyntax = errors.New("fwimg: malformed input")
	// ErrChecksum: a record checksum, or a uImage CRC, does not match.
	ErrChecksum = errors.New("fwimg: checksum mismatch")
	// ErrUnknownFormat: the input is none of the formats Detect knows.
	ErrUnknownFormat = errors.New("fwimg: input is not ELF, Intel HEX, S-record, uImage, UF2 or Verilog hex")
)

// DecodeOptions bounds a decoder.
type DecodeOptions struct {
	// MaxSize bounds the decoded data, in bytes, plus 16 bytes of bookkeeping
	// for every run of data that does not continue the previous one. Zero
	// means DefaultMaxSize; the bound is capped at 2 GiB - 1. A file that
	// holds more is refused with ErrTooLarge.
	MaxSize uint64
}

// DecodeIHEX reads an Intel HEX file into an Image: types 00 to 05, upper or
// lower case digits, LF or CRLF line ends, blank lines ignored.
//
// Every record's length, checksum and type is checked, and so is the file as a
// whole: it must end with a type-01 record and nothing may follow it
// (ErrSyntax, ErrChecksum). Addresses follow [intel5] (docs/spec-notes.md
// 2.1): before any base record, and after a type-04 record, an address is
// base+offset and a record that crosses a 64 KiB boundary continues in the
// next one; after a type-02 record the address wraps inside the 64 KiB
// segment. A byte above 4 GiB is refused (ErrAddrOverflow), and so are two
// records that write the same address (ErrOverlap) or a second start record
// (ErrSyntax). The start address is the type-05 value, or CS*16+IP of a
// type-03 record.
func DecodeIHEX(text []byte, opts DecodeOptions) (*Image, error) {
	c := newCollector(opts.MaxSize)
	var (
		rec      [5 + 255]byte
		base     uint64
		segMode  bool
		sawEOF   bool
		entry    uint64
		hasEntry bool
		lineNo   int
	)
	for rest := text; ; {
		line, r, n, ok := nextLine(rest)
		lineNo += n
		if !ok {
			break
		}
		rest = r
		fail := func(why string) error { return fmt.Errorf("ihex line %d: %w: %s", lineNo, ErrSyntax, why) }
		if sawEOF {
			return nil, fail("record after the end-of-file record")
		}
		if line[0] != ':' {
			return nil, fail("record does not start with ':'")
		}
		body := line[1:]
		k := len(body) / 2
		if len(body)%2 != 0 || k < 5 || k > len(rec) {
			return nil, fail("bad record length")
		}
		if !unhex(rec[:k], body) {
			return nil, fail("not a hex digit")
		}
		if int(rec[0])+5 != k {
			return nil, fail("byte count does not match the record length")
		}
		var sum byte
		for _, b := range rec[:k] {
			sum += b
		}
		if sum != 0 {
			return nil, fmt.Errorf("ihex line %d: %w", lineNo, ErrChecksum)
		}
		off := uint64(rec[1])<<8 | uint64(rec[2])
		data := rec[4 : 4+int(rec[0])]
		switch typ := rec[3]; typ {
		case 0x00:
			var err error
			if segMode {
				// The address wraps inside the 64 KiB segment.
				first := min(len(data), int(0x10000-off))
				if err = c.add(base+off, data[:first]); err == nil {
					err = c.add(base, data[first:])
				}
			} else {
				if base+off+uint64(len(data)) > 1<<32 {
					return nil, fmt.Errorf("ihex line %d: %w: %d bytes at 0x%x", lineNo, ErrAddrOverflow, len(data), base+off)
				}
				err = c.add(base+off, data)
			}
			if err != nil {
				return nil, err
			}
		case 0x01:
			if len(data) != 0 {
				return nil, fail("end-of-file record with data")
			}
			sawEOF = true
		case 0x02, 0x04:
			if len(data) != 2 {
				return nil, fail("extended address record is not 2 bytes")
			}
			v := uint64(data[0])<<8 | uint64(data[1])
			if typ == 0x02 {
				base, segMode = v<<4, true
			} else {
				base, segMode = v<<16, false
			}
		case 0x03, 0x05:
			if len(data) != 4 {
				return nil, fail("start address record is not 4 bytes")
			}
			if hasEntry {
				return nil, fail("second start address record")
			}
			hasEntry = true
			if typ == 0x05 {
				entry = uint64(data[0])<<24 | uint64(data[1])<<16 | uint64(data[2])<<8 | uint64(data[3])
			} else {
				entry = (uint64(data[0])<<8|uint64(data[1]))<<4 + (uint64(data[2])<<8 | uint64(data[3]))
			}
		default:
			return nil, fail(fmt.Sprintf("unknown record type %02X", typ))
		}
	}
	if !sawEOF {
		return nil, fmt.Errorf("ihex: %w: no end-of-file record", ErrSyntax)
	}
	im, err := c.image()
	if err != nil {
		return nil, err
	}
	im.Entry, im.HasEntry = entry, hasEntry
	return im, nil
}

// srecAddrLen is the address field size of each S-record type, 0 for the
// types that do not exist (S4).
var srecAddrLen = [10]int{2, 2, 3, 4, 0, 2, 3, 4, 3, 2}

// DecodeSREC reads a Motorola S-record file into an Image: S0 (the header,
// kept as Image.Name), S1 to S3, S5 and S6 (the count of data records, which
// must equal the number read so far), S7 to S9 (the termination, whose
// address is the start). Upper or lower case digits, LF or CRLF line ends,
// blank lines ignored.
//
// Every checksum is verified (ErrChecksum). The file must end with an S7, S8
// or S9 record and nothing may follow it; an S0 may only come first
// (ErrSyntax). A data record that runs past 4 GiB is refused
// (ErrAddrOverflow), and so are two records that write the same address
// (ErrOverlap).
func DecodeSREC(text []byte, opts DecodeOptions) (*Image, error) {
	c := newCollector(opts.MaxSize)
	var (
		rec      [256]byte
		name     string
		entry    uint64
		terminal bool
		records  uint64 // data records read so far
		seen     int    // records read so far, any type
		lineNo   int
	)
	for rest := text; ; {
		line, r, n, ok := nextLine(rest)
		lineNo += n
		if !ok {
			break
		}
		rest = r
		fail := func(why string) error { return fmt.Errorf("srec line %d: %w: %s", lineNo, ErrSyntax, why) }
		if terminal {
			return nil, fail("record after the termination record")
		}
		if len(line) < 2 || line[0] != 'S' || line[1] < '0' || line[1] > '9' {
			return nil, fail("record does not start with 'S' and a digit")
		}
		typ := int(line[1] - '0')
		al := srecAddrLen[typ]
		if al == 0 {
			return nil, fail("S4 is reserved")
		}
		body := line[2:]
		k := len(body) / 2
		if len(body)%2 != 0 || k < 1+al+1 || k > len(rec) {
			return nil, fail("bad record length")
		}
		if !unhex(rec[:k], body) {
			return nil, fail("not a hex digit")
		}
		if int(rec[0])+1 != k {
			return nil, fail("byte count does not match the record length")
		}
		var sum byte
		for _, b := range rec[:k-1] {
			sum += b
		}
		if ^sum != rec[k-1] {
			return nil, fmt.Errorf("srec line %d: %w", lineNo, ErrChecksum)
		}
		var addr uint64
		for _, b := range rec[1 : 1+al] {
			addr = addr<<8 | uint64(b)
		}
		data := rec[1+al : k-1]
		switch typ {
		case 0:
			if seen != 0 {
				return nil, fail("S0 is not the first record")
			}
			name = string(data)
		case 1, 2, 3:
			if addr+uint64(len(data)) > 1<<32 {
				return nil, fmt.Errorf("srec line %d: %w: %d bytes at 0x%x", lineNo, ErrAddrOverflow, len(data), addr)
			}
			if err := c.add(addr, data); err != nil {
				return nil, err
			}
			records++
		case 5, 6:
			if len(data) != 0 {
				return nil, fail("count record with data")
			}
			if addr != records {
				return nil, fail(fmt.Sprintf("count says %d data records, %d were read", addr, records))
			}
		default: // 7, 8, 9
			if len(data) != 0 {
				return nil, fail("termination record with data")
			}
			entry, terminal = addr, true
		}
		seen++
	}
	if !terminal {
		return nil, fmt.Errorf("srec: %w: no S7, S8 or S9 termination record", ErrSyntax)
	}
	im, err := c.image()
	if err != nil {
		return nil, err
	}
	im.Entry, im.HasEntry, im.Name = entry, true, name
	return im, nil
}
