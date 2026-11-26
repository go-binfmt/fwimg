package fwimg

import (
	"encoding/binary"
	"fmt"
)

// SRECAuto asks EncodeSRECOpts to pick the address length the way objcopy
// does: the shortest of 16, 24 and 32 bits that holds the highest address
// written (S1, S2, S3).
const SRECAuto = -1

// SRECOptions controls EncodeSRECOpts.
type SRECOptions struct {
	// Name is the S0 header text (at most 252 bytes).
	Name string
	// DataPerLine is the data bytes per record, 16 when zero, at most 250.
	DataPerLine int
	// AddrBits is the address length: 16 (S1/S9), 24 (S2/S8), 32 (S3/S7) or
	// SRECAuto. Zero means 32, what EncodeSREC always wrote.
	AddrBits int
	// Count writes the S5 (or, above 65535 records, S6) count of the data
	// records before the terminator, as srec_cat does. objcopy never does.
	Count bool
	// CRLF ends every line with CR LF, as objcopy and srec_cat do; the
	// default is LF.
	CRLF bool
}

func (o SRECOptions) eol() string { return eol(o.CRLF) }

func eol(crlf bool) string {
	if crlf {
		return "\r\n"
	}
	return "\n"
}

// checkSpan refuses a range of n bytes starting at addr that would run past
// the end of a bits-wide address space.
func checkSpan(addr uint64, n int, bits int) error {
	limit := uint64(1) << bits
	if addr > limit || addr+uint64(n) > limit {
		if bits == 32 {
			return fmt.Errorf("%w: %d bytes at 0x%08x run past 4 GiB", ErrAddrOverflow, n, addr)
		}
		return fmt.Errorf("%w: %d bytes at 0x%08x run past the %d-bit address space", ErrAddrOverflow, n, addr, bits)
	}
	return nil
}

// highest is the address of the last byte of the image, 0 when it is empty.
func (im *Image) highest() uint64 {
	var hi uint64
	for _, s := range im.Segments {
		if len(s.Data) > 0 {
			hi = max(hi, s.End()-1)
		}
	}
	return hi
}

// EncodeSRECOpts is EncodeSREC with options: the address length, the count
// record and the line ending. The segments are written in order, each as data
// records, and a gap between two is left out of the file. The terminator
// carries the image's entry, 0 when it has none. It refuses (ErrFormat) a
// name above 252 bytes, DataPerLine above 250 or an unknown AddrBits, and
// (ErrAddrOverflow) data or an entry the address length cannot hold.
func EncodeSRECOpts(im *Image, o SRECOptions) ([]byte, error) {
	per := o.DataPerLine
	if per <= 0 {
		per = 16
	}
	if per > 250 {
		return nil, fmt.Errorf("%w: %d data bytes per S-record, at most 250", ErrFormat, per)
	}
	if len(o.Name) > 252 {
		return nil, fmt.Errorf("%w: S0 name of %d bytes, at most 252", ErrFormat, len(o.Name))
	}
	bits := o.AddrBits
	switch bits {
	case 0:
		bits = 32
	case SRECAuto:
		switch hi := im.highest(); {
		case hi <= 0xffff:
			bits = 16
		case hi <= 0xff_ffff:
			bits = 24
		default:
			bits = 32
		}
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("%w: S-record address length %d, want 16, 24, 32 or auto", ErrFormat, bits)
	}
	for _, s := range im.Segments {
		if err := checkSpan(s.Addr, len(s.Data), bits); err != nil {
			return nil, err
		}
	}
	var entry uint64
	if im.HasEntry {
		entry = im.Entry
	}
	if entry >= 1<<bits {
		return nil, fmt.Errorf("%w: start address 0x%x does not fit %d bits", ErrAddrOverflow, entry, bits)
	}
	size, err := textSize(im.Len()+uint64(len(o.Name)), per)
	if err != nil {
		return nil, err
	}
	nl := o.eol()
	dataType := byte('1' + (bits-16)/8)
	out := make([]byte, 0, size)
	out = srecLine(out, '0', 0, []byte(o.Name), nl) // S0: address 0000, data = name
	var records uint64
	for _, s := range im.Segments {
		for off := 0; off < len(s.Data); off += per {
			end := min(off+per, len(s.Data))
			out = srecLine(out, dataType, uint32(s.Addr)+uint32(off), s.Data[off:end], nl)
			records++
		}
	}
	if o.Count {
		switch {
		case records <= 0xffff:
			out = srecLine(out, '5', uint32(records), nil, nl)
		case records <= 0xff_ffff:
			out = srecLine(out, '6', uint32(records), nil, nl)
		default:
			return nil, fmt.Errorf("%w: %d data records, an S6 count holds 16777215", ErrFormat, records)
		}
	}
	return srecLine(out, byte('0'+10-int(dataType-'0')), uint32(entry), nil, nl), nil
}

// srecLine appends one S-record ending in nl. The address field is as long as
// the record type says: S0 is the header and carries the 2-byte address 0000
// the format defines (a 4-byte S0 would have a strict reader take two zero
// bytes for the name).
func srecLine(out []byte, typ byte, addr uint32, data []byte, nl string) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], addr)
	ab := a[4-srecAddrLen[typ-'0']:]
	count := len(ab) + len(data) + 1 // address + data + checksum
	sum := count
	for _, b := range ab {
		sum += int(b)
	}
	for _, b := range data {
		sum += int(b)
	}
	out = append(out, 'S', typ)
	out = appendHexByte(out, byte(count))
	out = appendHex(out, ab)
	out = appendHex(out, data)
	out = appendHexByte(out, byte(^sum&0xff))
	return append(out, nl...)
}

// IHEXMode selects how the Intel HEX encoder reaches addresses above 64 KiB,
// where the two reference tools disagree (docs/spec-notes.md §2.2-2.3).
type IHEXMode int

const (
	// IHEXLinear writes type 04 (extended linear address) records only and a
	// type 05 start record, as srec_cat does by default.
	IHEXLinear IHEXMode = iota
	// IHEXObjcopy follows objcopy: type 02 (segment base) records up to
	// 0xFFFFF, type 04 above, and a type 03 start record up to 0xFFFFF, type
	// 05 above.
	IHEXObjcopy
)

// IHEXOptions controls EncodeIHEXOpts.
type IHEXOptions struct {
	// DataPerLine is the data bytes per record, 16 when zero, at most 255.
	DataPerLine int
	// Mode is the address mode, IHEXLinear by default.
	Mode IHEXMode
	// CRLF ends every line with CR LF, as objcopy and srec_cat do; the
	// default is LF.
	CRLF bool
}

// EncodeIHEXOpts is EncodeIHEX with options. A non-zero start address is
// written before the EOF record, as type 05 (type 03 below 1 MiB in
// IHEXObjcopy mode); the same refusals as EncodeIHEX apply, and an unknown
// mode is ErrFormat.
func EncodeIHEXOpts(im *Image, o IHEXOptions) ([]byte, error) {
	per := o.DataPerLine
	if per <= 0 {
		per = 16
	}
	if per > 255 {
		return nil, fmt.Errorf("%w: %d data bytes per record, at most 255", ErrFormat, per)
	}
	if o.Mode != IHEXLinear && o.Mode != IHEXObjcopy {
		return nil, fmt.Errorf("%w: Intel HEX address mode %d", ErrFormat, o.Mode)
	}
	for _, s := range im.Segments {
		if err := checkSpan(s.Addr, len(s.Data), 32); err != nil {
			return nil, err
		}
	}
	if im.HasEntry && im.Entry >= 1<<32 {
		return nil, fmt.Errorf("%w: start address 0x%x does not fit 32 bits", ErrAddrOverflow, im.Entry)
	}
	size, err := textSize(im.Len(), per)
	if err != nil {
		return nil, err
	}
	nl := eol(o.CRLF)
	out := make([]byte, 0, size)
	if o.Mode == IHEXObjcopy {
		out = ihexObjcopyData(out, im, per, nl)
	} else {
		out = ihexLinearData(out, im, per, nl)
	}
	if im.HasEntry && im.Entry != 0 {
		start := uint32(im.Entry)
		if o.Mode == IHEXObjcopy && start <= 0xfffff {
			out = ihexRecord(out, 0, 0x03, []byte{byte((start & 0xf0000) >> 12), 0, byte(start >> 8), byte(start)}, nl)
		} else {
			var e [4]byte
			binary.BigEndian.PutUint32(e[:], start)
			out = ihexRecord(out, 0, 0x05, e[:], nl)
		}
	}
	return ihexRecord(out, 0, 0x01, nil, nl), nil // EOF
}

// ihexLinearData writes the data records with a type-04 record whenever the
// upper 16 bits change.
func ihexLinearData(out []byte, im *Image, per int, nl string) []byte {
	// The base starts at 0, which is what a reader assumes before any type-04
	// record: no record is needed until the upper half differs.
	var upper uint32
	for _, s := range im.Segments {
		addr, data := uint32(s.Addr), s.Data
		for off := 0; off < len(data); {
			cur := addr + uint32(off)
			hi := cur >> 16
			// A record never crosses a 64 KiB boundary: its 16-bit address
			// would wrap inside the segment.
			n := min(per, len(data)-off, int(0x10000-(cur&0xffff)))
			if hi != upper {
				upper = hi
				var ext [2]byte
				binary.BigEndian.PutUint16(ext[:], uint16(hi))
				out = ihexRecord(out, 0, 0x04, ext[:], nl)
			}
			out = ihexRecord(out, uint16(cur), 0x00, data[off:off+n], nl)
			off += n
		}
	}
	return out
}

// ihexObjcopyData mirrors the write loop of binutils' ihex.c: a segment base
// (type 02) while the address is below 1 MiB and no linear base has been
// written, a linear base (type 04) otherwise, the segment base cleared first.
func ihexObjcopyData(out []byte, im *Image, per int, nl string) []byte {
	var extbase, segbase uint64
	for _, s := range im.Segments {
		where, data := s.Addr, s.Data
		for len(data) > 0 {
			if where < extbase || where-extbase < segbase || where-extbase-segbase > 0xffff {
				if extbase == 0 && where <= 0xfffff {
					segbase = where & 0xf0000
					out = ihexRecord(out, 0, 0x02, []byte{byte(segbase >> 12), byte(segbase >> 4)}, nl)
				} else {
					if segbase != 0 {
						out = ihexRecord(out, 0, 0x02, []byte{0, 0}, nl)
						segbase = 0
					}
					extbase = where & 0xffff0000
					out = ihexRecord(out, 0, 0x04, []byte{byte(extbase >> 24), byte(extbase >> 16)}, nl)
				}
			}
			off := where - extbase - segbase
			n := min(per, len(data), int(0x10000-off))
			out = ihexRecord(out, uint16(off), 0x00, data[:n], nl)
			where += uint64(n)
			data = data[n:]
		}
	}
	return out
}

// ihexRecord appends one Intel HEX record ending in nl.
func ihexRecord(out []byte, addr uint16, typ byte, data []byte, nl string) []byte {
	out = append(out, ':')
	out = appendHexByte(out, byte(len(data)))
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], addr)
	out = appendHex(out, a[:])
	out = appendHexByte(out, typ)
	out = appendHex(out, data)
	sum := len(data) + int(a[0]) + int(a[1]) + int(typ)
	for _, b := range data {
		sum += int(b)
	}
	out = appendHexByte(out, byte(-sum&0xff))
	return append(out, nl...)
}
