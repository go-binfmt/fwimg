// Package fwimg produces bare-metal / firmware images in pure Go, with no
// dependency on binutils (objcopy), srec_cat or U-Boot's mkimage.
//
// It turns an ELF executable into the formats a flat-loaded target needs:
//
//   - Flatten: an ELF executable → a flat binary (objcopy -O binary),
//     for images a bootloader/ROM loads at a fixed address (Raspberry Pi
//     kernel.img, QEMU -kernel, flash images);
//   - SREC / IHEX: Motorola S-record and Intel HEX text encodings, for
//     flashing tools and ROM programmers;
//   - UImage: the legacy U-Boot image header, for boards booted via
//     `bootm` (e.g. NXP i.MX).
//
// The input is untrusted. Every size and address is checked before it is
// used: a segment that points outside the file, an address range that wraps
// around, an image that would need more memory than the caller allows, a
// payload that does not fit the 32-bit field of the format: each is refused
// with an error that wraps one of the Err values below, and nothing is
// allocated for it.
package fwimg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"slices"
	"sort"

	"github.com/go-binfmt/elfpatch"
)

// ELF constants fwimg needs: the PT_LOAD segment type and the machines it
// maps to a uImage architecture (e_machine values from the ELF gABI).
const (
	ptLoad      = 1
	emARM       = 40
	emX86_64    = 62
	emAARCH64   = 183
	emRISCV     = 243
	emLoongArch = 258
)

// Refusals. Test with errors.Is.
var (
	// ErrTooLarge: the flat image would be larger than the allowed size.
	ErrTooLarge = errors.New("fwimg: image larger than the allowed size")
	// ErrRange: a segment's file range lies outside the input.
	ErrRange = errors.New("fwimg: segment file range outside the input")
	// ErrAddrOverflow: an address range wraps around its integer width.
	ErrAddrOverflow = errors.New("fwimg: address range overflows")
	// ErrOverlap: two loadable segments overlap in memory.
	ErrOverlap = errors.New("fwimg: loadable segments overlap")
	// ErrFormat: a parameter does not fit the output format.
	ErrFormat = errors.New("fwimg: value does not fit the output format")
)

// DefaultMaxSize is the largest flat image Flatten builds when
// FlattenOptions.MaxSize is zero: 256 MiB. Firmware images are kilobytes to
// a few megabytes; the bound exists because two segments far apart in
// memory would otherwise ask for the whole distance between them.
const DefaultMaxSize = 256 << 20

// FlattenOptions controls Flatten.
type FlattenOptions struct {
	// UseVaddr places each segment by its virtual address (p_vaddr)
	// instead of its load address (p_paddr, the objcopy default). For most
	// bare-metal ELFs the two are equal.
	UseVaddr bool
	// Pad is the byte used to fill gaps between segments (default 0).
	Pad byte
	// MaxSize bounds the image, in bytes, from the lowest to the highest
	// loaded address (gaps included). Zero means DefaultMaxSize. A larger
	// image is refused with ErrTooLarge before anything is allocated. On a
	// 32-bit platform the effective bound is also capped at the largest int.
	MaxSize uint64
}

// Flatten converts an ELF executable into a flat binary image, mirroring
// `objcopy -O binary`: every PT_LOAD segment with file content is placed
// at its load address relative to the lowest such address, and the gaps
// between segments are filled with opts.Pad. Trailing zero-initialised
// memory (p_memsz > p_filesz, i.e. .bss) is not emitted.
//
// size is the length of r in bytes; every segment must lie inside it
// (ErrRange), overlapping segments are refused (ErrOverlap), and so is an
// image longer than opts.MaxSize (ErrTooLarge).
//
// It returns the image bytes and the base load address the image starts
// at (the lowest segment address), so callers can feed SREC/IHEX/UImage.
func Flatten(r io.ReaderAt, size int64, opts FlattenOptions) ([]byte, uint64, error) {
	if size < 0 {
		size = 0
	}
	if uint64(size) > math.MaxInt32 {
		return nil, 0, fmt.Errorf("parse ELF: %w: input of %d bytes", ErrRange, size)
	}
	data := make([]byte, size)
	if n, err := r.ReadAt(data, 0); err != nil && !(err == io.EOF && n == len(data)) {
		return nil, 0, fmt.Errorf("read ELF: %w", err)
	}
	return FlattenBytes(data, opts)
}

// FlattenBytes is Flatten for an image already in memory (at most 2 GiB, the
// bound elfpatch.Parse holds); the segments are copied out of data.
func FlattenBytes(data []byte, opts FlattenOptions) ([]byte, uint64, error) {
	size := int64(len(data))
	ef, err := elfpatch.Parse(data)
	if errors.Is(err, elfpatch.ErrSegmentRange) {
		return nil, 0, fmt.Errorf("%w: %w", ErrRange, err)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("parse ELF: %w", err)
	}
	limit := opts.MaxSize
	if limit == 0 {
		limit = DefaultMaxSize
	}
	if limit > math.MaxInt {
		limit = math.MaxInt
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
		return nil, 0, fmt.Errorf("no PT_LOAD segments with file content")
	}
	for i, p := range loads {
		// p.Off+p.Filesz must not wrap, and must end inside the input.
		if p.Off > uint64(size) || p.Filesz > uint64(size)-p.Off {
			return nil, 0, fmt.Errorf("%w: segment %d offset 0x%x size 0x%x, input is %d bytes", ErrRange, i, p.Off, p.Filesz, size)
		}
		if p.Filesz > math.MaxUint64-addr(p) {
			return nil, 0, fmt.Errorf("%w: segment %d address 0x%x size 0x%x", ErrAddrOverflow, i, addr(p), p.Filesz)
		}
	}
	sort.SliceStable(loads, func(i, j int) bool { return addr(loads[i]) < addr(loads[j]) })

	base := addr(loads[0])
	var end uint64
	for i, p := range loads {
		e := addr(p) + p.Filesz // cannot wrap: checked above
		if i > 0 && addr(p) < end {
			return nil, 0, fmt.Errorf("%w: segment at 0x%x starts before 0x%x", ErrOverlap, addr(p), end)
		}
		end = e
	}
	// Sorted and disjoint, so end is the highest address and the segments
	// together never read more than end-base bytes.
	if end-base > limit {
		return nil, 0, fmt.Errorf("%w: 0x%x..0x%x is %d bytes, limit %d", ErrTooLarge, base, end, end-base, limit)
	}
	out := make([]byte, int(end-base))
	if opts.Pad != 0 {
		for i := range out {
			out[i] = opts.Pad
		}
	}
	for _, p := range loads {
		at := int(addr(p) - base)
		copy(out[at:at+int(p.Filesz)], data[p.Off:p.Off+p.Filesz])
	}
	return out, base, nil
}

// checkSpan refuses a range of n bytes starting at the 32-bit address addr
// that would run past the end of the 32-bit address space.
func checkSpan(addr uint64, n int) error {
	if addr > 1<<32 || addr+uint64(n) > 1<<32 {
		return fmt.Errorf("%w: %d bytes at 0x%08x run past 4 GiB", ErrAddrOverflow, n, addr)
	}
	return nil
}

// --- Motorola S-record (SREC) -------------------------------------------------

// SREC encodes data loaded at addr as Motorola S-records using 32-bit
// addresses (S3 data records, an S0 header carrying name, and an S7
// termination carrying entry). dataPerLine bytes are emitted per S3 record
// (default 16 when zero). The result ends with a trailing newline.
//
// It refuses (ErrAddrOverflow) data that would run past 4 GiB, and
// (ErrFormat) a name longer than 252 bytes or dataPerLine above 250: the
// record's one-byte count could not hold them.
func SREC(addr uint32, data []byte, name string, entry uint32, dataPerLine int) ([]byte, error) {
	im := &Image{Entry: uint64(entry), HasEntry: true}
	if len(data) > 0 {
		im.Segments = []Segment{{Addr: uint64(addr), Data: data}}
	}
	return EncodeSREC(im, name, dataPerLine)
}

// EncodeSREC is SREC for an Image: the segments are written in order, each as
// S3 records, and a gap between two is left out of the file (objcopy does the
// same). The S7 record carries the image's entry, 0 when it has none. The
// same refusals as SREC apply, and an entry above 32 bits is refused
// (ErrAddrOverflow).
func EncodeSREC(im *Image, name string, dataPerLine int) ([]byte, error) {
	if dataPerLine <= 0 {
		dataPerLine = 16
	}
	if dataPerLine > 250 {
		return nil, fmt.Errorf("%w: %d data bytes per S-record, at most 250", ErrFormat, dataPerLine)
	}
	if len(name) > 252 {
		return nil, fmt.Errorf("%w: S0 name of %d bytes, at most 252", ErrFormat, len(name))
	}
	for _, s := range im.Segments {
		if err := checkSpan(s.Addr, len(s.Data)); err != nil {
			return nil, err
		}
	}
	var entry uint64
	if im.HasEntry {
		entry = im.Entry
	}
	if entry > math.MaxUint32 {
		return nil, fmt.Errorf("%w: start address 0x%x does not fit 32 bits", ErrAddrOverflow, entry)
	}
	size, err := textSize(im.Len()+uint64(len(name)), dataPerLine)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size)
	// S0 header: address 0x0000, data = name bytes.
	out = srecLine(out, '0', 0, []byte(name))
	// S3 data records.
	for _, s := range im.Segments {
		for off := 0; off < len(s.Data); off += dataPerLine {
			end := min(off+dataPerLine, len(s.Data))
			out = srecLine(out, '3', uint32(s.Addr)+uint32(off), s.Data[off:end])
		}
	}
	// S7 termination with the entry address, no data.
	out = srecLine(out, '7', uint32(entry), nil)
	return out, nil
}

// srecLine appends one S-record. S3 and S7 carry a 4-byte address; S0 is the
// header record and carries the 2-byte address 0000 the format defines (a
// 4-byte S0 would have a strict reader take two zero bytes for the name).
func srecLine(out []byte, typ byte, addr uint32, data []byte) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], addr)
	ab := a[:]
	if typ == '0' {
		ab = a[2:]
	}
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
	return append(out, '\n')
}

// --- Intel HEX (IHEX) ---------------------------------------------------------

// IHEX encodes data loaded at addr as Intel HEX, emitting Extended Linear
// Address (type 04) records whenever the upper 16 bits of the address
// change, then an EOF (type 01) record. dataPerLine bytes per data record
// (default 16). The result ends with a trailing newline.
//
// It refuses (ErrAddrOverflow) data that would run past 4 GiB and
// (ErrFormat) dataPerLine above 255.
func IHEX(addr uint32, data []byte, dataPerLine int) ([]byte, error) {
	im := &Image{}
	if len(data) > 0 {
		im.Segments = []Segment{{Addr: uint64(addr), Data: data}}
	}
	return EncodeIHEX(im, dataPerLine)
}

// EncodeIHEX is IHEX for an Image: every segment is written in order, with a
// type-04 record whenever the upper 16 bits change, and a gap between
// segments is left out of the file. A non-zero start address is written as a
// type-05 record before the EOF (objcopy does not write one for 0), and one
// above 32 bits is refused (ErrAddrOverflow). The same refusals as IHEX apply.
func EncodeIHEX(im *Image, dataPerLine int) ([]byte, error) {
	if dataPerLine <= 0 {
		dataPerLine = 16
	}
	if dataPerLine > 255 {
		return nil, fmt.Errorf("%w: %d data bytes per record, at most 255", ErrFormat, dataPerLine)
	}
	for _, s := range im.Segments {
		if err := checkSpan(s.Addr, len(s.Data)); err != nil {
			return nil, err
		}
	}
	if im.HasEntry && im.Entry > math.MaxUint32 {
		return nil, fmt.Errorf("%w: start address 0x%x does not fit 32 bits", ErrAddrOverflow, im.Entry)
	}
	size, err := textSize(im.Len(), dataPerLine)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size)
	// The segment base starts at 0, which is what a reader assumes before
	// any type-04 record: no record is needed until the upper half differs.
	var upper uint32
	for _, s := range im.Segments {
		addr, data := uint32(s.Addr), s.Data
		for off := 0; off < len(data); {
			cur := addr + uint32(off)
			hi := cur >> 16
			// A record never crosses a 64 KiB boundary: its 16-bit address
			// would wrap inside the segment.
			n := min(dataPerLine, len(data)-off, int(0x10000-(cur&0xffff)))
			if hi != upper {
				upper = hi
				var ext [2]byte
				binary.BigEndian.PutUint16(ext[:], uint16(hi))
				out = ihexRecord(out, 0, 0x04, ext[:])
			}
			out = ihexRecord(out, uint16(cur), 0x00, data[off:off+n])
			off += n
		}
	}
	if im.HasEntry && im.Entry != 0 {
		var e [4]byte
		binary.BigEndian.PutUint32(e[:], uint32(im.Entry))
		out = ihexRecord(out, 0, 0x05, e[:])
	}
	return ihexRecord(out, 0, 0x01, nil), nil // EOF
}

// ihexRecord appends one Intel HEX record.
func ihexRecord(out []byte, addr uint16, typ byte, data []byte) []byte {
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
	cksum := byte(-sum & 0xff)
	out = appendHexByte(out, cksum)
	return append(out, '\n')
}

// --- U-Boot legacy uImage -----------------------------------------------------

// uImage OS, architecture, image-type and compression codes (subset of
// U-Boot's image.h that a Go firmware image actually needs).
const (
	OSLinux        = 5
	OSUBoot        = 17
	ArchARM        = 2
	ArchARM64      = 22
	ArchX86_64     = 24
	ArchRISCV      = 26
	ArchLoongArch  = 27
	TypeStandalone = 1
	TypeKernel     = 2
	TypeFirmware   = 5
	CompNone       = 0
	CompGzip       = 1
)

const uImageMagic = 0x27051956

// maxUImagePayload is the largest size the 32-bit header field holds. It is
// a variable only so a test can lower it: a 4 GiB slice cannot be built
// honestly in a test (and unsafe.Slice over one byte trips checkptr).
var maxUImagePayload uint64 = math.MaxUint32

// UImageOptions controls UImage. Time is taken from the caller (default 0)
// to keep output reproducible.
type UImageOptions struct {
	Load  uint32
	Entry uint32
	Name  string // truncated to 31 bytes + NUL
	OS    byte   // default OSLinux
	Arch  byte   // default ArchARM
	Type  byte   // default TypeKernel
	Comp  byte   // default CompNone
	Time  uint32
}

// UImage wraps payload in a legacy U-Boot image header (64 bytes,
// big-endian) with correct header and data CRC32 (IEEE), so the result
// can be booted with `bootm`. Equivalent to `mkimage -A .. -O .. -T ..
// -C none -a load -e entry -n name -d payload`.
//
// The header's size field is 32 bits: a payload of 4 GiB or more is refused
// (ErrFormat) instead of being recorded with a truncated length.
func UImage(payload []byte, opts UImageOptions) ([]byte, error) {
	if uint64(len(payload)) > maxUImagePayload {
		return nil, fmt.Errorf("%w: uImage payload of %d bytes, at most 4 GiB - 1", ErrFormat, len(payload))
	}
	if opts.OS == 0 {
		opts.OS = OSLinux
	}
	if opts.Arch == 0 {
		opts.Arch = ArchARM
	}
	if opts.Type == 0 {
		opts.Type = TypeKernel
	}
	hdr := make([]byte, 64, 64+len(payload))
	binary.BigEndian.PutUint32(hdr[0:], uImageMagic)
	// hdr[4:8] = header CRC, filled last (computed over header with it zeroed)
	binary.BigEndian.PutUint32(hdr[8:], opts.Time)
	binary.BigEndian.PutUint32(hdr[12:], uint32(len(payload)))
	binary.BigEndian.PutUint32(hdr[16:], opts.Load)
	binary.BigEndian.PutUint32(hdr[20:], opts.Entry)
	binary.BigEndian.PutUint32(hdr[24:], crc32.ChecksumIEEE(payload)) // data CRC
	hdr[28] = opts.OS
	hdr[29] = opts.Arch
	hdr[30] = opts.Type
	hdr[31] = opts.Comp
	name := opts.Name
	if len(name) > 31 {
		name = name[:31]
	}
	copy(hdr[32:63], name)
	binary.BigEndian.PutUint32(hdr[4:], crc32.ChecksumIEEE(hdr)) // header CRC (field currently 0)
	return append(hdr, payload...), nil
}

// ArchFromELF maps an ELF machine to the uImage architecture code, or 0
// when the machine has none here.
func ArchFromELF(m uint16) byte {
	switch m {
	case emARM:
		return ArchARM
	case emAARCH64:
		return ArchARM64
	case emX86_64:
		return ArchX86_64
	case emRISCV:
		return ArchRISCV
	case emLoongArch:
		return ArchLoongArch
	}
	return 0
}

// ArchFromName maps an architecture name (arm, arm64/aarch64,
// x86_64/amd64, riscv/riscv64, loongarch/loong64) to the uImage code. The
// empty name is 0, "derive it from the ELF".
func ArchFromName(s string) (byte, error) {
	switch s {
	case "":
		return 0, nil
	case "arm":
		return ArchARM, nil
	case "arm64", "aarch64":
		return ArchARM64, nil
	case "x86_64", "amd64":
		return ArchX86_64, nil
	case "riscv", "riscv64":
		return ArchRISCV, nil
	case "loongarch", "loong64":
		return ArchLoongArch, nil
	}
	return 0, fmt.Errorf("unknown uimage arch %q", s)
}

// --- hex helpers --------------------------------------------------------------

const hexDigits = "0123456789ABCDEF"

func appendHexByte(out []byte, b byte) []byte {
	return append(out, hexDigits[b>>4], hexDigits[b&0xf])
}

func appendHex(out, b []byte) []byte {
	n := len(out)
	out = slices.Grow(out, 2*len(b))[:n+2*len(b)]
	for i, x := range b {
		out[n+2*i] = hexDigits[x>>4]
		out[n+2*i+1] = hexDigits[x&0xf]
	}
	return out
}

// maxText is the largest text output an int can index on this platform. It is
// a variable so a test can lower it: the real limit needs a 32-bit build and a
// gigabyte of input.
var maxText uint64 = math.MaxInt

// textSize estimates the encoded size of n data bytes in lines of per bytes
// (hex digits plus roughly 16 bytes of record framing per line), so the
// encoders allocate once. An output that cannot be indexed by an int on this
// platform is refused (ErrTooLarge): on 32 bits the doubled size of a large
// input wraps negative.
func textSize(n uint64, per int) (int, error) {
	est := 2*n + (n/uint64(per)+3)*16
	if est > maxText {
		return 0, fmt.Errorf("%w: %d data bytes encode to about %d bytes of text", ErrTooLarge, n, est)
	}
	return int(est), nil
}
