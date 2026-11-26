package fwimg

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"time"
)

// More uImage codes, for reading (U-Boot include/image.h).
const (
	TypeRAMDisk = 3
	TypeMulti   = 4
	TypeScript  = 6
)

const uImageHeaderSize = 64

// UImageHeader is the 64-byte legacy U-Boot header, docs/spec-notes.md 5.1.
type UImageHeader struct {
	HeaderCRC uint32
	Time      uint32
	Size      uint32 // ih_size: the data length
	Load      uint32
	Entry     uint32
	DataCRC   uint32
	OS        byte
	Arch      byte
	Type      byte
	Comp      byte
	Name      string // up to the first NUL, at most 32 bytes
}

// ParseUImage reads a legacy uImage: it checks the magic, the header CRC
// (over the header with that field zeroed) and the data CRC, and that ih_size
// bytes of data follow the header inside data. It returns the header and the
// payload, a slice of data; bytes after the payload are ignored, as U-Boot
// ignores them.
//
// Refusals wrap ErrSyntax (not a uImage), ErrChecksum (a CRC differs) or
// ErrRange (ih_size runs past the end of the input).
func ParseUImage(data []byte) (*UImageHeader, []byte, error) {
	if len(data) < uImageHeaderSize {
		return nil, nil, fmt.Errorf("uimage: %w: %d bytes, a header is %d", ErrSyntax, len(data), uImageHeaderSize)
	}
	if binary.BigEndian.Uint32(data) != uImageMagic {
		return nil, nil, fmt.Errorf("uimage: %w: bad magic", ErrSyntax)
	}
	var hdr [uImageHeaderSize]byte
	copy(hdr[:], data)
	h := &UImageHeader{
		HeaderCRC: binary.BigEndian.Uint32(hdr[4:]),
		Time:      binary.BigEndian.Uint32(hdr[8:]),
		Size:      binary.BigEndian.Uint32(hdr[12:]),
		Load:      binary.BigEndian.Uint32(hdr[16:]),
		Entry:     binary.BigEndian.Uint32(hdr[20:]),
		DataCRC:   binary.BigEndian.Uint32(hdr[24:]),
		OS:        hdr[28],
		Arch:      hdr[29],
		Type:      hdr[30],
		Comp:      hdr[31],
	}
	name := hdr[32:64]
	for i, b := range name {
		if b == 0 {
			name = name[:i]
			break
		}
	}
	h.Name = string(name)
	clear(hdr[4:8])
	if got := crc32.ChecksumIEEE(hdr[:]); got != h.HeaderCRC {
		return nil, nil, fmt.Errorf("uimage: %w: header CRC is %08x, the header says %08x", ErrChecksum, got, h.HeaderCRC)
	}
	if uint64(h.Size) > uint64(len(data)-uImageHeaderSize) {
		return nil, nil, fmt.Errorf("uimage: %w: data size %d, the file holds %d after the header", ErrRange, h.Size, len(data)-uImageHeaderSize)
	}
	payload := data[uImageHeaderSize : uImageHeaderSize+int(h.Size)]
	if got := crc32.ChecksumIEEE(payload); got != h.DataCRC {
		return nil, nil, fmt.Errorf("uimage: %w: data CRC is %08x, the header says %08x", ErrChecksum, got, h.DataCRC)
	}
	return h, payload, nil
}

// Components splits the payload of a multi-file image (Type TypeMulti) into
// its files, docs/spec-notes.md 5.3: a table of big-endian uint32 sizes ended
// by a zero, then the files, each followed by padding to 4 bytes.
//
// U-Boot counts the table with a loop that is not bounded by ih_size; this
// reader is. The table must end inside the payload, and every file, and the
// padding after every file but the last, must fit in what is left of it
// (ErrRange). Any other Type returns the payload as its one component.
func (h *UImageHeader) Components(payload []byte) ([][]byte, error) {
	if h.Type != TypeMulti {
		return [][]byte{payload}, nil
	}
	var sizes []uint32
	table := 0
	for {
		if table+4 > len(payload) {
			return nil, fmt.Errorf("uimage: %w: the size table does not end inside the %d byte payload", ErrRange, len(payload))
		}
		s := binary.BigEndian.Uint32(payload[table:])
		table += 4
		if s == 0 {
			break
		}
		sizes = append(sizes, s)
	}
	out := make([][]byte, 0, len(sizes))
	off := uint64(table)
	for i, s := range sizes {
		if uint64(s) > uint64(len(payload))-off {
			return nil, fmt.Errorf("uimage: %w: file %d of %d bytes at offset %d, the payload is %d bytes", ErrRange, i, s, off, len(payload))
		}
		out = append(out, payload[off:off+uint64(s):off+uint64(s)])
		off = (off + uint64(s) + 3) &^ 3
		if i < len(sizes)-1 && off > uint64(len(payload)) {
			return nil, fmt.Errorf("uimage: %w: padding after file %d runs past the payload", ErrRange, i)
		}
	}
	return out, nil
}

// Names as U-Boot prints them (boot/image.c, the uimage_os, uimage_arch,
// uimage_type and uimage_comp tables); a code not listed prints as U-Boot's
// "Unknown ..." text.
var (
	uimageOS = map[byte]string{0: "Invalid OS", 1: "OpenBSD", 2: "NetBSD", 3: "FreeBSD", 5: "Linux", 14: "VxWorks",
		17: "U-Boot", 18: "RTEMS", 25: "ARM Trusted Firmware", 27: "RISC-V OpenSBI"}
	uimageArch = map[byte]string{0: "Invalid Architecture", 2: "ARM", 3: "Intel x86", 5: "MIPS", 7: "PowerPC",
		22: "AArch64", 24: "AMD x86_64", 26: "RISC-V", 27: "LoongArch"}
	uimageType = map[byte]string{0: "Invalid Image", 1: "Standalone Program", 2: "Kernel Image", 3: "RAMDisk Image",
		4: "Multi-File Image", 5: "Firmware", 6: "Script", 7: "Filesystem Image (any type)", 8: "Flat Device Tree"}
	uimageComp = map[byte]string{0: "uncompressed", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}
)

func nameOr(m map[byte]string, k byte, unknown string) string {
	if s, ok := m[k]; ok {
		return s
	}
	return unknown
}

// sizeText is U-Boot's genimg_print_size text: "N Bytes = X KiB = Y MiB".
func sizeText(n uint32) string {
	return fmt.Sprintf("%d Bytes = %.2f KiB = %.2f MiB", n, float64(n)/1024, float64(n)/1024/1024)
}

// Listing is what `mkimage -l` prints for the header: name, creation time
// (UTC, in ctime's layout), type, data size, load address and entry point.
// For a multi-file image, pass the Components of its payload to get the
// "Contents:" section, one line per file.
func (h *UImageHeader) Listing(components [][]byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Image Name:   %s\n", h.Name)
	fmt.Fprintf(&b, "Created:      %s\n", time.Unix(int64(h.Time), 0).UTC().Format("Mon Jan _2 15:04:05 2006"))
	fmt.Fprintf(&b, "Image Type:   %s %s %s (%s)\n",
		nameOr(uimageArch, h.Arch, "Unknown Architecture"), nameOr(uimageOS, h.OS, "Unknown OS"),
		nameOr(uimageType, h.Type, "Unknown Image"), nameOr(uimageComp, h.Comp, "Unknown Compression"))
	fmt.Fprintf(&b, "Data Size:    %s\n", sizeText(h.Size))
	fmt.Fprintf(&b, "Load Address: %08x\n", h.Load)
	fmt.Fprintf(&b, "Entry Point:  %08x\n", h.Entry)
	if h.Type == TypeMulti {
		b.WriteString("Contents:\n")
		for i, c := range components {
			fmt.Fprintf(&b, "   Image %d: %s\n", i, sizeText(uint32(len(c))))
		}
	}
	return b.String()
}

// UImageImage is the Image a uImage loads: its payload at the load address,
// with the entry point, the name and the header. A compressed payload is
// refused (ErrFormat): the loader decompresses it, and this reader does not.
func UImageImage(data []byte) (*Image, error) {
	h, payload, err := ParseUImage(data)
	if err != nil {
		return nil, err
	}
	if h.Comp != CompNone {
		return nil, fmt.Errorf("uimage: %w: the payload is %s compressed", ErrFormat, nameOr(uimageComp, h.Comp, "unknown"))
	}
	if h.Type == TypeMulti {
		return nil, fmt.Errorf("uimage: %w: a multi-file image has no single load image", ErrFormat)
	}
	// A 32-bit load address and a payload of at most 32 bits cannot pass 2^64.
	im, _ := RawImage(payload, uint64(h.Load))
	im.Entry, im.HasEntry, im.Name, im.UImage = uint64(h.Entry), true, h.Name, h
	return im, nil
}
