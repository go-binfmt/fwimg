// Package elfgen builds minimal ELF64 little-endian images that carry only
// program headers: all fwimg reads. The tests and the corpus generator share
// it so the committed fuzz seeds and the unit tests describe the same files.
package elfgen

import (
	"debug/elf"
	"encoding/binary"
)

// Seg is one PT_LOAD segment. Data is copied to Off; Filesz and Memsz are
// written to the header as given, so a test can lie about them.
type Seg struct {
	Paddr, Vaddr, Off, Filesz, Memsz uint64
	Data                             []byte
}

// Sec is one section header. Its bytes are the file's own at Off, written by
// the segments that hold them; Build only names it.
type Sec struct {
	Name                string
	Type                uint32
	Flags, Addr, Off, N uint64
}

// BuildSections is Build plus a section header table (a null section, secs
// in order, and a string table) appended after the segment data.
func BuildSections(machine elf.Machine, entry uint64, segs []Seg, secs []Sec) []byte {
	buf := Build(machine, entry, segs)
	str := []byte{0}
	names := make([]uint32, len(secs))
	for i, s := range secs {
		names[i] = uint32(len(str))
		str = append(str, s.Name...)
		str = append(str, 0)
	}
	strOff := uint64(len(buf))
	buf = append(buf, str...)
	for len(buf)%8 != 0 {
		buf = append(buf, 0)
	}
	shoff := uint64(len(buf))
	buf = append(buf, make([]byte, 64*(len(secs)+2))...)
	put := func(i int, name, typ uint32, flags, addr, off, size uint64) {
		h := buf[shoff+uint64(64*i):]
		binary.LittleEndian.PutUint32(h, name)
		binary.LittleEndian.PutUint32(h[4:], typ)
		binary.LittleEndian.PutUint64(h[8:], flags)
		binary.LittleEndian.PutUint64(h[16:], addr)
		binary.LittleEndian.PutUint64(h[24:], off)
		binary.LittleEndian.PutUint64(h[32:], size)
	}
	for i, s := range secs {
		put(i+1, names[i], s.Type, s.Flags, s.Addr, s.Off, s.N)
	}
	put(len(secs)+1, 0, uint32(elf.SHT_STRTAB), 0, 0, strOff, uint64(len(str)))
	binary.LittleEndian.PutUint64(buf[40:], shoff)
	binary.LittleEndian.PutUint16(buf[58:], 64)
	binary.LittleEndian.PutUint16(buf[60:], uint16(len(secs)+2))
	binary.LittleEndian.PutUint16(buf[62:], uint16(len(secs)+1))
	return buf
}

// Build returns an ELF64 executable of the given machine with one PT_LOAD
// program header per segment.
func Build(machine elf.Machine, entry uint64, segs []Seg) []byte {
	const phoff = 64
	size := uint64(0x400)
	for _, s := range segs {
		if e := s.Off + uint64(len(s.Data)); e > size && s.Off < 1<<30 {
			size = e
		}
	}
	buf := make([]byte, size)
	copy(buf, []byte{0x7f, 'E', 'L', 'F'})
	buf[4], buf[5], buf[6] = 2, 1, 1 // ELFCLASS64, LSB, EV_CURRENT
	binary.LittleEndian.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(buf[18:], uint16(machine))
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[24:], entry)
	binary.LittleEndian.PutUint64(buf[32:], phoff)
	binary.LittleEndian.PutUint16(buf[52:], 64) // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:], 56) // e_phentsize
	binary.LittleEndian.PutUint16(buf[56:], uint16(len(segs)))
	for i, s := range segs {
		p := phoff + i*56
		binary.LittleEndian.PutUint32(buf[p:], uint32(elf.PT_LOAD))
		binary.LittleEndian.PutUint32(buf[p+4:], uint32(elf.PF_R|elf.PF_X))
		binary.LittleEndian.PutUint64(buf[p+8:], s.Off)
		binary.LittleEndian.PutUint64(buf[p+16:], s.Vaddr)
		binary.LittleEndian.PutUint64(buf[p+24:], s.Paddr)
		binary.LittleEndian.PutUint64(buf[p+32:], s.Filesz)
		binary.LittleEndian.PutUint64(buf[p+40:], s.Memsz)
		binary.LittleEndian.PutUint64(buf[p+48:], 0x1000)
		if s.Off < size && uint64(len(s.Data)) <= size-s.Off {
			copy(buf[s.Off:], s.Data)
		}
	}
	return buf
}
