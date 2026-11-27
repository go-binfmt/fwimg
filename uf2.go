package fwimg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// UF2 (docs/spec-notes.md 8; github.com/microsoft/uf2 README): 512-byte blocks,
// every field a little-endian uint32. The oracle is uf2conv.py of the same
// repository: for one contiguous image it writes blocks of 256 payload bytes,
// the last one zero-padded, with the family ID flag when a family is given.
const (
	uf2Magic0 = 0x0A324655 // "UF2\n"
	uf2Magic1 = 0x9E5D5157
	uf2MagicE = 0x0AB16F30

	// uf2BlockSize is the block, uf2DataMax the payload area (512 - 32 - 4),
	// uf2Payload the payload size uf2conv.py writes ("256 is always correct").
	uf2BlockSize = 512
	uf2DataMax   = 476
	uf2Payload   = 256

	uf2FlagNotMain  = 0x00000001
	uf2FlagFileCont = 0x00001000
	uf2FlagFamily   = 0x00002000
	uf2FlagMD5      = 0x00004000
	uf2FlagExt      = 0x00008000
	uf2KnownFlags   = uf2FlagNotMain | uf2FlagFileCont | uf2FlagFamily | uf2FlagMD5 | uf2FlagExt
)

// UF2Family is one row of utils/uf2families.json.
type UF2Family struct {
	ID          uint32
	Name        string // short_name
	Description string
}

// UF2Families is utils/uf2families.json of github.com/microsoft/uf2 at commit
// 70fdee51cf15a487526e88ada2d52346596f80af (read 2026-11-27), in the file's own
// order. TestDifferential_UF2FamiliesAgainstSource checks it against that file when
// FWIMG_UF2_FAMILIES names a copy (CI fetches the pinned commit).
var UF2Families = []UF2Family{
	{0x16573617, "ATMEGA32", "Microchip (Atmel) ATmega32"},
	{0x1851780a, "SAML21", "Microchip (Atmel) SAML21"},
	{0x1b57745f, "NRF52", "Nordic NRF52"},
	{0x1c5f21b0, "ESP32", "ESP32"},
	{0x1e1f432d, "STM32L1", "ST STM32L1xx"},
	{0x202e3a91, "STM32L0", "ST STM32L0xx"},
	{0x21460ff0, "STM32WL", "ST STM32WLxx"},
	{0x22e0d6fc, "RTL8710B", "Realtek AmebaZ RTL8710B"},
	{0x2abc77ec, "LPC55", "NXP LPC55xx"},
	{0x300f5633, "STM32G0", "ST STM32G0xx"},
	{0x31d228c6, "GD32F350", "GD32F350"},
	{0x3379CFE2, "RTL8720D", "Realtek AmebaD RTL8720D"},
	{0x04240bdf, "STM32L5", "ST STM32L5xx"},
	{0x4c71240a, "STM32G4", "ST STM32G4xx"},
	{0x4fb2d5bd, "MIMXRT10XX", "NXP i.MX RT10XX"},
	{0x51e903a8, "XR809", "Xradiotech 809"},
	{0x53b80f00, "STM32F7", "ST STM32F7xx"},
	{0x55114460, "SAMD51", "Microchip (Atmel) SAMD51"},
	{0x57755a57, "STM32F4", "ST STM32F4xx"},
	{0x5a18069b, "FX2", "Cypress FX2"},
	{0x5d1a0a2e, "STM32F2", "ST STM32F2xx"},
	{0x5ee21072, "STM32F1", "ST STM32F103"},
	{0x621e937a, "NRF52833", "Nordic NRF52833"},
	{0x647824b6, "STM32F0", "ST STM32F0xx"},
	{0x675a40b0, "BK7231U", "Beken 7231U/7231T"},
	{0x68ed2b88, "SAMD21", "Microchip (Atmel) SAMD21"},
	{0x6a82cc42, "BK7251", "Beken 7251/7252"},
	{0x6b846188, "STM32F3", "ST STM32F3xx"},
	{0x6d0922fa, "STM32F407", "ST STM32F407"},
	{0x4e8f1c5d, "STM32H5", "ST STM32H5xx"},
	{0x6db66082, "STM32H7", "ST STM32H7xx"},
	{0x70d16653, "STM32WB", "ST STM32WBxx"},
	{0x7b3ef230, "BK7231N", "Beken 7231N"},
	{0x7eab61ed, "ESP8266", "ESP8266"},
	{0x7f83e793, "KL32L2", "NXP KL32L2x"},
	{0x8fb060fe, "STM32F407VG", "ST STM32F407VG"},
	{0x9fffd543, "RTL8710A", "Realtek Ameba1 RTL8710A"},
	{0xada52840, "NRF52840", "Nordic NRF52840"},
	{0x820d9a5f, "NRF52820", "Nordic NRF52820_xxAA"},
	{0xbfdd4eee, "ESP32S2", "ESP32-S2"},
	{0xc47e5767, "ESP32S3", "ESP32-S3"},
	{0xd42ba06c, "ESP32C3", "ESP32-C3"},
	{0x2b88d29c, "ESP32C2", "ESP32-C2"},
	{0x332726f6, "ESP32H2", "ESP32-H2"},
	{0x540ddf62, "ESP32C6", "ESP32-C6"},
	{0x3d308e94, "ESP32P4", "ESP32-P4"},
	{0xf71c0343, "ESP32C5", "ESP32-C5"},
	{0x77d850c4, "ESP32C61", "ESP32-C61"},
	{0xb6dd00af, "ESP32H21", "ESP32-H21"},
	{0x9e0baa8a, "ESP32H4", "ESP32-H4"},
	{0x3101f7c1, "ESP32S31", "ESP32-S31"},
	{0xde1270b7, "BL602", "Boufallo 602"},
	{0xe08f7564, "RTL8720C", "Realtek AmebaZ2 RTL8720C"},
	{0xe48bff56, "RP2040", "Raspberry Pi RP2040"},
	{0xe48bff57, "RP2XXX_ABSOLUTE", "Raspberry Pi Microcontrollers: Absolute (unpartitioned) download"},
	{0xe48bff58, "RP2XXX_DATA", "Raspberry Pi Microcontrollers: Data partition download"},
	{0xe48bff59, "RP2350_ARM_S", "Raspberry Pi RP2350, Secure Arm image"},
	{0xe48bff5a, "RP2350_RISCV", "Raspberry Pi RP2350, RISC-V image"},
	{0xe48bff5b, "RP2350_ARM_NS", "Raspberry Pi RP2350, Non-secure Arm image"},
	{0x00ff6919, "STM32L4", "ST STM32L4xx"},
	{0x9af03e33, "GD32VF103", "GigaDevice GD32VF103"},
	{0x4f6ace52, "CSK4", "LISTENAI CSK300x/400x"},
	{0x6e7348a8, "CSK6", "LISTENAI CSK60xx"},
	{0x11de784a, "M0SENSE", "M0SENSE BL702"},
	{0x4b684d71, "MaixPlay-U4", "Sipeed MaixPlay-U4(BL618)"},
	{0x9517422f, "RZA1LU", "Renesas RZ/A1LU (R7S7210xx)"},
	{0x2dc309c5, "STM32F411xE", "ST STM32F411xE"},
	{0x06d1097b, "STM32F411xC", "ST STM32F411xC"},
	{0x72721d4e, "NRF52832xxAA", "Nordic NRF52832xxAA"},
	{0x6f752678, "NRF52832xxAB", "Nordic NRF52832xxAB"},
	{0xa0c97b8e, "AT32F415", "ArteryTek AT32F415"},
	{0x699b62ec, "CH32V", "WCH CH32V2xx and CH32V3xx"},
	{0x7b8c32a7, "CH32V4X7", "WCH CH32V407 and CH32V467"},
	{0x7be8976d, "RA4M1", "Renesas RA4M1"},
	{0x7410520a, "MAX32690", "Analog Devices MAX32690"},
	{0xd63f8632, "MAX32650", "Analog Devices MAX32650/1/2"},
	{0xf0c30d71, "MAX32666", "Analog Devices MAX32665/6"},
	{0x91d3fd18, "MAX78002", "Analog Devices MAX78002"},
	{0x7d7a66ef, "PY32F071-UVK5-V3", "Quansheng UV-K5 V3 amateur radio based on Puya Semiconductor PY32F071"},
	{0xf4b47471, "Adaboot", "Adafruit maintained MCUboot+UF2 bootloader that manages board checks using extension tags"},
}

// ParseUF2Family reads a --uf2-family value: a short_name of UF2Families (case
// does not matter, as uf2conv.py upper-cases it) or a number, decimal or 0x-hex,
// that fits 32 bits. Zero is "no family" and is refused here: leave the flag out.
func ParseUF2Family(s string) (uint32, error) {
	for _, f := range UF2Families {
		if strings.EqualFold(f.Name, s) {
			return f.ID, nil
		}
	}
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("%w: %q is neither a UF2 family name nor a non-zero 32-bit number", ErrFormat, s)
	}
	return uint32(v), nil
}

// UF2FamilyName is the short_name of a family ID, "" when it is not listed.
func UF2FamilyName(id uint32) string {
	for _, f := range UF2Families {
		if f.ID == id {
			return f.Name
		}
	}
	return ""
}

// UF2Options controls EncodeUF2.
type UF2Options struct {
	// Family is the family ID. Zero writes no family (flags 0, the file field 0),
	// as uf2conv.py does without --family.
	Family uint32
}

// uf2Block is one block of a plan: a payload at an address, the payload size
// the header states; the bytes between len(data) and size are zero.
type uf2Block struct {
	addr uint32
	data []byte
	size int
}

// uf2Plan lays the image out in blocks. Each segment starts a new run of blocks
// at its own address; a block carries 256 bytes, the last block of a segment is
// zero-padded to 256 as uf2conv.py does, unless that would write past the start
// of the next segment or past 4 GiB, in which case it is padded to a multiple of
// 4 only. A segment must start on a multiple of 4 (ErrFormat) and fit 32 bits
// (ErrAddrOverflow), and the file must fit an int (ErrTooLarge).
func uf2Plan(im *Image) ([]uf2Block, error) {
	var blocks []uf2Block
	for i, s := range im.Segments {
		if len(s.Data) == 0 {
			continue
		}
		if s.Addr%4 != 0 {
			return nil, fmt.Errorf("%w: UF2 target address 0x%x is not a multiple of 4", ErrFormat, s.Addr)
		}
		if s.End() > 1<<32 {
			return nil, fmt.Errorf("%w: UF2 has 32-bit addresses, 0x%x..0x%x does not fit", ErrAddrOverflow, s.Addr, s.End())
		}
		limit := uint64(1) << 32
		if i+1 < len(im.Segments) {
			limit = im.Segments[i+1].Addr
		}
		for off := 0; off < len(s.Data); off += uf2Payload {
			chunk := s.Data[off:min(off+uf2Payload, len(s.Data))]
			addr := s.Addr + uint64(off)
			size := uf2Payload
			if len(chunk) < uf2Payload && addr+uf2Payload > limit {
				size = (len(chunk) + 3) &^ 3
			}
			blocks = append(blocks, uf2Block{addr: uint32(addr), data: chunk, size: size})
			if uint64(len(blocks)) > math.MaxUint32 || uint64(len(blocks))*uf2BlockSize > maxText {
				return nil, fmt.Errorf("%w: more than %d UF2 blocks", ErrTooLarge, len(blocks)-1)
			}
		}
	}
	return blocks, nil
}

// EncodeUF2 writes the image as a UF2 file. The start address is not recorded:
// the format has none. See uf2Plan for the layout; the output is empty for an
// empty image.
func EncodeUF2(im *Image, opts UF2Options) ([]byte, error) {
	blocks, err := uf2Plan(im)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(blocks)*uf2BlockSize)
	var flags uint32
	if opts.Family != 0 {
		flags = uf2FlagFamily
	}
	le := binary.LittleEndian
	for i, b := range blocks {
		blk := out[i*uf2BlockSize : (i+1)*uf2BlockSize]
		le.PutUint32(blk[0:], uf2Magic0)
		le.PutUint32(blk[4:], uf2Magic1)
		le.PutUint32(blk[8:], flags)
		le.PutUint32(blk[12:], b.addr)
		le.PutUint32(blk[16:], uint32(b.size))
		le.PutUint32(blk[20:], uint32(i))
		le.PutUint32(blk[24:], uint32(len(blocks)))
		le.PutUint32(blk[28:], opts.Family)
		copy(blk[32:], b.data)
		le.PutUint32(blk[uf2BlockSize-4:], uf2MagicE)
	}
	return out, nil
}

// DecodeUF2 reads a UF2 file into an Image. Every block is checked: the three
// magic numbers, the payload size (at most 476), the total block count (it must
// be the number of blocks in the file) and the block number (0, 1, 2, ...). The
// family ID, when the blocks carry one, must be the same in all of them and is
// returned in Image.Family. A block flagged "not main flash" or as a file
// container, or with a flag the format does not define, is refused (ErrFormat):
// dropping it silently would make a different image. The MD5 and extension-tag
// flags are accepted and the bytes after the payload ignored.
//
// Refusals: ErrSyntax (not a UF2 file, a block that is damaged or out of
// sequence), ErrFormat (the flags above, two families), ErrAddrOverflow (a
// payload that passes 4 GiB), ErrOverlap (two blocks write one address),
// ErrTooLarge (more data than opts.MaxSize).
func DecodeUF2(data []byte, opts DecodeOptions) (*Image, error) {
	if len(data) == 0 || len(data)%uf2BlockSize != 0 {
		return nil, fmt.Errorf("uf2: %w: %d bytes is not a whole number of %d-byte blocks", ErrSyntax, len(data), uf2BlockSize)
	}
	n := len(data) / uf2BlockSize
	c := newCollector(opts.MaxSize)
	var (
		family    uint32
		hasFamily bool
	)
	le := binary.LittleEndian
	for i := 0; i < n; i++ {
		blk := data[i*uf2BlockSize : (i+1)*uf2BlockSize]
		fail := func(why string) error { return fmt.Errorf("uf2 block %d: %w: %s", i, ErrSyntax, why) }
		if le.Uint32(blk[0:]) != uf2Magic0 || le.Uint32(blk[4:]) != uf2Magic1 || le.Uint32(blk[uf2BlockSize-4:]) != uf2MagicE {
			return nil, fail("bad magic number")
		}
		flags, addr, size := le.Uint32(blk[8:]), uint64(le.Uint32(blk[12:])), uint64(le.Uint32(blk[16:]))
		if flags&^uf2KnownFlags != 0 {
			return nil, fmt.Errorf("uf2 block %d: %w: flags 0x%x are not defined", i, ErrFormat, flags)
		}
		if flags&(uf2FlagNotMain|uf2FlagFileCont) != 0 {
			return nil, fmt.Errorf("uf2 block %d: %w: flags 0x%x mark a block that is not main flash content", i, ErrFormat, flags)
		}
		if size > uf2DataMax {
			return nil, fail(fmt.Sprintf("payload of %d bytes, at most %d", size, uf2DataMax))
		}
		if no := le.Uint32(blk[20:]); no != uint32(i) {
			return nil, fail(fmt.Sprintf("block number %d, expected %d", no, i))
		}
		if total := le.Uint32(blk[24:]); uint64(total) != uint64(n) {
			return nil, fail(fmt.Sprintf("the block says the file has %d blocks, it has %d", total, n))
		}
		if flags&uf2FlagFamily != 0 {
			id := le.Uint32(blk[28:])
			switch {
			case i == 0:
				family, hasFamily = id, true
			case !hasFamily:
				return nil, fail("a family ID after blocks that have none")
			case id != family:
				return nil, fmt.Errorf("uf2 block %d: %w: family 0x%08x after 0x%08x: one image has one family", i, ErrFormat, id, family)
			}
		} else if hasFamily {
			return nil, fail("no family ID after blocks that have one")
		}
		if addr+size > 1<<32 {
			return nil, fmt.Errorf("uf2 block %d: %w: %d bytes at 0x%x", i, ErrAddrOverflow, size, addr)
		}
		if err := c.add(addr, blk[32:32+size]); err != nil {
			return nil, err
		}
	}
	im, err := c.image()
	if err != nil {
		return nil, err
	}
	if hasFamily {
		im.Family = family
	}
	return im, nil
}

// VerifyUF2 reads the UF2 file in written and compares it with what EncodeUF2
// makes of im: the same image once the zero padding of the last block of each
// run is applied to both, and the same family.
func VerifyUF2(written []byte, im *Image, opts UF2Options) error {
	want, err := EncodeUF2(im, opts)
	if err != nil {
		return mismatch("%v", err)
	}
	if bytes.Equal(want, written) {
		return nil
	}
	got, err := DecodeUF2(written, DecodeOptions{MaxSize: math.MaxInt32})
	if err != nil {
		return mismatch("%v", err)
	}
	wantIm, err := DecodeUF2(want, DecodeOptions{MaxSize: math.MaxInt32})
	if err != nil {
		return mismatch("%v", err)
	}
	if got.Family != opts.Family {
		return mismatch("the family is 0x%08x, wanted 0x%08x", got.Family, opts.Family)
	}
	if err := CompareImages(wantIm, got); err != nil {
		return err
	}
	return mismatch("the file is not the %d bytes that were written", len(want))
}
