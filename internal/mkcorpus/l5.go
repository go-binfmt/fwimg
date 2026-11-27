package main

import (
	"bytes"
	"encoding/binary"
	"path/filepath"

	"github.com/go-binfmt/fwimg"
)

// The L5 seeds: UF2, Verilog hex and compressed uImage. A Verilog seed starts
// with the configuration byte FuzzVerilog reads (verilogConfig), then the text.

// verilogConfig is the data width (1 to 8) and byte order a Verilog fuzz input
// asks for in its first byte: the low three bits are the width minus one, the
// high bit the big-endian flag.
func verilogConfig(b byte) fwimg.VerilogOptions {
	return fwimg.VerilogOptions{DataWidth: int(b&7) + 1, BigEndian: b&0x80 != 0}
}

func runL5(root string) error {
	for name, seeds := range map[string]map[string][]byte{
		"FuzzUF2":        uf2Seeds(),
		"FuzzVerilog":    verilogSeeds(),
		"FuzzUImageComp": uimageCompSeeds(),
	} {
		if err := write(filepath.Join(root, name), seeds); err != nil {
			return err
		}
	}
	return nil
}

func uf2Seeds() map[string][]byte {
	enc := func(im *fwimg.Image, fam uint32) []byte {
		return must(fwimg.EncodeUF2(im, fwimg.UF2Options{Family: fam}))
	}
	one := must2(fwimg.RawImage([]byte("hello uf2"), 0x10000000))
	big := must2(fwimg.RawImage(bytes.Repeat([]byte{0xA5, 0x5A, 0x00}, 200), 0x2000))
	valid := enc(one, 0xe48bff56)
	twoSeg := &fwimg.Image{Segments: []fwimg.Segment{
		{Addr: 0x1000, Data: []byte("first")},
		{Addr: 0x2000, Data: []byte("second")},
	}}
	clone := func(b []byte, f func([]byte)) []byte { c := append([]byte(nil), b...); f(c); return c }
	return map[string][]byte{
		"valid-one-block-family": valid,
		"valid-no-family":        enc(one, 0),
		"valid-three-blocks":     enc(big, 0x1c5f21b0),
		"valid-two-segments":     enc(twoSeg, 0),
		"truncated":              valid[:511],
		"bad-magic-start":        clone(valid, func(c []byte) { c[0] ^= 1 }),
		"bad-magic-end":          clone(valid, func(c []byte) { c[508] ^= 1 }),
		"payload-too-large":      clone(valid, func(c []byte) { binary.LittleEndian.PutUint32(c[16:], 477) }),
		"flag-file-container":    clone(valid, func(c []byte) { binary.LittleEndian.PutUint32(c[8:], 0x1000) }),
		"flag-not-main-flash":    clone(valid, func(c []byte) { binary.LittleEndian.PutUint32(c[8:], 0x2001) }),
		"unknown-flag":           clone(valid, func(c []byte) { binary.LittleEndian.PutUint32(c[8:], 0x2000|0x10000) }),
		"block-number-gap":       clone(enc(big, 0), func(c []byte) { binary.LittleEndian.PutUint32(c[512+20:], 7) }),
		"count-too-large":        clone(valid, func(c []byte) { binary.LittleEndian.PutUint32(c[24:], 0xFFFFFFFF) }),
		"address-wraps": clone(valid, func(c []byte) {
			binary.LittleEndian.PutUint32(c[12:], 0xFFFFFFF0)
			binary.LittleEndian.PutUint32(c[16:], 256)
		}),
	}
}

func must2(im *fwimg.Image, err error) *fwimg.Image {
	if err != nil {
		panic(err)
	}
	return im
}

func verilogSeeds() map[string][]byte {
	// width 1: config 0x00; width 2 little-endian: 0x01; width 4 big: 0x83.
	return map[string][]byte{
		"valid-width1":           []byte("\x00@00000000\r\n00 01 02 03\r\n"),
		"valid-width4-little":    []byte("\x03@00000010\r\n04030201 08070605 0c0b0a09\r\n"),
		"valid-width2-big-space": []byte("\x81@00000000\r\n0102 0304 \r\n"),
		"valid-comments":         []byte("\x00// header\n/* block\ncomment */ @10 A_A BB\n// tail\n"),
		"valid-no-address":       []byte("\x00DE AD BE EF\n"),
		"valid-short-tail":       []byte("\x03@0\n04030201 06\n"),
		"valid-empty":            []byte("\x00"),
		"bad-digit":              []byte("\x00@0\nXX\n"),
		"unterminated-comment":   []byte("\x00/* never closed"),
		"odd-digits":             []byte("\x00@0\nABC\n"),
		"token-wider-than-word":  []byte("\x00@0\nAABB\n"),
		"overlap":                []byte("\x00@0\n01 02\n@1\n03\n"),
		"address-overflow":       []byte("\x07@FFFFFFFFFFFFFFFF\n01\n"),
		"empty-address":          []byte("\x00@\n"),
		"long-token":             []byte("\x07@0\n00112233445566778899AABBCCDDEEFF00\n"),
	}
}

func uimageCompSeeds() map[string][]byte {
	img := func(raw []byte, comp byte) []byte {
		p := must(fwimg.CompressPayload(raw, comp))
		return must(fwimg.UImage(p, fwimg.UImageOptions{Load: 0x8000, Entry: 0x8000, Name: "c", Comp: comp, Time: 1700000000}))
	}
	text := bytes.Repeat([]byte("firmware "), 50)
	badGzip := must(fwimg.UImage([]byte("not gzip"), fwimg.UImageOptions{Comp: fwimg.CompGzip}))
	badLZ4 := must(fwimg.UImage([]byte("not lz4 at all"), fwimg.UImageOptions{Comp: fwimg.CompLZ4}))
	unknown := must(fwimg.UImage([]byte("zz"), fwimg.UImageOptions{Comp: 99}))
	zeros := make([]byte, 1<<20)
	return map[string][]byte{
		"valid-gzip":          img(text, fwimg.CompGzip),
		"valid-lz4":           img(text, fwimg.CompLZ4),
		"valid-gzip-empty":    img(nil, fwimg.CompGzip),
		"valid-none":          img(text, fwimg.CompNone),
		"bad-gzip":            badGzip,
		"bad-lz4":             badLZ4,
		"unknown-compression": unknown,
		"bomb-gzip":           img(zeros, fwimg.CompGzip),
		"bomb-lz4":            img(zeros, fwimg.CompLZ4),
	}
}
