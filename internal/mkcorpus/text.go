package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-binfmt/fwimg"
)

// write stores seeds in dir in the fuzz corpus format, one file each.
func write(dir string, seeds map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, b := range seeds {
		body := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", b)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// runText writes the FuzzIHEX, FuzzSREC and FuzzUImage seeds under root.
func runText(root string) error {
	for name, seeds := range map[string]map[string][]byte{
		"FuzzIHEX":   ihexSeeds(),
		"FuzzSREC":   srecSeeds(),
		"FuzzUImage": uimageSeeds(),
	} {
		if err := write(filepath.Join(root, name), seeds); err != nil {
			return err
		}
	}
	return nil
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func ihexSeeds() map[string][]byte {
	return map[string][]byte{
		"valid-one-record":      must(fwimg.IHEX(0x100, []byte("hello"), 16)),
		"valid-crosses-64KiB":   must(fwimg.IHEX(0xFFF0, []byte(strings.Repeat("x", 40)), 16)),
		"valid-top-of-4GiB":     must(fwimg.IHEX(0xFFFFFFF0, []byte("0123456789abcdef"), 16)),
		"valid-empty":           []byte(":00000001FF\n"),
		"valid-segment-and-cs":  []byte(":020000021000EC\n:0400000300100000E9\n:01000000AA55\n:00000001FF\n"),
		"no-eof":                []byte(":0100000041BE\n"),
		"bad-checksum":          []byte(":0100000041BF\n:00000001FF\n"),
		"overlap":               []byte(":03000000010203F7\n:0100020009F4\n:00000001FF\n"),
		"past-4GiB":             []byte(":02000004FFFFFC\n:02FFFF000102FD\n:00000001FF\n"),
		"data-after-eof":        []byte(":00000001FF\n:0100000041BE\n"),
		"long-line":             []byte(":" + strings.Repeat("00", 300) + "\n:00000001FF\n"),
		"alternating-addresses": alternatingIHEX(),
	}
}

func alternatingIHEX() []byte {
	var b strings.Builder
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&b, ":01%04X0001%02X\n", 2*i, byte(-(1 + byte(2*i>>8) + byte(2*i) + 1)))
	}
	b.WriteString(":00000001FF\n")
	return []byte(b.String())
}

func srecSeeds() map[string][]byte {
	return map[string][]byte{
		"valid-one-record":      must(fwimg.SREC(0x100, []byte("hello"), "nm", 0x100, 16)),
		"valid-top-of-4GiB":     must(fwimg.SREC(0xFFFFFFF0, []byte("0123456789abcdef"), "", 0, 16)),
		"valid-empty":           []byte("S9030000FC\n"),
		"valid-s1-s2-and-count": []byte("S1040000AA51\nS20500010055A4\nS5030002FA\nS9030000FC\n"),
		"no-termination":        []byte("S1040000AA51\n"),
		"bad-checksum":          []byte("S1040000AA50\nS9030000FC\n"),
		"overlap":               []byte("S10500000102F7\nS10401000103F7\nS9030000FC\n"),
		"s4-reserved":           []byte("S4030000FC\nS9030000FC\n"),
		"data-after-end":        []byte("S9030000FC\nS1040000AA51\n"),
		"long-line":             []byte("S1" + strings.Repeat("00", 300) + "\nS9030000FC\n"),
	}
}

func uimageSeeds() map[string][]byte {
	img := func(p []byte, o fwimg.UImageOptions) []byte { return must(fwimg.UImage(p, o)) }
	multi := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, 3), 2), 0)
	multi = append(multi, 'a', 'b', 'c', 0, 'd', 'e', 0, 0)
	noEnd := img(binary.BigEndian.AppendUint32(nil, 1), fwimg.UImageOptions{Type: fwimg.TypeMulti})
	hugeSize := img([]byte("abc"), fwimg.UImageOptions{})
	binary.BigEndian.PutUint32(hugeSize[12:], 0xFFFFFFFF)
	badData := img([]byte("abc"), fwimg.UImageOptions{})
	badData[64] ^= 1
	return map[string][]byte{
		"valid-kernel":     img([]byte("kernel payload"), fwimg.UImageOptions{Load: 0x8000, Entry: 0x8040, Name: "k", Time: 1700000000}),
		"valid-empty":      img(nil, fwimg.UImageOptions{}),
		"valid-multi":      img(multi, fwimg.UImageOptions{Type: fwimg.TypeMulti, Name: "m"}),
		"multi-no-end":     noEnd,
		"size-too-big":     hugeSize,
		"bad-data-crc":     badData,
		"header-only-stub": img(nil, fwimg.UImageOptions{})[:40],
	}
}
