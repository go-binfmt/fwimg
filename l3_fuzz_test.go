package fwimg

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// FuzzVerifyFlat builds an image from arbitrary bytes (segments of 1 to 9
// bytes, holes of at least one) and holds VerifyFlat to its contract: the
// image's own flat file verifies, any one byte changed is refused with
// ErrVerify, and so is a file cut short or one grown.
func FuzzVerifyFlat(f *testing.F) {
	f.Add([]byte("abcdefghij"), byte(0))
	f.Add([]byte{0, 1, 0xff, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9}, byte(0xA5))
	f.Add([]byte{}, byte(1))
	f.Fuzz(func(t *testing.T, data []byte, pad byte) {
		im := &Image{}
		addr := uint64(0x1000)
		for pos := 0; pos < len(data); {
			n := int(data[pos])%9 + 1
			hole := uint64(data[pos]>>5) + 1
			pos++
			n = min(n, len(data)-pos)
			if n == 0 {
				break
			}
			im.Segments = append(im.Segments, Segment{Addr: addr, Data: data[pos : pos+n]})
			addr += uint64(n) + hole
			pos += n
		}
		flat, _, err := im.Flat(pad, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyFlat(bytes.NewReader(flat), im, pad); err != nil {
			t.Fatalf("an image's own flat file: %v", err)
		}
		if len(flat) == 0 {
			return
		}
		bad := bytes.Clone(flat)
		bad[int(pad)%len(bad)] ^= 1 << (pad % 8)
		if err := VerifyFlat(bytes.NewReader(bad), im, pad); !errors.Is(err, ErrVerify) {
			t.Fatalf("a flipped byte: %v", err)
		}
		if err := VerifyFlat(bytes.NewReader(flat[:len(flat)-1]), im, pad); !errors.Is(err, ErrVerify) {
			t.Fatalf("a short file: %v", err)
		}
		if err := VerifyFlat(bytes.NewReader(append(bytes.Clone(flat), pad)), im, pad); !errors.Is(err, ErrVerify) {
			t.Fatalf("a long file: %v", err)
		}
	})
}

// FuzzParseRegion: no panic, and a region it accepts has a name, a size, an end
// that does not wrap, and reads back as itself.
func FuzzParseRegion(f *testing.F) {
	for _, s := range []string{"FLASH=0x8000000:1M", "RAM=0x20000000:128k", "A=0:1", "A=1:0", "=1:2", "A=0xffffffffffffffff:1", "A=0:18446744073709551615K", "a b=1:2", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRegion(s)
		if err != nil {
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("%q: %v is not ErrFormat", s, err)
			}
			return
		}
		if r.Name == "" || strings.ContainsAny(r.Name, " \t") || r.Size == 0 || r.End() < r.Start {
			t.Fatalf("%q accepted as %+v", s, r)
		}
		back, err := ParseRegion(fmt.Sprintf("%s=%d:%d", r.Name, r.Start, r.Size))
		if err != nil || back != r {
			t.Fatalf("%q = %+v reads back as %+v, %v", s, r, back, err)
		}
	})
}
