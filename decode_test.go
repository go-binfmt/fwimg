package fwimg

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// ih builds one Intel HEX line, with its checksum computed here and not by
// the encoder under test.
func ih(typ byte, addr uint16, data ...byte) string {
	b := append([]byte{byte(len(data)), byte(addr >> 8), byte(addr), typ}, data...)
	var s byte
	for _, x := range b {
		s += x
	}
	return fmt.Sprintf(":%X%02X\n", b, -s)
}

// sr builds one S-record line: al address bytes, the checksum computed here.
func sr(typ int, al int, addr uint32, data ...byte) string {
	b := []byte{byte(al + len(data) + 1)}
	for i := al - 1; i >= 0; i-- {
		b = append(b, byte(addr>>(8*i)))
	}
	b = append(b, data...)
	var s byte
	for _, x := range b {
		s += x
	}
	return fmt.Sprintf("S%d%X%02X\n", typ, b, ^s)
}

const ihEOF = ":00000001FF\n"

func segs(im *Image) string {
	var parts []string
	for _, s := range im.Segments {
		parts = append(parts, fmt.Sprintf("%x:%q", s.Addr, s.Data))
	}
	return strings.Join(parts, " ")
}

func TestDecodeIHEX_Records(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		want  string
		entry uint64
		has   bool
	}{
		{"one record", ih(0, 0x100, 'a', 'b') + ihEOF, `100:"ab"`, 0, false},
		{"empty file with only EOF", ihEOF, ``, 0, false},
		{"lower case digits and CRLF", strings.ToLower(strings.ReplaceAll(ih(0, 0x10, 'x')+ihEOF, "\n", "\r\n")), `10:"x"`, 0, false},
		{"blank lines and no final newline", "\n\n" + ih(0, 0, 1) + "\r\n" + strings.TrimSuffix(ihEOF, "\n"), "0:\"\\x01\"", 0, false},
		{"contiguous records merge", ih(0, 0, 'a') + ih(0, 1, 'b') + ihEOF, `0:"ab"`, 0, false},
		{"records out of order are sorted", ih(0, 4, 'c', 'd') + ih(0, 0, 'a', 'b') + ihEOF, `0:"ab" 4:"cd"`, 0, false},
		{"out of order and adjacent merge", ih(0, 2, 'c') + ih(0, 0, 'a', 'b') + ihEOF, `0:"abc"`, 0, false},
		{"zero length data record", ih(0, 5) + ihEOF, ``, 0, false},
		{"linear base", ih(4, 0, 0x08, 0x00) + ih(0, 0x20, 'q') + ihEOF, `8000020:"q"`, 0, false},
		{"linear record crosses 64 KiB and continues", ih(4, 0, 0, 1) + ih(0, 0xFFFF, 'a', 'b') + ihEOF, `1ffff:"ab"`, 0, false},
		{"initial base crosses 64 KiB and continues", ih(0, 0xFFFF, 'a', 'b') + ihEOF, `ffff:"ab"`, 0, false},
		{"segment base", ih(2, 0, 0x10, 0x00) + ih(0, 0x20, 'q') + ihEOF, `10020:"q"`, 0, false},
		{"segment record wraps inside its 64 KiB", ih(2, 0, 0x10, 0x00) + ih(0, 0xFFFF, 'a', 'b', 'c') + ihEOF, `10000:"bc" 1ffff:"a"`, 0, false},
		{"linear after segment", ih(2, 0, 0x10, 0) + ih(4, 0, 0, 2) + ih(0, 0xFFFF, 'a', 'b') + ihEOF, `2ffff:"ab"`, 0, false},
		{"type 05 start", ih(5, 0, 0x08, 0, 0x01, 0x00) + ih(0, 0, 1) + ihEOF, "0:\"\\x01\"", 0x08000100, true},
		{"type 03 start is CS*16+IP", ih(3, 0, 0x10, 0x00, 0x00, 0x20) + ihEOF, ``, 0x10020, true},
		{"top of the address space", ih(4, 0, 0xFF, 0xFF) + ih(0, 0xFFFE, 'a', 'b') + ihEOF, `fffffffe:"ab"`, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			im, err := DecodeIHEX([]byte(c.text), DecodeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := segs(im); got != c.want {
				t.Errorf("segments %s, want %s", got, c.want)
			}
			if im.Entry != c.entry || im.HasEntry != c.has {
				t.Errorf("entry %x/%v, want %x/%v", im.Entry, im.HasEntry, c.entry, c.has)
			}
		})
	}
}

// A decoder that is handed hostile text must refuse, not crash. When a guard
// is removed the code after it crashes; reporting that as a failed assertion
// (not a dead test binary) is what lets a mutation of the guard be told from
// luck: the test names the case that the guard exists for.
func guarded(t *testing.T, decode func() (*Image, error)) (im *Image, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the decoder crashed instead of refusing: %v", r)
		}
	}()
	return decode()
}

func guardedIHEX(t *testing.T, text string) (*Image, error) {
	t.Helper()
	return guarded(t, func() (*Image, error) { return DecodeIHEX([]byte(text), DecodeOptions{}) })
}

func guardedSREC(t *testing.T, text string) (*Image, error) {
	t.Helper()
	return guarded(t, func() (*Image, error) { return DecodeSREC([]byte(text), DecodeOptions{}) })
}

func TestDecodeIHEX_Refusals(t *testing.T) {
	good := ih(0, 0, 1)
	bad := func(s string, i int) string { // flip one hex digit of a line
		b := []byte(s)
		if b[i] == '0' {
			b[i] = '1'
		} else {
			b[i] = '0'
		}
		return string(b)
	}
	cases := []struct {
		name string
		text string
		want error
	}{
		{"no EOF record", good, ErrSyntax},
		{"empty input", "", ErrSyntax},
		{"data after EOF", ihEOF + good, ErrSyntax},
		{"EOF with data, last", ih(1, 0, 1), ErrSyntax},
		{"EOF with data, then another EOF", ih(1, 0, 1) + ihEOF, ErrSyntax},
		{"no colon", "0" + good[1:] + ihEOF, ErrSyntax},
		{"odd length", good[:len(good)-2] + "\n" + ihEOF, ErrSyntax},
		{"too short", ":0000\n" + ihEOF, ErrSyntax},
		{"too long", ":" + strings.Repeat("00", 261) + "\n" + ihEOF, ErrSyntax},
		{"not hex, low nibble", ":0G000001FF\n", ErrSyntax},
		{"not hex, high nibble", ":G0000001FF\n", ErrSyntax},
		{"count does not match", ":01000000FF\n" + ihEOF, ErrSyntax},
		{"bad checksum", bad(good, 9) + ihEOF, ErrChecksum},
		{"unknown type", ih(6, 0) + ihEOF, ErrSyntax},
		{"segment record of 1 byte", ih(2, 0, 1) + ihEOF, ErrSyntax},
		{"linear record of 3 bytes", ih(4, 0, 1, 2, 3) + ihEOF, ErrSyntax},
		{"start record of 2 bytes", ih(5, 0, 1, 2) + ihEOF, ErrSyntax},
		{"second type 05", ih(5, 0, 0, 0, 0, 1) + ih(5, 0, 0, 0, 0, 2) + ihEOF, ErrSyntax},
		{"type 03 then 05", ih(3, 0, 0, 0, 0, 1) + ih(5, 0, 0, 0, 0, 2) + ihEOF, ErrSyntax},
		{"past 4 GiB", ih(4, 0, 0xFF, 0xFF) + ih(0, 0xFFFF, 1, 2) + ihEOF, ErrAddrOverflow},
		{"overlap", ih(0, 0, 1, 2, 3) + ih(0, 2, 9) + ihEOF, ErrOverlap},
		{"overlap, same record twice", ih(0, 0, 1) + ih(0, 0, 1) + ihEOF, ErrOverlap},
		{"overlap through the segment wrap", ih(2, 0, 0, 1) + ih(0, 0xFFFF, 1, 2) + ih(0, 0, 3) + ihEOF, ErrOverlap},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			im, err := guardedIHEX(t, c.text)
			if !errors.Is(err, c.want) || im != nil {
				t.Fatalf("image %v, err = %v, want %v", im, err, c.want)
			}
		})
	}
}

func TestDecodeIHEX_ReportsTheLine(t *testing.T) {
	_, err := DecodeIHEX([]byte(ih(0, 0, 1)+"\n\n"+ih(6, 0)+ihEOF), DecodeOptions{})
	if err == nil || !strings.Contains(err.Error(), "ihex line 4") {
		t.Errorf("err = %v, want it to name line 4", err)
	}
}

func TestDecodeSREC_Records(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		want  string
		entry uint64
		name0 string
	}{
		{"S1", sr(0, 2, 0, 'h', 'i') + sr(1, 2, 0x100, 'a', 'b') + sr(5, 2, 1) + sr(9, 2, 0x100), `100:"ab"`, 0x100, "hi"},
		{"S2", sr(2, 3, 0x123456, 'a') + sr(6, 3, 1) + sr(8, 3, 0x123456), `123456:"a"`, 0x123456, ""},
		{"S3", sr(3, 4, 0xFFFFFFFE, 'a', 'b') + sr(7, 4, 0), `fffffffe:"ab"`, 0, ""},
		{"empty", sr(7, 4, 0x20), ``, 0x20, ""},
		{"lower case and CRLF", strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(strings.ReplaceAll(sr(1, 2, 0x10, 'x', 'y')+sr(9, 2, 0), "\n", "\r\n")), "s1", "S1"), "s9", "S9"), `10:"xy"`, 0, ""},
		{"blank lines, no final newline", "\n" + sr(1, 2, 0, 1) + "\n" + strings.TrimSuffix(sr(9, 2, 4), "\n"), "0:\"\\x01\"", 4, ""},
		{"out of order", sr(1, 2, 8, 'c') + sr(1, 2, 0, 'a') + sr(9, 2, 0), `0:"a" 8:"c"`, 0, ""},
		{"mixed S1 S2 S3", sr(1, 2, 0, 'a') + sr(2, 3, 1, 'b') + sr(3, 4, 2, 'c') + sr(5, 2, 3) + sr(7, 4, 0), `0:"abc"`, 0, ""},
		{"S5 after S0 only", sr(0, 2, 0) + sr(5, 2, 0) + sr(9, 2, 0), ``, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			im, err := DecodeSREC([]byte(c.text), DecodeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := segs(im); got != c.want {
				t.Errorf("segments %s, want %s", got, c.want)
			}
			if im.Entry != c.entry || !im.HasEntry || im.Name != c.name0 {
				t.Errorf("entry %x/%v name %q, want %x name %q", im.Entry, im.HasEntry, im.Name, c.entry, c.name0)
			}
		})
	}
}

func TestDecodeSREC_Refusals(t *testing.T) {
	end := sr(9, 2, 0)
	data := sr(1, 2, 0, 'a')
	bad := strings.Replace(data, "61", "62", 1)
	cases := []struct {
		name string
		text string
		want error
	}{
		{"no termination", data, ErrSyntax},
		{"empty input", "", ErrSyntax},
		{"record after termination", end + data, ErrSyntax},
		{"S0 not first", data + sr(0, 2, 0) + end, ErrSyntax},
		{"second S0", sr(0, 2, 0) + sr(0, 2, 0) + end, ErrSyntax},
		{"no S", "T" + data[1:] + end, ErrSyntax},
		{"no digit", "SX" + data[2:] + end, ErrSyntax},
		{"one byte line", "S\n" + end, ErrSyntax},
		{"S4 is reserved", sr(4, 2, 0) + end, ErrSyntax},
		{"S4 with no address and nothing after it", "S401FE\n", ErrSyntax},
		{"odd length", data[:len(data)-2] + "\n" + end, ErrSyntax},
		{"too short for its address", "S1030000\n" + end, ErrSyntax},
		{"too long", "S1" + strings.Repeat("00", 257) + "\n" + end, ErrSyntax},
		{"not hex", "S1G50000" + data[8:] + end, ErrSyntax},
		{"count does not match", "S105000000\n" + end, ErrSyntax},
		{"bad checksum", bad + end, ErrChecksum},
		{"S3 past 4 GiB", sr(3, 4, 0xFFFFFFFF, 1, 2) + sr(7, 4, 0), ErrAddrOverflow},
		{"overlap", sr(1, 2, 0, 1, 2) + sr(1, 2, 1, 3) + end, ErrOverlap},
		{"count record with data", sr(5, 2, 0, 1) + end, ErrSyntax},
		{"count too high", data + sr(5, 2, 2) + end, ErrSyntax},
		{"count too low", data + sr(5, 2, 0) + end, ErrSyntax},
		{"termination with data", sr(9, 2, 0, 1), ErrSyntax},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			im, err := guardedSREC(t, c.text)
			if !errors.Is(err, c.want) || im != nil {
				t.Fatalf("image %v, err = %v, want %v", im, err, c.want)
			}
		})
	}
	_, err := DecodeSREC([]byte(data+"\n"+sr(5, 2, 9)+end), DecodeOptions{})
	if err == nil || !strings.Contains(err.Error(), "srec line 3") {
		t.Errorf("err = %v, want it to name line 3", err)
	}
}

// decode(encode(x)) == x, through the encoders of this package.
func TestDecodeRoundTrip(t *testing.T) {
	for _, base := range []uint32{0, 0x1234, 0xFFF0, 0x08000000, 0xFFFFFF00} {
		in := counting(0x240)
		if uint64(base)+uint64(len(in)) > 1<<32 {
			in = in[:0x100]
		}
		for _, per := range []int{1, 7, 16, 250} {
			text, err := SREC(base, in, "n", base+1, per)
			if err != nil {
				t.Fatal(err)
			}
			im, err := DecodeSREC(text, DecodeOptions{})
			if err != nil {
				t.Fatalf("srec %x/%d: %v", base, per, err)
			}
			if len(im.Segments) != 1 || im.Segments[0].Addr != uint64(base) || !bytes.Equal(im.Segments[0].Data, in) || im.Entry != uint64(base)+1 || im.Name != "n" {
				t.Fatalf("srec %x/%d: %s entry %x name %q", base, per, segs(im), im.Entry, im.Name)
			}
			text, err = IHEX(base, in, per)
			if err != nil {
				t.Fatal(err)
			}
			im, err = DecodeIHEX(text, DecodeOptions{})
			if err != nil {
				t.Fatalf("ihex %x/%d: %v", base, per, err)
			}
			if len(im.Segments) != 1 || im.Segments[0].Addr != uint64(base) || !bytes.Equal(im.Segments[0].Data, in) {
				t.Fatalf("ihex %x/%d: %s", base, per, segs(im))
			}
		}
	}
}

func TestEncodeImage_SparseSegmentsAndStart(t *testing.T) {
	im := &Image{
		Segments: []Segment{{Addr: 0x1000, Data: []byte("ab")}, {Addr: 0x20000, Data: []byte("cd")}},
		Entry:    0x1004, HasEntry: true,
	}
	text, err := EncodeSREC(im, "x", 0)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSREC(text, DecodeOptions{})
	if err != nil || segs(back) != segs(im) || back.Entry != 0x1004 {
		t.Fatalf("srec: %v %s entry %x", err, segs(back), back.Entry)
	}
	text, err = EncodeIHEX(im, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), ":0400000500001004") {
		t.Errorf("no type 05 record:\n%s", text)
	}
	back, err = DecodeIHEX(text, DecodeOptions{})
	if err != nil || segs(back) != segs(im) || back.Entry != 0x1004 || !back.HasEntry {
		t.Fatalf("ihex: %v %s entry %x", err, segs(back), back.Entry)
	}
	// No start record for a start address of 0, as objcopy; S7 says 0.
	im.Entry = 0
	text, _ = EncodeIHEX(im, 0)
	if strings.Contains(string(text), ":04000005") {
		t.Errorf("a type 05 record for the start address 0:\n%s", text)
	}
	im.HasEntry = false
	if text, _ = EncodeSREC(im, "", 0); !strings.Contains(string(text), "S70500000000FA") {
		t.Errorf("S7 for no start:\n%s", text)
	}
	for _, e := range []func(*Image) ([]byte, error){
		func(i *Image) ([]byte, error) { return EncodeSREC(i, "", 0) },
		func(i *Image) ([]byte, error) { return EncodeIHEX(i, 0) },
	} {
		big := &Image{Entry: 1 << 32, HasEntry: true}
		if _, err := e(big); !errors.Is(err, ErrAddrOverflow) {
			t.Errorf("start above 32 bits: %v", err)
		}
		far := &Image{Segments: []Segment{{Addr: 1 << 33, Data: []byte{1}}}}
		if _, err := e(far); !errors.Is(err, ErrAddrOverflow) {
			t.Errorf("segment above 32 bits: %v", err)
		}
		past := &Image{Segments: []Segment{{Addr: math.MaxUint64, Data: []byte{1}}}}
		if _, err := e(past); !errors.Is(err, ErrAddrOverflow) {
			t.Errorf("segment at the top of 64 bits: %v", err)
		}
	}
}

// A file of one-byte records at alternating addresses costs a run each; the
// budget counts them, so it cannot ask for memory the limit does not allow.
func TestDecode_BombsAreRefusedUnderAMemoryLimit(t *testing.T) {
	old := debug.SetMemoryLimit(256 << 20)
	defer debug.SetMemoryLimit(old)

	var ihex, srec strings.Builder
	for i := 0; i < 20000; i++ {
		ihex.WriteString(ih(0, uint16(2*i), 1))
		srec.WriteString(sr(1, 2, uint32(2*i), 1))
	}
	ihex.WriteString(ihEOF)
	srec.WriteString(sr(9, 2, 0))
	const limit = 100000 // 20000 runs * 17 = 340000
	for name, decode := range map[string]func() error{
		"ihex": func() error { _, err := DecodeIHEX([]byte(ihex.String()), DecodeOptions{MaxSize: limit}); return err },
		"srec": func() error { _, err := DecodeSREC([]byte(srec.String()), DecodeOptions{MaxSize: limit}); return err },
	} {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		err := decode()
		runtime.ReadMemStats(&after)
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: err = %v, want ErrTooLarge", name, err)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
			t.Errorf("%s: a refused file allocated %d bytes", name, grew)
		}
	}
	// A contiguous file is charged for its bytes only: exactly at the limit
	// it is accepted, one byte over it is refused.
	var one strings.Builder
	for i := 0; i < 10; i++ {
		one.WriteString(ih(0, uint16(i), byte(i)))
	}
	one.WriteString(ihEOF)
	if _, err := DecodeIHEX([]byte(one.String()), DecodeOptions{MaxSize: 10 + 16}); err != nil {
		t.Errorf("at the limit: %v", err)
	}
	if _, err := DecodeIHEX([]byte(one.String()), DecodeOptions{MaxSize: 10 + 16 - 1}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("one byte over: %v", err)
	}
	// Two bytes at the far ends of the address space: a small file whose
	// flat image is 4 GiB is refused by Flat before anything is allocated.
	text := ih(0, 0, 1) + ih(4, 0, 0xFF, 0xFF) + ih(0, 0xFFFF, 2) + ihEOF
	im, err := DecodeIHEX([]byte(text), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _, err = im.Flat(0, 0)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Flat of a 4 GiB span: %v", err)
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Errorf("a refused Flat allocated %d bytes", grew)
	}
}

func TestDecode_LimitIsCappedAtTwoGiB(t *testing.T) {
	if c := newCollector(math.MaxUint64); c.limit != math.MaxInt32 {
		t.Errorf("limit %d", c.limit)
	}
	if c := newCollector(0); c.limit != DefaultMaxSize {
		t.Errorf("default limit %d", c.limit)
	}
}

func TestImage_EmptyImageAnswersWithoutCrashing(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("an empty image crashed instead of answering: %v", r)
		}
	}()
	im := &Image{}
	if im.Base() != 0 || im.Span() != 0 || im.Len() != 0 {
		t.Errorf("base %d span %d len %d", im.Base(), im.Span(), im.Len())
	}
	if err := im.Shift(0x1000); err != nil || len(im.Segments) != 0 {
		t.Errorf("shift: %v %v", err, im.Segments)
	}
	if b, base, err := im.Flat(0, 0); b != nil || base != 0 || err != nil {
		t.Errorf("flat: %v %d %v", b, base, err)
	}
}

func TestImage_Flat(t *testing.T) {
	im := &Image{Segments: []Segment{{Addr: 0x10, Data: []byte("ab")}, {Addr: 0x14, Data: []byte("c")}}}
	if got, base, err := im.Flat(0xEE, 0); err != nil || base != 0x10 || string(got) != "ab\xee\xeec" {
		t.Errorf("padded: %q %x %v", got, base, err)
	}
	if got, _, err := im.Flat(0, 0); err != nil || string(got) != "ab\x00\x00c" {
		t.Errorf("zero pad: %q %v", got, err)
	}
	if im.Len() != 3 || im.Span() != 5 || im.Base() != 0x10 {
		t.Errorf("len %d span %d base %x", im.Len(), im.Span(), im.Base())
	}
	if _, _, err := im.Flat(0, 5); err != nil {
		t.Errorf("span at the limit: %v", err)
	}
	if _, _, err := im.Flat(0, 4); !errors.Is(err, ErrTooLarge) {
		t.Errorf("span over the limit: %v", err)
	}
	if _, _, err := im.Flat(0, math.MaxUint64); err != nil {
		t.Errorf("limit above int: %v", err)
	}
	one := &Image{Segments: []Segment{{Addr: 7, Data: []byte("xyz")}}}
	got, base, err := one.Flat(0xEE, 0)
	if err != nil || base != 7 || &got[0] != &one.Segments[0].Data[0] {
		t.Errorf("one segment is not returned as it is: %v", err)
	}
	empty := &Image{}
	if got, base, err := empty.Flat(0, 0); got != nil || base != 0 || err != nil || empty.Base() != 0 || empty.Span() != 0 || empty.Len() != 0 {
		t.Errorf("empty image: %v %v %v", got, base, err)
	}
}

func TestImage_ShiftAndRaw(t *testing.T) {
	im := &Image{Segments: []Segment{{Addr: 0x100, Data: []byte("a")}, {Addr: 0x200, Data: []byte("b")}}, Entry: 0x150, HasEntry: true}
	if err := im.Shift(0x40); err != nil || im.Segments[0].Addr != 0x40 || im.Segments[1].Addr != 0x140 || im.Entry != 0x150 {
		t.Errorf("down: %v %s entry %x", err, segs(im), im.Entry)
	}
	if err := im.Shift(0x1000); err != nil || im.Segments[1].Addr != 0x10100 && im.Segments[1].Addr != 0x1100 {
		t.Errorf("up: %v %s", err, segs(im))
	}
	if err := im.Shift(1); err != nil || im.Base() != 1 {
		t.Errorf("down again: %v", err)
	}
	if err := im.Shift(math.MaxUint64 - 0x100); !errors.Is(err, ErrAddrOverflow) {
		t.Errorf("past 2^64: %v", err)
	}
	if im.Base() != 1 {
		t.Errorf("a refused shift moved the image to %x", im.Base())
	}
	if err := (&Image{}).Shift(5); err != nil {
		t.Errorf("empty: %v", err)
	}

	if r, err := RawImage([]byte("abc"), 0x80); err != nil || segs(r) != `80:"abc"` || r.HasEntry {
		t.Errorf("raw: %v %v", r, err)
	}
	if r, err := RawImage(nil, 0x80); err != nil || len(r.Segments) != 0 {
		t.Errorf("empty raw: %v %v", r, err)
	}
	if _, err := RawImage([]byte("abc"), math.MaxUint64-1); !errors.Is(err, ErrAddrOverflow) {
		t.Errorf("raw past 2^64: %v", err)
	}
	if r, err := RawImage([]byte("abc"), math.MaxUint64-3); err != nil || r.Segments[0].End() != math.MaxUint64 {
		t.Errorf("raw at the top: %v", err)
	}
}

func TestDetect(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"\x7fELF\x02\x01", FormatELF},
		{"\x27\x05\x19\x56rest", FormatUImage},
		{":10010000", FormatIHEX},
		{"\r\n \t\n:10", FormatIHEX},
		{"S0030000FC", FormatSREC},
		{"\nS9", FormatSREC},
		{"S", ""},
		{"Sx", ""},
		{"SREC", ""},
		{"", ""},
		{"  \n", ""},
		{"\x7fEL", ""},
		{"\x27\x05\x19\x57", ""},
		{"\x27\x05\x18\x56", ""},
		{"\x27\x04\x19\x56", ""},
		{"\x26\x05\x19\x56", ""},
		{"hello", ""},
		{"\x00\x01\x02\x03", ""},
	} {
		if got := Detect([]byte(c.in)); got != c.want {
			t.Errorf("Detect(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDecode_UnsortedImagesShareNoBytes(t *testing.T) {
	// The out-of-order path copies into address order: the segments of the
	// result are separate slices with no spare capacity to append into.
	text := ih(0, 8, 'c') + ih(0, 0, 'a') + ihEOF
	im, err := DecodeIHEX([]byte(text), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if segs(im) != `0:"a" 8:"c"` {
		t.Fatalf("%s", segs(im))
	}
	if cap(im.Segments[0].Data) != 1 {
		t.Errorf("cap %d", cap(im.Segments[0].Data))
	}
}

func TestFlattenBytes_LimitAboveInt(t *testing.T) {
	img := buildELF(elf.EM_AARCH64, []seg{{Paddr: 0x1000, Off: 0x200, Filesz: 2, Memsz: 2, Data: []byte("AA")}})
	if out, _, err := FlattenBytes(img, FlattenOptions{MaxSize: math.MaxUint64}); err != nil || string(out) != "AA" {
		t.Fatalf("%q %v", out, err)
	}
}
