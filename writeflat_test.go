package fwimg

import (
	"bytes"
	"errors"
	"testing"
)

// failAfter is a writer that takes n bytes and then refuses.
type failAfter struct {
	n   int
	buf bytes.Buffer
}

var errSink = errors.New("sink full")

func (f *failAfter) Write(p []byte) (int, error) {
	if f.buf.Len()+len(p) > f.n {
		return 0, errSink
	}
	return f.buf.Write(p)
}

// WriteFlat writes what Flat returns: one segment, several with gaps smaller
// and larger than its block, a pad byte, and the empty image.
func TestWriteFlatEqualsFlat(t *testing.T) {
	seg := func(addr uint64, n int, b byte) Segment { return Segment{Addr: addr, Data: bytes.Repeat([]byte{b}, n)} }
	for _, c := range []struct {
		name string
		im   *Image
		pad  byte
	}{
		{"empty", &Image{}, 0},
		{"one", &Image{Segments: []Segment{seg(0x1000, 10, 1)}}, 0},
		{"small gap", &Image{Segments: []Segment{seg(0x1000, 10, 1), seg(0x1020, 5, 2)}}, 0xFF},
		{"zero pad", &Image{Segments: []Segment{seg(0x1000, 10, 1), seg(0x1020, 5, 2)}}, 0},
		{"gap above the block", &Image{Segments: []Segment{seg(0x1000, 10, 1), seg(0x1000+10+3*flatChunk+7, 5, 2), seg(0x1000+10+3*flatChunk+7+5+1, 3, 3)}}, 0xA5},
		{"big segments", &Image{Segments: []Segment{seg(0x1000, 2*flatChunk+9, 1), seg(0x1000+2*flatChunk+9+100, 3*flatChunk, 2)}}, 0x11},
	} {
		want, wbase, werr := c.im.Flat(c.pad, 0)
		var got bytes.Buffer
		gbase, gerr := c.im.WriteFlat(&got, c.pad, 0)
		if werr != nil || gerr != nil || wbase != gbase || !bytes.Equal(want, got.Bytes()) {
			t.Errorf("%s: WriteFlat = %d bytes, base %#x, %v; Flat = %d bytes, base %#x, %v", c.name, got.Len(), gbase, gerr, len(want), wbase, werr)
		}
	}
}

func TestWriteFlatRefusals(t *testing.T) {
	im := &Image{Segments: []Segment{{Addr: 0, Data: []byte{1}}, {Addr: 100, Data: []byte{2}}}}
	var w bytes.Buffer
	if _, err := im.WriteFlat(&w, 0, 50); !errors.Is(err, ErrTooLarge) || w.Len() != 0 {
		t.Errorf("a span over the limit: %v, %d bytes written", err, w.Len())
	}
	if _, err := im.CheckFlat(50); !errors.Is(err, ErrTooLarge) {
		t.Errorf("CheckFlat: %v", err)
	}
	// A sink that fails is reported wherever it fails: on the lone segment, on a
	// gap, on a segment, and when the last block is flushed.
	big := &Image{Segments: []Segment{{Addr: 0, Data: bytes.Repeat([]byte{1}, 3*flatChunk)}, {Addr: 3*flatChunk + 2*flatChunk, Data: []byte{2}}}}
	for _, c := range []struct {
		name string
		im   *Image
		n    int
	}{
		{"lone segment", &Image{Segments: []Segment{{Data: []byte{1, 2}}}}, 1},
		{"first segment", big, 1},
		{"gap", big, 3*flatChunk + 1},
		{"flush", im, 1},
	} {
		if _, err := c.im.WriteFlat(&failAfter{n: c.n}, 0, 0); !errors.Is(err, errSink) {
			t.Errorf("%s: err = %v, want the sink's", c.name, err)
		}
	}
	// A gap written, then a segment that the sink refuses.
	gap := &Image{Segments: []Segment{{Addr: 0, Data: []byte{1}}, {Addr: 10, Data: []byte{2}}}}
	if _, err := gap.WriteFlat(&failAfter{n: 0}, 0, 0); !errors.Is(err, errSink) {
		t.Errorf("gap then segment: err = %v", err)
	}
}
