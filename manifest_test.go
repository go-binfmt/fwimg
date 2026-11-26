package fwimg

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// sample is an image of three segments with two holes, a start address, and
// the manifest options that go with it.
func sample() *Image {
	return &Image{
		Segments: []Segment{
			{Addr: 0x8000000, Data: []byte("AAAAAAAA")},
			{Addr: 0x8000010, Data: []byte("BBBB")},
			{Addr: 0x8000020, Data: []byte("CC")},
		},
		Entry: 0x8000004, HasEntry: true,
	}
}

func sampleOpts() ManifestOptions {
	return ManifestOptions{
		Version: "v9.9.9", Format: FormatIHEX, Pad: 0xAA,
		Source:   &ManifestSource{File: "fw.elf", Format: FormatELF, Size: 99, SHA256: strings.Repeat("0", 64)},
		Regions:  []Region{{"FLASH", 0x8000000, 0x1000}, {"RAM", 0x20000000, 0x100}, {"HIGH", 0x8000018, 0x10}},
		Sections: []ManifestSection{{".text", "0x8000000", 8, 1}},
	}
}

func mustManifest(t *testing.T, im *Image, o ManifestOptions) *Manifest {
	t.Helper()
	m, err := NewManifest(im, o)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManifest_HashesAgainstTheStandardLibrary(t *testing.T) {
	im := sample()
	m := mustManifest(t, im, sampleOpts())
	flat, base, err := im.Flat(0xAA, 0)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(flat)
	if m.SHA256 != hex.EncodeToString(sum[:]) || m.CRC32 != fmt.Sprintf("%08x", crc32.ChecksumIEEE(flat)) {
		t.Errorf("image hashes %s %s", m.CRC32, m.SHA256)
	}
	if m.Base != Hex(base) || m.Size != uint64(len(flat)) || m.DataSize != 14 || m.Pad != 0xAA {
		t.Errorf("layout %+v", m)
	}
	if m.Entry == nil || *m.Entry != "0x8000004" || m.Fwimg != "v9.9.9" || m.Format != "ihex" || m.SchemaVersion != 1 || m.Schema != ManifestSchemaID {
		t.Errorf("header %+v", m)
	}
	for i, s := range im.Segments {
		sum := sha256.Sum256(s.Data)
		g := m.Segments[i]
		if g.Address != Hex(s.Addr) || g.Size != uint64(len(s.Data)) || g.Source != "fw.elf" ||
			g.SHA256 != hex.EncodeToString(sum[:]) || g.CRC32 != fmt.Sprintf("%08x", crc32.ChecksumIEEE(s.Data)) {
			t.Errorf("segment %d: %+v", i, g)
		}
	}
	// FLASH holds all three segments, HIGH only the last one's two bytes and
	// the hole before them is not its own, RAM nothing.
	want := []struct {
		addr string
		size uint64
		data string
	}{
		{"0x8000000", 0x22, ""}, {"0x20000000", 0, ""}, {"0x8000020", 2, "CC"},
	}
	for i, w := range want {
		r := m.Regions[i]
		if r.DataAddress != w.addr || r.DataSize != w.size {
			t.Errorf("region %s: data %s+%d, want %s+%d", r.Name, r.DataAddress, r.DataSize, w.addr, w.size)
		}
		if w.data != "" {
			if c, h := SumBytes([]byte(w.data)); r.CRC32 != c || r.SHA256 != h {
				t.Errorf("region %s hashes", r.Name)
			}
		}
	}
	if c, h := SumBytes(nil); m.Regions[1].CRC32 != c || m.Regions[1].SHA256 != h {
		t.Errorf("an empty region hashes to %s %s", m.Regions[1].CRC32, m.Regions[1].SHA256)
	}
	// The region of the middle: a span with a hole in it is hashed with pad.
	flash := append(append(append(append([]byte{}, "AAAAAAAA"...), bytes.Repeat([]byte{0xAA}, 8)...), "BBBB"...), bytes.Repeat([]byte{0xAA}, 12)...)
	flash = append(flash, "CC"...)
	if c, h := SumBytes(flash); m.Regions[0].CRC32 != c || m.Regions[0].SHA256 != h {
		t.Errorf("FLASH span hashes %s %s", m.Regions[0].CRC32, m.Regions[0].SHA256)
	}
}

func TestManifest_JSONIsDeterministicAndHasNoClockUnlessAsked(t *testing.T) {
	a := mustManifest(t, sample(), sampleOpts()).JSON()
	b := mustManifest(t, sample(), sampleOpts()).JSON()
	if !bytes.Equal(a, b) || a[len(a)-1] != '\n' || bytes.Contains(a, []byte("created")) {
		t.Errorf("not deterministic or has a time:\n%s", a)
	}
	// Keys come in the order of the schema's table, and "<" is not escaped.
	order := []string{`"$schema"`, `"schema_version"`, `"fwimg_version"`, `"format"`, `"source"`, `"base"`, `"entry"`, `"pad"`, `"size"`, `"data_size"`, `"crc32"`, `"sha256"`, `"segments"`, `"regions"`, `"sections"`}
	at := 0
	for _, k := range order {
		i := bytes.Index(a[at:], []byte(k))
		if i < 0 {
			t.Fatalf("key %s missing or out of order in\n%s", k, a)
		}
		at += i
	}
	o := sampleOpts()
	o.Regions = []Region{{"<&>", 0, 1}}
	if j := mustManifest(t, sample(), o).JSON(); !bytes.Contains(j, []byte(`"<&>"`)) {
		t.Errorf("HTML escaped:\n%s", j)
	}
	// SOURCE_DATE_EPOCH is the one clock.
	e := int64(1700000000)
	o = sampleOpts()
	o.Epoch = &e
	if m := mustManifest(t, sample(), o); m.Created != "2023-11-14T22:13:20Z" {
		t.Errorf("created %q", m.Created)
	}
	// No entry is null, not absent; an empty image has an empty list.
	j := mustManifest(t, &Image{}, ManifestOptions{}).JSON()
	if !bytes.Contains(j, []byte(`"entry": null`)) || !bytes.Contains(j, []byte(`"segments": []`)) {
		t.Errorf("empty image:\n%s", j)
	}
}

func TestManifest_ReadsWhatItWrites(t *testing.T) {
	o := sampleOpts()
	o.UImage = &UImageHeader{Name: "n", OS: 5, Arch: 2, Type: 2, Time: 7, Load: 0x8000, Entry: 0x8004}
	e := int64(0)
	o.Epoch = &e
	m := mustManifest(t, sample(), o)
	back, err := ReadManifest(m.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, m) {
		t.Errorf("read back\n%+v\nwant\n%+v", back, m)
	}
	if !bytes.Equal(back.JSON(), m.JSON()) {
		t.Error("the JSON of a read manifest differs")
	}
}

func TestManifest_VerifyAcceptsAnyLayoutOfTheSameBytes(t *testing.T) {
	im := sample()
	m := mustManifest(t, im, sampleOpts())
	flat, base, _ := im.Flat(0xAA, 0)
	raw, _ := RawImage(flat, base)
	raw.Entry, raw.HasEntry = im.Entry, true
	for name, got := range map[string]*Image{"itself": im, "flat binary": raw} {
		if err := m.Verify(got, VerifyOptions{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A flat binary has no start address, and an image without one is not
	// refused for it.
	raw.HasEntry = false
	if err := m.Verify(raw, VerifyOptions{}); err != nil {
		t.Errorf("no start address: %v", err)
	}
	// The text formats' own decoders give the same image back.
	hexText, err := EncodeIHEX(im, 0)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeIHEX(hexText, DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(dec, VerifyOptions{}); err != nil {
		t.Errorf("ihex round trip: %v", err)
	}
	// An empty manifest verifies an empty image.
	if err := mustManifest(t, &Image{}, ManifestOptions{}).Verify(&Image{}, VerifyOptions{}); err != nil {
		t.Errorf("empty: %v", err)
	}
}

func TestManifest_VerifyNamesEveryDifference(t *testing.T) {
	m := mustManifest(t, sample(), sampleOpts())
	mut := func(f func(*Image)) *Image {
		im := sample()
		for i := range im.Segments {
			im.Segments[i].Data = bytes.Clone(im.Segments[i].Data)
		}
		f(im)
		return im
	}
	for name, c := range map[string]struct {
		im   *Image
		want []string
	}{
		"a byte": {mut(func(im *Image) { im.Segments[1].Data[0] = 'X' }),
			[]string{"1 difference(s)", "" /* image hash */}},
		"entry":     {mut(func(im *Image) { im.Entry = 0x1234 }), []string{"start address is 0x1234, the manifest says 0x8000004"}},
		"base":      {mut(func(im *Image) { im.Segments[0].Addr-- }), []string{"base is 0x7ffffff, the manifest says 0x8000000"}},
		"shorter":   {mut(func(im *Image) { im.Segments = im.Segments[:2] }), []string{"spans 20 bytes", "segment 2"}},
		"two bytes": {mut(func(im *Image) { im.Segments[0].Data[0] = 'X'; im.Segments[2].Data[1] = 'Y' }), []string{"segment 0", "segment 2", "region FLASH"}},
	} {
		err := m.Verify(c.im, VerifyOptions{})
		if !errors.Is(err, ErrVerify) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, w := range c.want {
			if w != "" && name != "a byte" && !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q missing from %v", name, w, err)
			}
		}
	}
	// A byte that is different shows in the image, the segment and the region.
	err := m.Verify(mut(func(im *Image) { im.Segments[1].Data[0] = 'X' }), VerifyOptions{})
	if err == nil || !strings.Contains(err.Error(), "3 difference(s)") {
		t.Errorf("one byte: %v", err)
	}
	// An image with a start address the manifest does not have.
	n := mustManifest(t, &Image{Segments: sample().Segments}, ManifestOptions{})
	if err := n.Verify(sample(), VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "the manifest has no start address") {
		t.Errorf("no start in manifest: %v", err)
	}
}

func TestManifest_VerifyBoundsWhatItWalks(t *testing.T) {
	m := mustManifest(t, sample(), sampleOpts())
	if err := m.Verify(sample(), VerifyOptions{MaxSize: 16}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("an image above the bound: %v", err)
	}
	// The manifest's span is bounded too, whatever the image.
	small, _ := RawImage([]byte("A"), 0x8000000)
	if err := m.Verify(small, VerifyOptions{MaxSize: 0x20}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a manifest above the bound: %v", err)
	}
	// The image's own span is refused first, though the manifest is small.
	tiny := mustManifest(t, small, ManifestOptions{})
	if err := tiny.Verify(sample(), VerifyOptions{MaxSize: 0x20}); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "limit 32") || strings.Contains(err.Error(), "manifest's image") {
		t.Fatalf("an image above the bound: %v", err)
	}
	big := *m
	big.Size = 1 << 40
	big.DataSize = 0
	big.Segments = nil
	if err := big.Verify(small, VerifyOptions{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a manifest of a terabyte: %v", err)
	}
	if _, err := NewManifest(sample(), ManifestOptions{MaxSize: 16}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("NewManifest: %v", err)
	}
	// A manifest that was not read is checked as one that was.
	bad := *m
	bad.SchemaVersion = 2
	if err := bad.Verify(sample(), VerifyOptions{}); !errors.Is(err, ErrManifest) {
		t.Errorf("a bad manifest: %v", err)
	}
}

func TestReadManifest_Refusals(t *testing.T) {
	good := string(mustManifest(t, sample(), sampleOpts()).JSON())
	if _, err := ReadManifest([]byte(good)); err != nil {
		t.Fatal(err)
	}
	h64 := strings.Repeat("a", 64)
	for name, c := range map[string]struct{ old, new, want string }{
		"version":           {`"schema_version": 1`, `"schema_version": 2`, "schema_version 2"},
		"unknown field":     {`"pad": 170,`, `"pad": 170, "extra": 1,`, "unknown field"},
		"not JSON":          {`{`, `[`, "invalid"},
		"base case":         {`"base": "0x8000000"`, `"base": "0X8000000"`, "lowercase hex"},
		"base upper":        {`"base": "0x8000000"`, `"base": "0xA000000"`, "lowercase hex"},
		"base leading zero": {`"base": "0x8000000"`, `"base": "0x08000000"`, "lowercase hex"},
		"base no digits":    {`"base": "0x8000000"`, `"base": "0x"`, "lowercase hex"},
		"base wide":         {`"base": "0x8000000"`, `"base": "0x10000000000000000"`, "64 bits"},
		"entry":             {`"entry": "0x8000004"`, `"entry": "8000004"`, "entry"},
		"size wraps":        {`"size": 34,`, `"size": 18446744073709551615,`, "pass 2^64"},
		"image crc": {`"crc32": "` + mustManifest(t, sample(), sampleOpts()).CRC32 + `",
  "sha256"`, `"crc32": "XYZ",
  "sha256"`, "crc32"},
		"data size":        {`"data_size": 14`, `"data_size": 15`, "data_size says 15"},
		"segment address":  {`"address": "0x8000010"`, `"address": "10"`, "segment address"},
		"segment overlaps": {`"address": "0x8000010"`, `"address": "0x8000004"`, "overlapping"},
		"segment outside":  {`"address": "0x8000020"`, `"address": "0x9000020"`, "outside the image"},
		"segment past the end": {`"address": "0x8000020",
      "size": 2`, `"address": "0x8000020",
      "size": 3`, "outside the image"},
		"segment empty": {`"address": "0x8000020",
      "size": 2`, `"address": "0x8000020",
      "size": 0`, "empty"},
		"segment hash": {`"source": "fw.elf",
      "crc32": "`, `"source": "fw.elf",
      "crc32": "0`, "segment 0"},
		"region address": {`"address": "0x8000000",
      "size": 4096`, `"address": "zz",
      "size": 4096`, "region address"},
		"region data address": {`"data_address": "0x20000000"`, `"data_address": "0x"`, "region data_address"},
		"region hash":         {`"name": "RAM"`, `"name": "RAM", "x": 0`, "unknown field"},
		"region outside":      {`"data_size": 2`, `"data_size": 3`, "outside the image"},
		"section address": {`".text",
      "address": "0x8000000"`, `".text",
      "address": "g"`, "section address"},
	} {
		doc := strings.Replace(good, c.old, c.new, 1)
		if doc == good {
			t.Errorf("%s: the edit changed nothing", name)
			continue
		}
		if _, err := ReadManifest([]byte(doc)); !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want ErrManifest with %q", name, err, c.want)
		}
	}
	for name, tail := range map[string]string{"second document": "{}", "garbage": "x"} {
		if _, err := ReadManifest([]byte(good + tail)); !errors.Is(err, ErrManifest) {
			t.Errorf("trailing %s: %v", name, err)
		}
	}
	// Hashes of the wrong length are refused at every level.
	for name, f := range map[string]func(*Manifest){
		"region sha":        func(m *Manifest) { m.Regions[0].SHA256 = h64[1:] },
		"segment sha":       func(m *Manifest) { m.Segments[0].SHA256 = h64[1:] },
		"image sha":         func(m *Manifest) { m.SHA256 = strings.ToUpper(h64) },
		"uimage load":       func(m *Manifest) { m.UImage = &ManifestUImage{Load: "1", Entry: "0x1"} },
		"uimage entry":      func(m *Manifest) { m.UImage = &ManifestUImage{Load: "0x1", Entry: "1"} },
		"too many segments": func(m *Manifest) { m.Segments = make([]ManifestSegment, maxManifestItems+1) },
		"too many regions":  func(m *Manifest) { m.Regions = make([]ManifestRegion, maxManifestItems+1) },
		"too many sections": func(m *Manifest) { m.Sections = make([]ManifestSection, maxManifestItems+1) },
	} {
		m := mustManifest(t, sample(), sampleOpts())
		f(m)
		if err := m.check(); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The bound is on both sides: one byte over is refused for its size, the
	// bound itself is read (and fails as the JSON it is, not as too large).
	if _, err := ReadManifest(make([]byte, MaxManifestSize+1)); !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), "at most") {
		t.Errorf("an oversized manifest: %v", err)
	}
	if _, err := ReadManifest(make([]byte, MaxManifestSize)); !errors.Is(err, ErrManifest) || strings.Contains(err.Error(), "at most") {
		t.Errorf("a manifest at the bound: %v", err)
	}
	for name, f := range map[string]func(*Manifest, int){
		"segments": func(m *Manifest, n int) { m.Segments = make([]ManifestSegment, n) },
		"regions":  func(m *Manifest, n int) { m.Regions = make([]ManifestRegion, n) },
		"sections": func(m *Manifest, n int) { m.Sections = make([]ManifestSection, n) },
	} {
		for n, want := range map[int]bool{maxManifestItems: false, maxManifestItems + 1: true} {
			m := mustManifest(t, sample(), sampleOpts())
			f(m, n)
			err := m.check()
			if got := err != nil && strings.Contains(err.Error(), "more than"); got != want {
				t.Errorf("%d %s: refused for their number = %v, want %v (%v)", n, name, got, want, err)
			}
		}
	}
	// A base too short to hold 0x and a digit never reaches the slice of it.
	for _, b := range []string{"", "0", "x", "80", "0x"} {
		doc := strings.Replace(good, `"base": "0x8000000"`, `"base": "`+b+`"`, 1)
		if _, err := ReadManifest([]byte(doc)); !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), "lowercase hex") {
			t.Errorf("base %q: %v", b, err)
		}
	}
	// Zero is written 0x0, with its one digit.
	zero, _ := RawImage([]byte("A"), 0)
	if _, err := ReadManifest(mustManifest(t, zero, ManifestOptions{}).JSON()); err != nil {
		t.Errorf("an image at 0x0: %v", err)
	}
	if _, err := ReadManifest(nil); !errors.Is(err, ErrManifest) {
		t.Errorf("an empty manifest: %v", err)
	}
	// A uImage block and an entry of null are accepted.
	if _, err := ReadManifest(mustManifest(t, &Image{}, ManifestOptions{UImage: &UImageHeader{}}).JSON()); err != nil {
		t.Errorf("uimage: %v", err)
	}
}

func TestManifest_ELFSections(t *testing.T) {
	secs, err := ELFManifestSections(sectioned())
	if err != nil {
		t.Fatal(err)
	}
	if len(secs) == 0 {
		t.Fatal("no sections")
	}
	for _, s := range secs {
		if s.Name == "" || !strings.HasPrefix(s.Address, "0x") {
			t.Errorf("%+v", s)
		}
	}
	if _, err := ELFManifestSections([]byte("not an elf")); err == nil {
		t.Error("not an ELF accepted")
	}
	noSecs := elfgen.Build(elf.EM_ARM, 0x1000, []elfgen.Seg{{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}})
	if secs, err := ELFManifestSections(noSecs); err != nil || secs != nil {
		t.Errorf("an ELF without section headers: %v %v", secs, err)
	}
}

func TestManifest_ELFSectionsOfAMalformedTable(t *testing.T) {
	// Cut the file inside its section header table (it ends the file): the
	// segments still load, the table does not read.
	whole := sectioned()
	found := false
	for n := len(whole) - 1; n > len(whole)-200 && !found; n-- {
		if _, err := ELFManifestSections(whole[:n]); err != nil && !errors.Is(err, ErrManifest) {
			found = true
			t.Logf("cut at %d of %d: %v", n, len(whole), err)
		}
	}
	if !found {
		t.Error("no cut of the section table gives an error")
	}
}

func TestSumBytes(t *testing.T) {
	c, h := SumBytes([]byte("abc"))
	if c != "352441c2" || h != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("abc: %s %s", c, h)
	}
}

func TestWriteSpan(t *testing.T) {
	im := sample()
	flat, base, _ := im.Flat('.', 0)
	for lo := base - 3; lo < base+uint64(len(flat))+3; lo++ {
		for hi := lo; hi < base+uint64(len(flat))+3; hi++ {
			var got bytes.Buffer
			im.writeSpan(&got, '.', lo, hi)
			var want []byte
			for a := lo; a < hi; a++ {
				switch {
				case a < base || a >= base+uint64(len(flat)):
					want = append(want, '.')
				default:
					want = append(want, flat[a-base])
				}
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("span %#x..%#x: %q want %q", lo, hi, got.Bytes(), want)
			}
		}
	}
	// A gap longer than the block is written in several pieces.
	far := &Image{Segments: []Segment{{Addr: 0, Data: []byte{1}}, {Addr: 3 * flatChunk, Data: []byte{2}}}}
	var b bytes.Buffer
	far.writeSpan(&b, 7, 0, 3*flatChunk+1)
	if b.Len() != 3*flatChunk+1 || b.Bytes()[0] != 1 || b.Bytes()[1] != 7 || b.Bytes()[3*flatChunk] != 2 {
		t.Errorf("a long gap: %d bytes", b.Len())
	}
}

func TestRegionDataSkipsAnImageBelowAndAbove(t *testing.T) {
	im := sample()
	for _, c := range []struct {
		r       Region
		addr, n uint64
	}{
		{Region{"a", 0, 0x8000001}, 0x8000000, 1},
		{Region{"b", 0x8000021, 0x100}, 0x8000021, 1},
		{Region{"c", 0x9000000, 0x10}, 0x9000000, 0},
		{Region{"d", 0, math.MaxUint64}, 0x8000000, 0x22},
	} {
		if a, n := im.regionData(c.r); a != c.addr || n != c.n {
			t.Errorf("%+v: %#x+%d, want %#x+%d", c.r, a, n, c.addr, c.n)
		}
	}
}

// --- the schema ----------------------------------------------------------------

// validate checks v against the keywords manifest-1.schema.json uses: $ref,
// type, const, enum, oneOf, pattern, minimum, maximum, maxItems, required,
// properties, additionalProperties and items. It is not a general validator: a
// keyword it does not know is a test failure, so the schema cannot grow one
// that goes unchecked.
func validate(t *testing.T, root, s map[string]any, v any, path string) []string {
	t.Helper()
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, path+": "+fmt.Sprintf(f, a...)) }
	known := map[string]bool{"$schema": true, "$id": true, "$defs": true, "title": true, "description": true, "format": true,
		"$ref": true, "type": true, "const": true, "enum": true, "oneOf": true, "pattern": true, "minimum": true,
		"maximum": true, "maxItems": true, "required": true, "properties": true, "additionalProperties": true, "items": true}
	for k := range s {
		if !known[k] {
			t.Fatalf("the schema uses %q, which this test does not check", k)
		}
	}
	if ref, ok := s["$ref"].(string); ok {
		cur := any(root)
		for _, p := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			cur = cur.(map[string]any)[p]
		}
		errs = append(errs, validate(t, root, cur.(map[string]any), v, path)...)
	}
	if c, ok := s["const"]; ok && !reflect.DeepEqual(c, v) {
		bad("%v is not the constant %v", v, c)
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range e {
			found = found || reflect.DeepEqual(x, v)
		}
		if !found {
			bad("%v not in %v", v, e)
		}
	}
	if o, ok := s["oneOf"].([]any); ok {
		n := 0
		for _, alt := range o {
			if len(validate(t, root, alt.(map[string]any), v, path)) == 0 {
				n++
			}
		}
		if n != 1 {
			bad("%d of the alternatives match", n)
		}
	}
	if ty, ok := s["type"].(string); ok {
		okType := map[string]bool{
			"string": isT[string](v), "null": v == nil, "object": isT[map[string]any](v), "array": isT[[]any](v),
			"integer": isT[float64](v) && v.(float64) == math.Trunc(v.(float64)),
		}[ty]
		if !okType {
			bad("%T is not %s", v, ty)
			return errs
		}
	}
	switch x := v.(type) {
	case string:
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(x) {
			bad("%q does not match %s", x, p)
		}
	case float64:
		if m, ok := s["minimum"].(float64); ok && x < m {
			bad("%v below %v", x, m)
		}
		if m, ok := s["maximum"].(float64); ok && x > m {
			bad("%v above %v", x, m)
		}
	case []any:
		if m, ok := s["maxItems"].(float64); ok && float64(len(x)) > m {
			bad("%d items above %v", len(x), m)
		}
		if it, ok := s["items"].(map[string]any); ok {
			for i, e := range x {
				errs = append(errs, validate(t, root, it, e, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	case map[string]any:
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, there := x[r.(string)]; !there {
					bad("required %q missing", r)
				}
			}
		}
		for k, e := range x {
			if p, ok := props[k]; ok {
				errs = append(errs, validate(t, root, p.(map[string]any), e, path+"."+k)...)
			} else if s["additionalProperties"] == false {
				bad("property %q is not in the schema", k)
			}
		}
	}
	return errs
}

func isT[T any](v any) bool { _, ok := v.(T); return ok }

func schemaDoc(t *testing.T) map[string]any {
	t.Helper()
	var s map[string]any
	if err := json.Unmarshal(ManifestSchema, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSchema_IsTheOneTheManifestsSatisfy(t *testing.T) {
	s := schemaDoc(t)
	if s["$id"] != ManifestSchemaID || s["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$id %v $schema %v", s["$id"], s["$schema"])
	}
	if !strings.HasSuffix(ManifestSchemaID, fmt.Sprintf("manifest-%d.schema.json", ManifestSchemaVersion)) {
		t.Error("the schema's name does not carry its version")
	}
	o := sampleOpts()
	o.UImage = &UImageHeader{Name: "n", OS: 5, Arch: 2, Type: 2, Comp: 0, Time: 7, Load: 0x8000, Entry: 0x8004}
	e := int64(5)
	o.Epoch = &e
	full := mustManifest(t, sample(), o)
	docs := map[string]*Manifest{
		"full": full, "empty": mustManifest(t, &Image{}, ManifestOptions{Format: FormatBinary}),
		"no entry": mustManifest(t, &Image{Segments: sample().Segments}, sampleOpts()),
		"64 bit":   mustManifest(t, &Image{Segments: []Segment{{Addr: math.MaxUint64 - 3, Data: []byte("abcd")}}}, ManifestOptions{Format: FormatBinary}),
	}
	for name, m := range docs {
		var v any
		if err := json.Unmarshal(m.JSON(), &v); err != nil {
			t.Fatal(err)
		}
		if errs := validate(t, s, s, v, "$"); len(errs) > 0 {
			t.Errorf("%s: %v\n%s", name, errs, m.JSON())
		}
	}
	// The schema is not vacuous: each edit of the full manifest is refused.
	var base map[string]any
	_ = json.Unmarshal(full.JSON(), &base)
	for name, edit := range map[string]func(map[string]any){
		"extra key":        func(m map[string]any) { m["x"] = 1 },
		"no sha":           func(m map[string]any) { delete(m, "sha256") },
		"short crc":        func(m map[string]any) { m["crc32"] = "abc" },
		"version 2":        func(m map[string]any) { m["schema_version"] = 2.0 },
		"format":           func(m map[string]any) { m["format"] = "coff" },
		"address":          func(m map[string]any) { m["base"] = "0X1" },
		"address 65 bits":  func(m map[string]any) { m["base"] = "0x10000000000000000" },
		"entry type":       func(m map[string]any) { m["entry"] = 5.0 },
		"pad 256":          func(m map[string]any) { m["pad"] = 256.0 },
		"fraction":         func(m map[string]any) { m["size"] = 1.5 },
		"negative":         func(m map[string]any) { m["size"] = -1.0 },
		"segment extra":    func(m map[string]any) { m["segments"].([]any)[0].(map[string]any)["x"] = 1 },
		"segment empty":    func(m map[string]any) { m["segments"].([]any)[0].(map[string]any)["size"] = 0.0 },
		"region missing":   func(m map[string]any) { delete(m["regions"].([]any)[0].(map[string]any), "data_size") },
		"section type":     func(m map[string]any) { m["sections"].([]any)[0].(map[string]any)["type"] = "x" },
		"uimage time":      func(m map[string]any) { m["uimage"].(map[string]any)["time"] = 4294967296.0 },
		"source sha":       func(m map[string]any) { m["source"].(map[string]any)["sha256"] = "x" },
		"segments type":    func(m map[string]any) { m["segments"] = "none" },
		"segments too big": func(m map[string]any) { m["segments"] = make([]any, 65537) },
	} {
		var doc map[string]any
		_ = json.Unmarshal(full.JSON(), &doc)
		edit(doc)
		if name == "segments too big" {
			for i := range doc["segments"].([]any) {
				doc["segments"].([]any)[i] = map[string]any{}
			}
		}
		if errs := validate(t, s, s, any(doc), "$"); len(errs) == 0 {
			t.Errorf("%s: the schema accepted it", name)
		}
	}
	_ = base
	// Whatever the schema calls required, the Go type writes.
	for _, k := range s["required"].([]any) {
		if !bytes.Contains(docs["full"].JSON(), []byte(`"`+k.(string)+`"`)) {
			t.Errorf("required %v is not written", k)
		}
	}
}

// --- fuzz ----------------------------------------------------------------------

// FuzzReadManifest holds the reader to its contract on any bytes: no panic, a
// refusal wraps ErrManifest, an accepted manifest is internally consistent
// (its JSON reads back as itself) and Verify of it, against any image, either
// agrees or refuses with ErrVerify or ErrTooLarge, never a panic, and never
// walks a span above its bound.
func FuzzReadManifest(f *testing.F) {
	f.Add(mustManifestF(sample(), sampleOpts()).JSON())
	f.Add(mustManifestF(&Image{}, ManifestOptions{}).JSON())
	f.Add([]byte(`{"schema_version": 1}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ReadManifest(b)
		if err != nil {
			if !errors.Is(err, ErrManifest) {
				t.Fatalf("%v is not ErrManifest", err)
			}
			return
		}
		back, err := ReadManifest(m.JSON())
		if err != nil || !reflect.DeepEqual(back, m) {
			t.Fatalf("an accepted manifest does not read back: %v", err)
		}
		im := sample()
		verr := m.Verify(im, VerifyOptions{MaxSize: 1 << 16})
		if verr != nil && !errors.Is(verr, ErrVerify) && !errors.Is(verr, ErrTooLarge) {
			t.Fatalf("Verify: %v", verr)
		}
	})
}

func mustManifestF(im *Image, o ManifestOptions) *Manifest {
	m, err := NewManifest(im, o)
	if err != nil {
		panic(err)
	}
	return m
}
