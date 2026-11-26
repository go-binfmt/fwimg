package fwimg

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	_ "embed" // the schema file
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-binfmt/elfpatch"
)

// ManifestSchemaVersion is the version of the manifest layout: the integer a
// manifest carries as schema_version and the number in the schema file's name.
// A field that is added keeps the number; one that is renamed, removed or
// changes meaning raises it.
const ManifestSchemaVersion = 1

// ManifestSchemaID is the $id of ManifestSchema (JSON Schema draft 2020-12).
const ManifestSchemaID = "https://go-binfmt.github.io/fwimg/manifest-1.schema.json"

// ManifestSchema is the JSON Schema (draft 2020-12) a manifest satisfies.
//
//go:embed schema/manifest-1.schema.json
var ManifestSchema []byte

// MaxManifestSize bounds what ReadManifest accepts, and maxManifestItems the
// number of segments, regions and sections: a manifest is a few kilobytes.
const (
	MaxManifestSize  = 16 << 20
	maxManifestItems = 1 << 16
)

// ErrManifest: a manifest that is not valid JSON of the schema, or whose
// values contradict each other.
var ErrManifest = errors.New("fwimg: invalid manifest")

// ManifestSegment is one run of the image: where it is, how long, where it came
// from, and the CRC-32 (IEEE, 8 hex digits) and SHA-256 of its bytes.
type ManifestSegment struct {
	Address string `json:"address"`
	Size    uint64 `json:"size"`
	Source  string `json:"source"`
	CRC32   string `json:"crc32"`
	SHA256  string `json:"sha256"`
}

// ManifestRegion is a memory region (--region) and the bytes the image puts in
// it: DataAddress and DataSize give the span from its first to its last byte
// (gaps inside it read as the pad byte), the hashes are those of that span.
type ManifestRegion struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Size        uint64 `json:"size"`
	DataAddress string `json:"data_address"`
	DataSize    uint64 `json:"data_size"`
	CRC32       string `json:"crc32"`
	SHA256      string `json:"sha256"`
}

// ManifestSection is an allocated section of the source ELF.
type ManifestSection struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Size    uint64 `json:"size"`
	Type    uint32 `json:"type"`
}

// ManifestSource says what the image was made from.
type ManifestSource struct {
	File   string `json:"file"`
	Format string `json:"format"`
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256"`
}

// ManifestUImage is the header of a uImage, as its fields are stored.
type ManifestUImage struct {
	Name        string `json:"name"`
	OS          uint8  `json:"os"`
	Arch        uint8  `json:"arch"`
	Type        uint8  `json:"type"`
	Compression uint8  `json:"compression"`
	Time        uint32 `json:"time"`
	Load        string `json:"load"`
	Entry       string `json:"entry"`
}

// Manifest describes an image: its layout and the hashes to check it by. The
// image is the memory a loader would build: the segments at their addresses and
// Pad in the gaps, from Base for Size bytes. Addresses are strings of 0x and
// lowercase hex, so that no reader loses the bits of a 64-bit address in a
// double. The field order is the JSON order, and it is fixed.
type Manifest struct {
	Schema        string            `json:"$schema"`
	SchemaVersion int               `json:"schema_version"`
	Fwimg         string            `json:"fwimg_version"`
	Created       string            `json:"created,omitempty"`
	Format        string            `json:"format"`
	Source        *ManifestSource   `json:"source,omitempty"`
	Base          string            `json:"base"`
	Entry         *string           `json:"entry"`
	Pad           uint8             `json:"pad"`
	Size          uint64            `json:"size"`
	DataSize      uint64            `json:"data_size"`
	CRC32         string            `json:"crc32"`
	SHA256        string            `json:"sha256"`
	Segments      []ManifestSegment `json:"segments"`
	Regions       []ManifestRegion  `json:"regions,omitempty"`
	Sections      []ManifestSection `json:"sections,omitempty"`
	UImage        *ManifestUImage   `json:"uimage,omitempty"`
}

// ManifestOptions controls NewManifest.
type ManifestOptions struct {
	// Version is fwimg's version, recorded as fwimg_version.
	Version string
	// Format is the format of the file the image was read from or written to.
	Format string
	// Source, Regions, Sections and UImage are recorded as they are given.
	Source   *ManifestSource
	Regions  []Region
	Sections []ManifestSection
	UImage   *UImageHeader
	// Pad fills the gaps; MaxSize bounds the span (0 is DefaultMaxSize).
	Pad     byte
	MaxSize uint64
	// Epoch, when not nil, is recorded as the creation time (SOURCE_DATE_EPOCH):
	// a manifest has no timestamp unless one is given.
	Epoch *int64
}

// Hex is the manifest's spelling of an address.
func Hex(v uint64) string { return "0x" + strconv.FormatUint(v, 16) }

// digest hashes the bytes written to it with CRC-32 (IEEE) and SHA-256.
type digest struct {
	c hash.Hash32
	s hash.Hash
}

func newDigest() *digest { return &digest{crc32.NewIEEE(), sha256.New()} }

func (d *digest) Write(p []byte) (int, error) {
	d.c.Write(p)
	d.s.Write(p)
	return len(p), nil
}

func (d *digest) sums() (string, string) {
	return fmt.Sprintf("%08x", d.c.Sum32()), hex.EncodeToString(d.s.Sum(nil))
}

// SumBytes returns the CRC-32 (IEEE, 8 lowercase hex digits) and the SHA-256
// (64 hex digits) of b.
func SumBytes(b []byte) (crc, sha string) {
	d := newDigest()
	d.Write(b)
	return d.sums()
}

// writeSpan writes the bytes of the image from lo to hi: segments where they
// are, pad elsewhere. It allocates one block of pad, at most flatChunk.
func (im *Image) writeSpan(w io.Writer, pad byte, lo, hi uint64) {
	hi = max(hi, lo) // an inverted span is an empty one; hi-lo must not wrap
	var fill []byte
	gap := func(n uint64) {
		if fill == nil {
			fill = bytes.Repeat([]byte{pad}, int(min(hi-lo, flatChunk)))
		}
		for n > 0 {
			k := min(n, uint64(len(fill)))
			w.Write(fill[:k])
			n -= k
		}
	}
	at := lo
	i := sort.Search(len(im.Segments), func(i int) bool { return im.Segments[i].End() > lo })
	for ; i < len(im.Segments) && im.Segments[i].Addr < hi; i++ {
		s := im.Segments[i]
		if s.Addr > at {
			gap(s.Addr - at)
			at = s.Addr
		}
		from, to := max(s.Addr, lo), min(s.End(), hi)
		w.Write(s.Data[from-s.Addr : to-s.Addr])
		at = to
	}
	gap(hi - at)
}

// spanSums is the CRC-32 and SHA-256 of the image from lo to hi.
func (im *Image) spanSums(pad byte, lo, hi uint64) (string, string) {
	d := newDigest()
	im.writeSpan(d, pad, lo, hi)
	return d.sums()
}

func (im *Image) end() uint64 { return im.Base() + im.Span() }

// regionData is the span from the first to the last byte of the image inside r:
// its address and size, and (r.Start, 0) when the image has none there.
func (im *Image) regionData(r Region) (uint64, uint64) {
	lo, hi := uint64(math.MaxUint64), uint64(0)
	for _, s := range im.Segments {
		if a, b := max(s.Addr, r.Start), min(s.End(), r.End()); a < b {
			lo, hi = min(lo, a), max(hi, b)
		}
	}
	if lo > hi {
		return r.Start, 0
	}
	return lo, hi - lo
}

// NewManifest describes im. The image's span is bounded by o.MaxSize
// (ErrTooLarge). Nothing is allocated for it: the hashes are computed as the
// segments and the pad are streamed through them.
func NewManifest(im *Image, o ManifestOptions) (*Manifest, error) {
	if _, err := im.CheckFlat(o.MaxSize); err != nil {
		return nil, err
	}
	m := &Manifest{
		Schema: ManifestSchemaID, SchemaVersion: ManifestSchemaVersion, Fwimg: o.Version,
		Format: o.Format, Source: o.Source, Base: Hex(im.Base()), Pad: o.Pad,
		Size: im.Span(), DataSize: im.Len(), Segments: []ManifestSegment{},
		Sections: o.Sections,
	}
	if o.Epoch != nil {
		m.Created = time.Unix(*o.Epoch, 0).UTC().Format(time.RFC3339)
	}
	if im.HasEntry {
		e := Hex(im.Entry)
		m.Entry = &e
	}
	m.CRC32, m.SHA256 = im.spanSums(o.Pad, im.Base(), im.end())
	file := ""
	if o.Source != nil {
		file = o.Source.File
	}
	for _, s := range im.Segments {
		c, h := SumBytes(s.Data)
		m.Segments = append(m.Segments, ManifestSegment{Hex(s.Addr), uint64(len(s.Data)), file, c, h})
	}
	for _, r := range o.Regions {
		a, n := im.regionData(r)
		c, h := im.spanSums(o.Pad, a, a+n)
		m.Regions = append(m.Regions, ManifestRegion{r.Name, Hex(r.Start), r.Size, Hex(a), n, c, h})
	}
	if u := o.UImage; u != nil {
		m.UImage = &ManifestUImage{u.Name, u.OS, u.Arch, u.Type, u.Comp, u.Time, Hex(uint64(u.Load)), Hex(uint64(u.Entry))}
	}
	return m, nil
}

// JSON is the manifest as indented JSON ending in a newline. The bytes depend
// only on the manifest: the keys come in the order of the struct, and nothing
// is escaped for HTML.
func (m *Manifest) JSON() []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	// A Manifest holds strings and numbers: Encode cannot fail on it.
	_ = e.Encode(m)
	return b.Bytes()
}

// addr parses a manifest address.
func addr(field, s string) (uint64, error) {
	h, ok := strings.CutPrefix(s, "0x")
	if !ok || h == "" || s != strings.ToLower(s) || (len(h) > 1 && h[0] == '0') {
		return 0, fmt.Errorf("%w: %s %q is not 0x and lowercase hex", ErrManifest, field, s)
	}
	v, err := strconv.ParseUint(h, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s %q does not fit 64 bits", ErrManifest, field, s)
	}
	return v, nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

func badSums(field, crc, sha string) error {
	if !isHex(crc, 8) || !isHex(sha, 64) {
		return fmt.Errorf("%w: %s: crc32 %q or sha256 %q is not lowercase hex of 8 and 64 digits", ErrManifest, field, crc, sha)
	}
	return nil
}

// ReadManifest parses and checks a manifest. The input is untrusted: it is
// bounded, unknown fields and trailing data are refused, every address, hash
// and count is checked, and the segments must be sorted, disjoint and inside
// the image, so that Verify can rely on them. Refusals wrap ErrManifest.
func ReadManifest(data []byte) (*Manifest, error) {
	if len(data) > MaxManifestSize {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrManifest, len(data), MaxManifestSize)
	}
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: data after the manifest", ErrManifest)
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	return &m, nil
}

// check is the validation of ReadManifest.
func (m *Manifest) check() error {
	if m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("%w: schema_version %d, this fwimg reads %d", ErrManifest, m.SchemaVersion, ManifestSchemaVersion)
	}
	if len(m.Segments) > maxManifestItems || len(m.Regions) > maxManifestItems || len(m.Sections) > maxManifestItems {
		return fmt.Errorf("%w: more than %d segments, regions or sections", ErrManifest, maxManifestItems)
	}
	base, err := addr("base", m.Base)
	if err != nil {
		return err
	}
	if m.Entry != nil {
		if _, err := addr("entry", *m.Entry); err != nil {
			return err
		}
	}
	if m.Size > math.MaxUint64-base {
		return fmt.Errorf("%w: %d bytes at %s pass 2^64", ErrManifest, m.Size, m.Base)
	}
	if err := badSums("image", m.CRC32, m.SHA256); err != nil {
		return err
	}
	at, total := base, uint64(0)
	for i, s := range m.Segments {
		a, err := addr("segment address", s.Address)
		if err != nil {
			return err
		}
		if err := badSums(fmt.Sprintf("segment %d", i), s.CRC32, s.SHA256); err != nil {
			return err
		}
		if s.Size == 0 || a < at || a > base+m.Size || s.Size > base+m.Size-a {
			return fmt.Errorf("%w: segment %d (%s, %d bytes) is empty, unsorted, overlapping or outside the image", ErrManifest, i, s.Address, s.Size)
		}
		at, total = a+s.Size, total+s.Size
	}
	if total != m.DataSize {
		return fmt.Errorf("%w: segments hold %d bytes, data_size says %d", ErrManifest, total, m.DataSize)
	}
	for i, r := range m.Regions {
		if _, err := addr("region address", r.Address); err != nil {
			return err
		}
		da, err := addr("region data_address", r.DataAddress)
		if err != nil {
			return err
		}
		if err := badSums(fmt.Sprintf("region %d", i), r.CRC32, r.SHA256); err != nil {
			return err
		}
		if r.DataSize > 0 && (da < base || da > base+m.Size || r.DataSize > base+m.Size-da) {
			return fmt.Errorf("%w: region %q data (%s, %d bytes) is outside the image", ErrManifest, r.Name, r.DataAddress, r.DataSize)
		}
	}
	for _, s := range m.Sections {
		if _, err := addr("section address", s.Address); err != nil {
			return err
		}
	}
	if u := m.UImage; u != nil {
		if _, err := addr("uimage load", u.Load); err != nil {
			return err
		}
		if _, err := addr("uimage entry", u.Entry); err != nil {
			return err
		}
	}
	return nil
}

// VerifyOptions controls Manifest.Verify.
type VerifyOptions struct {
	// MaxSize bounds the span of the image (0 is DefaultMaxSize).
	MaxSize uint64
}

// Verify checks im against the manifest: base, size and data size, the start
// address when the image has one, the hashes of the image and of every segment
// and region, each recomputed from the bytes. The layout of im may differ from
// the manifest's (a flat binary is one segment, a text file may split the
// runs): a segment is checked by the bytes of im at its range, with the
// manifest's pad where im has none. All differences are reported, in one error
// that wraps ErrVerify. A manifest that was not read by ReadManifest is refused
// (ErrManifest) if it does not pass the same checks.
func (m *Manifest) Verify(im *Image, o VerifyOptions) error {
	if err := m.check(); err != nil {
		return err
	}
	if _, err := im.CheckFlat(o.MaxSize); err != nil {
		return err
	}
	// The manifest's own span is walked too: it is bounded the same way.
	limit := cmp.Or(o.MaxSize, DefaultMaxSize)
	if m.Size > limit {
		return fmt.Errorf("%w: the manifest's image is %d bytes, limit %d", ErrTooLarge, m.Size, limit)
	}
	var diffs []string
	diff := func(format string, a ...any) { diffs = append(diffs, fmt.Sprintf(format, a...)) }
	base, _ := addr("", m.Base) // check passed
	if im.Base() != base {
		diff("base is %s, the manifest says %s", Hex(im.Base()), m.Base)
	}
	if im.Span() != m.Size {
		diff("the image spans %d bytes, the manifest says %d", im.Span(), m.Size)
	}
	// data_size is not compared: a flat binary has no holes, so it counts its
	// padding as data. The hashes, taken with the manifest's pad, decide.
	if im.HasEntry {
		if m.Entry == nil {
			diff("the image starts at %s, the manifest has no start address", Hex(im.Entry))
		} else if e, _ := addr("", *m.Entry); e != im.Entry {
			diff("start address is %s, the manifest says %s", Hex(im.Entry), *m.Entry)
		}
	}
	if c, s := im.spanSums(m.Pad, base, base+m.Size); c != m.CRC32 || s != m.SHA256 {
		diff("the image hashes to crc32 %s sha256 %s, the manifest says %s and %s", c, s, m.CRC32, m.SHA256)
	}
	for i, s := range m.Segments {
		a, _ := addr("", s.Address)
		c, h := im.spanSums(m.Pad, a, a+s.Size)
		if c != s.CRC32 || h != s.SHA256 {
			diff("segment %d (%s, %d bytes) hashes to crc32 %s sha256 %s, the manifest says %s and %s", i, s.Address, s.Size, c, h, s.CRC32, s.SHA256)
		}
	}
	for _, r := range m.Regions {
		a, _ := addr("", r.DataAddress)
		c, h := im.spanSums(m.Pad, a, a+r.DataSize)
		if c != r.CRC32 || h != r.SHA256 {
			diff("region %s (%d bytes at %s) hashes to crc32 %s sha256 %s, the manifest says %s and %s", r.Name, r.DataSize, r.DataAddress, c, h, r.CRC32, r.SHA256)
		}
	}
	if len(diffs) > 0 {
		return mismatch("%d difference(s):\n  %s", len(diffs), strings.Join(diffs, "\n  "))
	}
	return nil
}

// ELFManifestSections lists the allocated sections of the ELF in data, in
// section-header order, for ManifestOptions.Sections. An ELF without section
// headers has none, which is not an error.
func ELFManifestSections(data []byte) ([]ManifestSection, error) {
	f, err := elfpatch.Parse(data)
	if err != nil {
		return nil, err
	}
	secs, err := f.Sections()
	if errors.Is(err, elfpatch.ErrUnsupported) {
		return nil, nil // no section headers (stripped): described by its segments alone
	}
	if err != nil {
		return nil, err
	}
	var out []ManifestSection
	for _, s := range secs {
		if s.Flags&shfAlloc != 0 {
			out = append(out, ManifestSection{s.Name, Hex(s.Addr), s.Size, s.Type})
		}
	}
	return out, nil
}
