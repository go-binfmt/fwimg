package fwimg

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-binfmt/fdt"
)

// A FIT (Flattened Image Tree) is a devicetree blob whose /images and
// /configurations nodes describe the images a boot loader loads. The format is
// the Flattened Image Tree Specification v1.0, chapter 5 (docs/spec-notes.md
// section 6); the blob itself is go-binfmt/fdt's.

// FormatFIT is the input name of a FIT, as Detect returns it.
const FormatFIT = "fit"

var (
	// ErrFITSignature is returned by Verify for a FIT that carries signature
	// nodes: fwimg does not check signatures, and a verification that skipped
	// them would report a pass for what it did not check.
	ErrFITSignature = errors.New("fwimg: the FIT carries signature nodes, which fwimg does not check")
	// ErrFITAlgo is returned by Verify for a hash algorithm it cannot compute.
	ErrFITAlgo = errors.New("fwimg: unsupported FIT hash algorithm")
	// ErrFITNoHash is returned by Verify, under RequireHash, for an image
	// without a hash node.
	ErrFITNoHash = errors.New("fwimg: FIT image without a hash node")
)

// FITHash is a hash node of an image. WriteFIT computes Value; ParseFIT reads it.
type FITHash struct {
	Name  string // hash-1
	Algo  string // crc32, sha1, sha256, ...
	Value []byte
}

// FITImage is a node of /images.
type FITImage struct {
	Name        string // kernel-1
	Description string
	Type        string // kernel, ramdisk, flat_dt, firmware, standalone, script, ...
	Arch        string // arm, arm64, x86_64, riscv, ...; may be empty
	OS          string // linux, u-boot, ...; may be empty
	Comp        string // none, gzip, lz4, ...; "none" when empty on writing
	Data        []byte // the stored bytes; for a parsed FIT a view of its input
	Load, Entry uint64
	HasLoad     bool
	HasEntry    bool
	Hashes      []FITHash
	// Reader only.
	External   bool     // the data lies after the structure (data-offset or data-position)
	Signatures []string // names of signature-* children
}

// FITConfig is a node of /configurations. Refs holds every property that names
// images (kernel, fdt, ramdisk, firmware, loadables, ...), in node order.
type FITConfig struct {
	Name        string
	Description string
	Refs        []FITRef
	Compatible  []string
	Signatures  []string // reader only
}

// FITRef is a configuration property that names images.
type FITRef struct {
	Prop  string
	Names []string
}

// Ref returns the images the property prop names.
func (c *FITConfig) Ref(prop string) []string {
	for _, r := range c.Refs {
		if r.Prop == prop {
			return r.Names
		}
	}
	return nil
}

// fitRefProps are the configuration properties that name images.
var fitRefProps = []string{"kernel", "firmware", "ramdisk", "fdt", "loadables", "script", "setup", "fpga", "standalone"}

// FIT is a parsed FIT.
type FIT struct {
	Description string
	Time        uint32
	HasTime     bool
	Images      []FITImage
	Configs     []FITConfig
	Default     string
	// StructSize is the totalsize of the devicetree blob.
	StructSize uint32
}

// Image returns the image called name, or nil.
func (f *FIT) Image(name string) *FITImage {
	for i := range f.Images {
		if f.Images[i].Name == name {
			return &f.Images[i]
		}
	}
	return nil
}

// FITOptions describes a FIT to write.
type FITOptions struct {
	Description  string
	Time         uint32
	AddressCells int // 1 (default) or 2: the size of load and entry
	Images       []FITImage
	Configs      []FITConfig
	Default      string // the default configuration; the first when empty and there are any
	// External puts the data after the structure (mkimage -E): data-size and
	// data-offset replace data. Align is mkimage -B: the structure and every
	// image are padded to it (a power of two, at least 4). Position (mkimage -p,
	// with HasPosition) puts the data at an absolute file position instead, in
	// data-position. All three need External.
	External    bool
	Align       uint32
	Position    uint64
	HasPosition bool
}

// fitHashLen is the size of each algorithm's value (spec 5.4.1).
var fitHashLen = map[string]int{"crc16-ccitt": 2, "crc32": 4, "md5": 16, "sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

// fitSum computes the hash of data, and reports whether it can.
func fitSum(algo string, data []byte) ([]byte, bool) {
	switch algo {
	case "crc32":
		return binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(data)), true
	case "sha1":
		s := sha1.Sum(data)
		return s[:], true
	case "sha256":
		s := sha256.Sum256(data)
		return s[:], true
	case "sha384":
		s := sha512.Sum384(data)
		return s[:], true
	case "sha512":
		s := sha512.Sum512(data)
		return s[:], true
	case "md5":
		s := md5.Sum(data)
		return s[:], true
	}
	return nil, false
}

func alignUp(n, a uint64) uint64 { return (n + a - 1) &^ (a - 1) }

// AppendFIT appends the FIT o describes to dst and returns it, laid out as
// mkimage lays it out: the devicetree blob, then (External) the images, each
// padded to the alignment, from the structure's end aligned the same way.
func AppendFIT(dst []byte, o FITOptions) ([]byte, error) {
	cells := o.AddressCells
	switch cells {
	case 0:
		cells = 1
	case 1, 2:
	default:
		return nil, fmt.Errorf("fit: #address-cells %d: want 1 or 2", o.AddressCells)
	}
	// The structure is padded to 4 (or -B); mkimage pads each image to 8 (or -B),
	// measured against mkimage 2026.10 with sizes 1001, 301 and 21.
	align, dalign := uint64(4), uint64(8)
	if !o.External && (o.Align != 0 || o.HasPosition) {
		return nil, errors.New("fit: alignment and position need external data")
	}
	if o.Align != 0 {
		if o.Align&(o.Align-1) != 0 {
			return nil, fmt.Errorf("fit: alignment %d is not a power of two", o.Align)
		}
		align = max(align, uint64(o.Align))
		dalign = align
	}
	if o.HasPosition {
		align = max(align, dalign) // mkimage -p pads the structure to 8 as well
	}
	if len(o.Images) == 0 {
		return nil, errors.New("fit: no images")
	}
	t := fdt.New()
	root := t.Root
	if err := root.SetUint32("timestamp", o.Time); err != nil {
		return nil, err
	}
	if err := root.SetString("description", o.Description); err != nil {
		return nil, err
	}
	if err := root.SetUint32("#address-cells", uint32(cells)); err != nil {
		return nil, err
	}
	images, _ := root.AddChild("images")
	var store, total uint64 // the data's size so far (aligned), and the sum of the sizes
	var stored int
	for i := range o.Images {
		im := &o.Images[i]
		if im.Type == "" {
			return nil, fmt.Errorf("fit: image %q has no type", im.Name)
		}
		if uint64(len(im.Data)) > math.MaxUint32 {
			return nil, fmt.Errorf("fit: image %q is %d bytes, above the 4 GiB a FIT holds", im.Name, len(im.Data))
		}
		n, err := images.AddChild(im.Name)
		if err != nil {
			return nil, fmt.Errorf("fit: image %q: %w", im.Name, err)
		}
		if err := writeFITImage(n, im, cells, o, &store, dalign); err != nil {
			return nil, fmt.Errorf("fit: image %q: %w", im.Name, err)
		}
		total += uint64(len(im.Data))
		stored += len(im.Data)
	}
	if len(o.Configs) > 0 {
		cn, _ := root.AddChild("configurations")
		def := o.Default
		if def == "" {
			def = o.Configs[0].Name
		}
		if !slices.ContainsFunc(o.Configs, func(c FITConfig) bool { return c.Name == def }) {
			return nil, fmt.Errorf("fit: default configuration %q does not exist", def)
		}
		_ = cn.SetString("default", def)
		for _, c := range o.Configs {
			n, err := cn.AddChild(c.Name)
			if err != nil {
				return nil, fmt.Errorf("fit: configuration %q: %w", c.Name, err)
			}
			if c.Description != "" {
				_ = n.SetString("description", c.Description)
			}
			for _, r := range c.Refs {
				for _, name := range r.Names {
					if !slices.ContainsFunc(o.Images, func(im FITImage) bool { return im.Name == name }) {
						return nil, fmt.Errorf("fit: configuration %q: %s names %q, which is not an image", c.Name, r.Prop, name)
					}
				}
				_ = n.SetStringList(r.Prop, r.Names...)
			}
			if len(c.Compatible) > 0 {
				_ = n.SetStringList("compatible", c.Compatible...)
			}
		}
	} else if o.Default != "" {
		return nil, errors.New("fit: a default configuration without configurations")
	}

	base := len(dst)
	room := 8192 + stored + int(align) // the data goes into the blob (embedded) or after it (external)
	if o.External {
		room += int(store - total) // the padding of every image
	}
	dst = slices.Grow(dst, room)
	dst, err := t.AppendMarshal(dst)
	if err != nil {
		return nil, err
	}
	if !o.External {
		return dst, nil
	}
	// mkimage -E: the structure is padded to the alignment (the header's
	// totalsize says so), the data follows, each image padded to it too.
	blob := uint64(len(dst) - base)
	padded := alignUp(blob, align)
	if o.HasPosition && o.Position < padded {
		return nil, fmt.Errorf("fit: data position %d is inside the structure, which is %d bytes", o.Position, padded)
	}
	dst = append(dst, make([]byte, padded-blob)...)
	binary.BigEndian.PutUint32(dst[base+4:], uint32(padded))
	if o.HasPosition {
		dst = append(dst, make([]byte, o.Position-padded)...)
	}
	for i := range o.Images {
		dst = append(dst, o.Images[i].Data...)
		dst = append(dst, make([]byte, alignUp(uint64(len(o.Images[i].Data)), dalign)-uint64(len(o.Images[i].Data)))...)
	}
	return dst, nil
}

// WriteFIT is AppendFIT to a new buffer.
func WriteFIT(o FITOptions) ([]byte, error) { return AppendFIT(nil, o) }

// writeFITImage fills the node of one image; store is the offset (or position,
// relative to the first image) of the next one.
func writeFITImage(n *fdt.Node, im *FITImage, cells int, o FITOptions, store *uint64, align uint64) error {
	size := uint64(len(im.Data))
	if o.External {
		if err := n.SetUint32("data-size", uint32(size)); err != nil {
			return err
		}
		if o.HasPosition {
			if o.Position+*store+size > math.MaxUint32 && cells == 1 {
				return errors.New("data position does not fit one address cell")
			}
			if err := n.SetCell("data-position", cells, o.Position+*store); err != nil {
				return err
			}
		} else {
			if *store > math.MaxUint32 {
				return errors.New("data offset does not fit 32 bits")
			}
			if err := n.SetUint32("data-offset", uint32(*store)); err != nil {
				return err
			}
		}
		*store += alignUp(size, align)
	}
	_ = n.SetString("description", im.Description)
	_ = n.SetString("type", im.Type)
	if im.Arch != "" {
		_ = n.SetString("arch", im.Arch)
	}
	if im.OS != "" {
		_ = n.SetString("os", im.OS)
	}
	_ = n.SetString("compression", cmpOr(im.Comp, "none"))
	if im.HasLoad {
		if err := n.SetCell("load", cells, im.Load); err != nil {
			return fmt.Errorf("load: %w", err)
		}
	}
	if im.HasEntry {
		if err := n.SetCell("entry", cells, im.Entry); err != nil {
			return fmt.Errorf("entry: %w", err)
		}
	}
	if !o.External {
		_ = n.Set("data", im.Data)
	}
	for i, h := range im.Hashes {
		sum, ok := fitSum(h.Algo, im.Data)
		if !ok {
			return fmt.Errorf("%w %q", ErrFITAlgo, h.Algo)
		}
		hn, err := n.AddChild(cmpOr(h.Name, fmt.Sprintf("hash-%d", i+1)))
		if err != nil {
			return err
		}
		_ = hn.SetString("algo", h.Algo)
		_ = hn.Set("value", sum)
	}
	return nil
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// exactChild is the child named name, with none of the unit-address matching
// of fdt's Child: a FIT reference names a node, whole.
func exactChild(n *fdt.Node, name string) *fdt.Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// noAliases refuses two siblings that differ only by a unit address
// ("kernel" and "kernel@1"): a reader that resolves a name without its unit
// address would pick either (CVE-2021-27138).
func noAliases(n *fdt.Node, what string) error {
	seen := make(map[string]string, len(n.Children))
	for _, c := range n.Children {
		base, _, _ := strings.Cut(c.Name, "@")
		if prev, ok := seen[base]; ok {
			return fmt.Errorf("fit: %w: %s %q and %q differ only by a unit address", ErrSyntax, what, prev, c.Name)
		}
		seen[base] = c.Name
	}
	return nil
}

func fitErr(format string, a ...any) error {
	return fmt.Errorf("fit: %w: "+format, append([]any{ErrSyntax}, a...)...)
}

// addrProp reads load, entry or data-position: one or two cells, by length, as
// U-Boot does.
func addrProp(n *fdt.Node, name string) (uint64, bool, error) {
	p := n.Prop(name)
	if p == nil {
		return 0, false, nil
	}
	switch len(p.Value) {
	case 4:
		return uint64(binary.BigEndian.Uint32(p.Value)), true, nil
	case 8:
		return binary.BigEndian.Uint64(p.Value), true, nil
	}
	return 0, false, fitErr("%s is %d bytes, want 4 or 8", name, len(p.Value))
}

func optString(n *fdt.Node, name string) string {
	s, _ := n.String(name)
	return s
}

// ParseFIT reads a FIT. It refuses a blob that is not a well-formed FIT
// (ErrSyntax, wrapping fdt's error for a bad blob), data outside the file
// (ErrRange), external data that overlaps the structure or another image,
// references to images that do not exist, siblings that differ only by a unit
// address and an address range that wraps. Hashes are not checked: that is
// Verify. The images' Data are views of data, which must not change while the
// FIT is in use.
func ParseFIT(data []byte) (*FIT, error) {
	t, err := fdt.ParseShared(data)
	if err != nil {
		return nil, fmt.Errorf("fit: %w: %w", ErrSyntax, err)
	}
	hdr, _ := fdt.ParseHeader(data) // Parse checked it
	f := &FIT{Description: optString(t.Root, "description"), StructSize: hdr.TotalSize}
	if v, err := t.Root.Uint32("timestamp"); err == nil {
		f.Time, f.HasTime = v, true
	}
	if err := noAliases(t.Root, "node"); err != nil {
		return nil, err
	}
	imgs := exactChild(t.Root, "images")
	if imgs == nil {
		return nil, fitErr("no /images node")
	}
	if err := noAliases(imgs, "image"); err != nil {
		return nil, err
	}
	type extent struct {
		lo, hi uint64
		name   string
	}
	var ext []extent
	store := alignUp(uint64(hdr.TotalSize), 4)
	f.Images = make([]FITImage, 0, len(imgs.Children))
	for _, n := range imgs.Children {
		im := FITImage{Name: n.Name, Description: optString(n, "description"), Type: optString(n, "type"),
			Arch: optString(n, "arch"), OS: optString(n, "os"), Comp: optString(n, "compression")}
		if n.Prop("type") == nil || n.Prop("compression") == nil {
			return nil, fitErr("image %q lacks type or compression", n.Name)
		}
		var lerr error
		if im.Load, im.HasLoad, lerr = addrProp(n, "load"); lerr != nil {
			return nil, lerr
		}
		if im.Entry, im.HasEntry, lerr = addrProp(n, "entry"); lerr != nil {
			return nil, lerr
		}
		dp, off, pos, sz := n.Prop("data"), n.Prop("data-offset"), n.Prop("data-position"), n.Prop("data-size")
		switch c := b2i(dp != nil) + b2i(off != nil) + b2i(pos != nil); {
		case c == 0:
			return nil, fitErr("image %q has no data", n.Name)
		case c > 1:
			return nil, fitErr("image %q says where its data is more than once (data, data-offset, data-position)", n.Name)
		}
		switch {
		case dp != nil:
			im.Data = dp.Value
			if sz != nil {
				if v, err := n.Uint32("data-size"); err != nil || uint64(v) != uint64(len(dp.Value)) {
					return nil, fitErr("image %q: data-size differs from the %d bytes of data", n.Name, len(dp.Value))
				}
			}
		default:
			if sz == nil {
				return nil, fitErr("image %q: external data without data-size", n.Name)
			}
			size, err := n.Uint32("data-size")
			if err != nil {
				return nil, fitErr("image %q: data-size: %v", n.Name, err)
			}
			var lo uint64
			if off != nil {
				o, err := n.Uint32("data-offset")
				if err != nil {
					return nil, fitErr("image %q: data-offset: %v", n.Name, err)
				}
				lo = store + uint64(o)
			} else {
				p, _, err := addrProp(n, "data-position")
				if err != nil {
					return nil, err
				}
				lo = p
				if lo < uint64(hdr.TotalSize) {
					return nil, fitErr("image %q: data-position %d is inside the structure (%d bytes)", n.Name, lo, hdr.TotalSize)
				}
			}
			if lo > uint64(len(data)) || uint64(size) > uint64(len(data))-lo {
				return nil, fmt.Errorf("fit: %w: image %q: %d bytes at %d, the file is %d bytes", ErrRange, n.Name, size, lo, len(data))
			}
			im.Data, im.External = data[lo:lo+uint64(size):lo+uint64(size)], true
			if size > 0 {
				ext = append(ext, extent{lo, lo + uint64(size), n.Name})
			}
		}
		if im.HasLoad && im.Load > math.MaxUint64-uint64(len(im.Data)) {
			return nil, fmt.Errorf("fit: %w: image %q: %d bytes at 0x%x wrap the address space", ErrRange, n.Name, len(im.Data), im.Load)
		}
		for _, c := range n.Children {
			switch {
			case strings.HasPrefix(c.Name, "hash"):
				im.Hashes = append(im.Hashes, FITHash{Name: c.Name, Algo: optString(c, "algo"), Value: propBytes(c, "value")})
			case strings.HasPrefix(c.Name, "signature"):
				im.Signatures = append(im.Signatures, c.Name)
			}
		}
		f.Images = append(f.Images, im)
	}
	slices.SortFunc(ext, func(a, b extent) int { return cmpU64(a.lo, b.lo) })
	for i := 1; i < len(ext); i++ {
		if ext[i].lo < ext[i-1].hi {
			return nil, fitErr("external data of %q and %q overlap", ext[i-1].name, ext[i].name)
		}
	}
	if cn := exactChild(t.Root, "configurations"); cn != nil {
		if err := noAliases(cn, "configuration"); err != nil {
			return nil, err
		}
		if d, err := cn.String("default"); err == nil {
			f.Default = d
		}
		if f.Default != "" && exactChild(cn, f.Default) == nil {
			return nil, fitErr("default configuration %q does not exist", f.Default)
		}
		for _, n := range cn.Children {
			c := FITConfig{Name: n.Name, Description: optString(n, "description")}
			c.Compatible, _ = n.StringList("compatible")
			for _, p := range fitRefProps {
				if n.Prop(p) == nil {
					continue
				}
				names, err := n.StringList(p)
				if err != nil {
					return nil, fitErr("configuration %q: %s: %v", n.Name, p, err)
				}
				for _, name := range names {
					if f.Image(name) == nil {
						return nil, fitErr("configuration %q: %s names %q, which is not an image", n.Name, p, name)
					}
				}
				c.Refs = append(c.Refs, FITRef{Prop: p, Names: names})
			}
			for _, ch := range n.Children {
				if strings.HasPrefix(ch.Name, "signature") {
					c.Signatures = append(c.Signatures, ch.Name)
				}
			}
			f.Configs = append(f.Configs, c)
		}
	}
	return f, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func propBytes(n *fdt.Node, name string) []byte {
	if p := n.Prop(name); p != nil {
		return p.Value
	}
	return nil
}

// FITVerifyOptions tunes Verify.
type FITVerifyOptions struct {
	// RequireHash refuses an image without a hash node.
	RequireHash bool
	// AllowSignatures lets a FIT with signature nodes through: they are not
	// checked either way.
	AllowSignatures bool
}

// Verify recomputes every hash node of every image from the image's stored
// bytes and compares it with the node's value. All differences are returned,
// joined: ErrChecksum for a value that differs, ErrSyntax for a hash node
// without algo or value or with a value of the wrong length, ErrFITAlgo for an
// algorithm it cannot compute (crc16-ccitt), ErrFITSignature and ErrFITNoHash
// as the options say. A pass therefore means that every claim the FIT makes
// about its data was checked.
func (f *FIT) Verify(o FITVerifyOptions) error {
	var errs []error
	for i := range f.Images {
		im := &f.Images[i]
		if len(im.Signatures) > 0 && !o.AllowSignatures {
			errs = append(errs, fmt.Errorf("fit: image %q: %w (%s)", im.Name, ErrFITSignature, strings.Join(im.Signatures, ", ")))
		}
		if len(im.Hashes) == 0 && o.RequireHash {
			errs = append(errs, fmt.Errorf("fit: image %q: %w", im.Name, ErrFITNoHash))
		}
		for _, h := range im.Hashes {
			want, ok := fitHashLen[h.Algo]
			switch {
			case h.Algo == "" || h.Value == nil:
				errs = append(errs, fitErr("image %q: %s has no algo or no value", im.Name, h.Name))
			case !ok:
				errs = append(errs, fmt.Errorf("fit: image %q: %s: %w %q", im.Name, h.Name, ErrFITAlgo, h.Algo))
			case len(h.Value) != want:
				errs = append(errs, fitErr("image %q: %s: a %s value is %d bytes, not %d", im.Name, h.Name, h.Algo, want, len(h.Value)))
			default:
				sum, can := fitSum(h.Algo, im.Data)
				switch {
				case !can:
					errs = append(errs, fmt.Errorf("fit: image %q: %s: %w %q", im.Name, h.Name, ErrFITAlgo, h.Algo))
				case !bytes.Equal(sum, h.Value):
					errs = append(errs, fmt.Errorf("fit: image %q: %s: %w: %s is %x, the node says %x", im.Name, h.Name, ErrChecksum, h.Algo, sum, h.Value))
				}
			}
		}
	}
	if !o.AllowSignatures {
		for _, c := range f.Configs {
			if len(c.Signatures) > 0 {
				errs = append(errs, fmt.Errorf("fit: configuration %q: %w (%s)", c.Name, ErrFITSignature, strings.Join(c.Signatures, ", ")))
			}
		}
	}
	return errors.Join(errs...)
}

// Names as U-Boot prints them for a FIT (boot/image-fit.c and image.c).
var (
	fitArchNames = map[string]string{"arm": "ARM", "arm64": "AArch64", "x86": "Intel x86", "x86_64": "AMD x86_64",
		"riscv": "RISC-V", "mips": "MIPS", "ppc": "PowerPC", "loongarch": "LoongArch"}
	fitOSNames = map[string]string{"linux": "Linux", "u-boot": "U-Boot", "openbsd": "OpenBSD", "netbsd": "NetBSD",
		"freebsd": "FreeBSD", "vxworks": "VxWorks", "rtems": "RTEMS", "arm-trusted-firmware": "ARM Trusted Firmware",
		"opensbi": "RISC-V OpenSBI"}
	fitTypeNames = map[string]string{"standalone": "Standalone Program", "kernel": "Kernel Image", "ramdisk": "RAMDisk Image",
		"multi": "Multi-File Image", "firmware": "Firmware", "script": "Script", "filesystem": "Filesystem Image",
		"flat_dt": "Flat Device Tree", "kernel_noload": "Kernel Image (no loading done)", "fpga": "FPGA Image"}
	fitCompNames = map[string]string{"none": "uncompressed", "gzip": "gzip compressed", "bzip2": "bzip2 compressed",
		"lzma": "lzma compressed", "lzo": "lzo compressed", "lz4": "lz4 compressed", "zstd": "zstd compressed"}
)

func fitName(m map[string]string, k, unknown string) string {
	if s, ok := m[k]; ok {
		return s
	}
	return unknown
}

// Listing is what `mkimage -l` prints for the FIT.
func (f *FIT) Listing() string {
	var b strings.Builder
	stamp := func(t uint32) string { return time.Unix(int64(t), 0).UTC().Format("Mon Jan _2 15:04:05 2006") }
	fmt.Fprintf(&b, "FIT description: %s\n", f.Description)
	if f.HasTime {
		fmt.Fprintf(&b, "Created:         %s\n", stamp(f.Time))
	}
	addr := func(label string, v uint64, ok bool) {
		if ok {
			fmt.Fprintf(&b, "  %-13s 0x%08x\n", label, v)
		} else {
			fmt.Fprintf(&b, "  %-13s unavailable\n", label)
		}
	}
	for i := range f.Images {
		im := &f.Images[i]
		fmt.Fprintf(&b, " Image %d (%s)\n", i, im.Name)
		fmt.Fprintf(&b, "  Description:  %s\n", im.Description)
		if f.HasTime {
			fmt.Fprintf(&b, "  Created:      %s\n", stamp(f.Time))
		}
		fmt.Fprintf(&b, "  Type:         %s\n", fitName(fitTypeNames, im.Type, "Unknown Image"))
		fmt.Fprintf(&b, "  Compression:  %s\n", fitName(fitCompNames, im.Comp, "unknown compression"))
		fmt.Fprintf(&b, "  Data Size:    %s\n", sizeText(uint32(len(im.Data))))
		switch im.Type {
		case "kernel", "ramdisk", "flat_dt", "firmware", "standalone":
			fmt.Fprintf(&b, "  Architecture: %s\n", fitName(fitArchNames, im.Arch, "Unknown Architecture"))
		}
		switch im.Type {
		case "kernel", "ramdisk", "firmware":
			fmt.Fprintf(&b, "  OS:           %s\n", fitName(fitOSNames, im.OS, "Unknown OS"))
		}
		switch im.Type {
		case "kernel", "ramdisk", "firmware", "standalone", "fpga":
			addr("Load Address:", im.Load, im.HasLoad)
		case "flat_dt":
			if im.HasLoad {
				addr("Load Address:", im.Load, true)
			}
		}
		switch im.Type {
		case "kernel", "ramdisk", "standalone":
			addr("Entry Point:", im.Entry, im.HasEntry)
		}
		for _, h := range im.Hashes {
			fmt.Fprintf(&b, "  Hash algo:    %s\n", h.Algo)
			fmt.Fprintf(&b, "  Hash value:   %s\n", hex.EncodeToString(h.Value))
		}
	}
	if f.Default != "" {
		fmt.Fprintf(&b, " Default Configuration: '%s'\n", f.Default)
	}
	list := func(label string, names []string) {
		for i, n := range names {
			if i == 0 {
				fmt.Fprintf(&b, "  %-13s %s\n", label, n)
			} else {
				fmt.Fprintf(&b, "  %-13s %s\n", "", n)
			}
		}
	}
	for i := range f.Configs {
		c := &f.Configs[i]
		fmt.Fprintf(&b, " Configuration %d (%s)\n", i, c.Name)
		fmt.Fprintf(&b, "  Description:  %s\n", c.Description)
		if k := c.Ref("kernel"); len(k) > 0 {
			list("Kernel:", k[:1])
		} else {
			fmt.Fprintf(&b, "  Kernel:       unavailable\n")
		}
		list("Init Ramdisk:", c.Ref("ramdisk"))
		list("Firmware:", c.Ref("firmware"))
		list("FDT:", c.Ref("fdt"))
		list("Compatible:", c.Compatible)
		list("Loadables:", c.Ref("loadables"))
	}
	return b.String()
}

// FITArchName is the FIT "arch" string of a uImage architecture code ("" for
// one the FIT specification does not name here).
func FITArchName(code byte) string {
	switch code {
	case 2:
		return "arm"
	case 3:
		return "x86"
	case 5:
		return "mips"
	case 7:
		return "ppc"
	case 22:
		return "arm64"
	case 24:
		return "x86_64"
	case 26:
		return "riscv"
	case 27:
		return "loongarch"
	}
	return ""
}
