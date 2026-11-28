package main

import (
	"cmp"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/go-binfmt/fwimg"
)

// fitOptions are the flags of -O fit.
type fitFlags struct {
	hash     string   // --fit-hash: comma-separated algorithms
	external bool     // --fit-external
	align    string   // --fit-align
	position string   // --fit-position
	add      []string // --fit-add TYPE[@LOAD]:FILE
}

// set reports whether any FIT-only flag was given.
func (f *fitFlags) set() bool {
	return f.external || f.align != "" || f.position != "" || len(f.add) > 0 || f.hash != "sha256"
}

// fitTypeAlias maps the short names --fit-add takes to FIT image types, and the
// configuration property that names each.
var fitTypeAlias = map[string]string{"fdt": "flat_dt", "dtb": "flat_dt"}

func fitRefProp(typ string) string {
	switch typ {
	case "kernel", "kernel_noload", "ramdisk", "firmware", "script":
		return strings.TrimSuffix(typ, "_noload")
	case "flat_dt":
		return "fdt"
	}
	return "loadables"
}

// fit builds a FIT: the image (an ELF's program, say) as the kernel, with the
// hashes asked for, and every --fit-add file after it. One configuration names
// them all.
func fit(o *options, im *fwimg.Image, src *source, arch byte, hasEntry bool, entry uint64, fo fwimg.FlattenOptions) ([]byte, fwimg.FITOptions, error) {
	none := fwimg.FITOptions{}
	flat, base, err := im.Flat(fo.Pad, fo.MaxSize)
	if err != nil {
		return nil, none, err
	}
	switch {
	case im.UImage != nil:
		arch = cmp.Or(arch, im.UImage.Arch)
	case src.elf:
		arch = cmp.Or(arch, fwimg.ArchFromELF(src.machine))
	case arch == 0:
		return nil, none, usageErr{"--uimage-arch is required: the input does not say which architecture it is for"}
	}
	an := fwimg.FITArchName(arch)
	if an == "" {
		return nil, none, usageErr{fmt.Sprintf("architecture code %d has no FIT name", arch)}
	}
	if !hasEntry {
		return nil, none, usageErr{"--entry is required: the input has no start address"}
	}
	var hashes []fwimg.FITHash
	for _, a := range strings.Split(o.fit.hash, ",") {
		hashes = append(hashes, fwimg.FITHash{Algo: strings.TrimSpace(a)})
	}
	fo2 := fwimg.FITOptions{
		Description: cmp.Or(o.name, im.Name, "fwimg FIT"), Time: o.stamp, External: o.fit.external,
		Images: []fwimg.FITImage{{
			Name: "kernel-1", Description: cmp.Or(o.name, im.Name, "kernel"), Type: "kernel", Arch: an, OS: "linux", Comp: "none",
			Data: flat, Load: base, Entry: entry, HasLoad: true, HasEntry: true, Hashes: hashes,
		}},
	}
	if base > math.MaxUint32 || entry > math.MaxUint32 {
		fo2.AddressCells = 2
	}
	if o.fit.align != "" {
		// mkimage -B takes hex; so does this flag, with or without 0x.
		h, herr := parseUint("fit-align", "0x"+strings.TrimPrefix(strings.TrimPrefix(o.fit.align, "0x"), "0X"), 32)
		if herr != nil {
			return nil, none, herr
		}
		fo2.Align = uint32(h)
	}
	if o.fit.position != "" {
		if fo2.Position, err = parseUint("fit-position", o.fit.position, 32); err != nil {
			return nil, none, err
		}
		fo2.HasPosition = true
	}
	refs := map[string][]string{"kernel": {"kernel-1"}}
	order := []string{"kernel"}
	counts := map[string]int{"kernel": 1}
	for _, spec := range o.fit.add {
		head, file, ok := strings.Cut(spec, ":")
		if !ok || file == "" {
			return nil, none, usageErr{fmt.Sprintf("--fit-add %q: want TYPE[@LOAD]:FILE", spec)}
		}
		typ, loadS, hasLoad := strings.Cut(head, "@")
		typ = cmp.Or(fitTypeAlias[typ], typ)
		var load uint64
		if hasLoad {
			if load, err = parseUint("fit-add", loadS, 64); err != nil {
				return nil, none, err
			}
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, none, err
		}
		short := strings.TrimSuffix(typ, "_noload")
		if typ == "flat_dt" {
			short = "fdt"
		}
		counts[short]++
		add := fwimg.FITImage{
			Name: fmt.Sprintf("%s-%d", short, counts[short]), Description: file, Type: typ, Arch: an, Comp: "none",
			Data: data, Load: load, HasLoad: hasLoad, Hashes: hashes,
		}
		if typ == "ramdisk" || typ == "firmware" {
			add.OS = "linux"
		}
		fo2.Images = append(fo2.Images, add)
		p := fitRefProp(typ)
		if _, seen := refs[p]; !seen {
			order = append(order, p)
		}
		refs[p] = append(refs[p], add.Name)
	}
	conf := fwimg.FITConfig{Name: "conf-1", Description: cmp.Or(o.name, im.Name, "fwimg configuration")}
	for _, p := range order {
		names := refs[p]
		if p != "loadables" && p != "kernel" {
			names = names[:1] // a configuration has one kernel, ramdisk, fdt, firmware, script
		}
		conf.Refs = append(conf.Refs, fwimg.FITRef{Prop: p, Names: names})
	}
	fo2.Configs = []fwimg.FITConfig{conf}
	out, err := fwimg.WriteFIT(fo2)
	return out, fo2, err
}

// fitCheck reads a written FIT back: it parses, and every hash it carries
// matches its data.
func fitCheck(b []byte) error {
	f, err := fwimg.ParseFIT(b)
	if err != nil {
		return err
	}
	return f.Verify(fwimg.FITVerifyOptions{})
}

// fitJSON is the machine-readable description of a FIT: no data, only its size
// and hashes.
type fitJSON struct {
	Format      string          `json:"format"`
	Description string          `json:"description"`
	Time        *uint32         `json:"timestamp,omitempty"`
	Default     string          `json:"default,omitempty"`
	Size        int             `json:"size"`
	Images      []fitImageJSON  `json:"images"`
	Configs     []fitConfigJSON `json:"configurations"`
}

type fitImageJSON struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Type        string        `json:"type"`
	Arch        string        `json:"arch,omitempty"`
	OS          string        `json:"os,omitempty"`
	Compression string        `json:"compression"`
	Size        int           `json:"size"`
	Load        *uint64       `json:"load,omitempty"`
	Entry       *uint64       `json:"entry,omitempty"`
	External    bool          `json:"external"`
	Hashes      []fitHashJSON `json:"hashes,omitempty"`
	Signatures  []string      `json:"signatures,omitempty"`
}

type fitHashJSON struct {
	Algo  string `json:"algo"`
	Value string `json:"value"`
}

type fitConfigJSON struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Refs        map[string][]string `json:"references,omitempty"`
	Compatible  []string            `json:"compatible,omitempty"`
	Signatures  []string            `json:"signatures,omitempty"`
}

func fitDescribe(f *fwimg.FIT, size int) []byte {
	j := fitJSON{Format: fwimg.FormatFIT, Description: f.Description, Default: f.Default, Size: size, Images: []fitImageJSON{}, Configs: []fitConfigJSON{}}
	if f.HasTime {
		t := f.Time
		j.Time = &t
	}
	for i := range f.Images {
		im := &f.Images[i]
		x := fitImageJSON{Name: im.Name, Description: im.Description, Type: im.Type, Arch: im.Arch, OS: im.OS, Compression: im.Comp,
			Size: len(im.Data), External: im.External, Signatures: im.Signatures}
		if im.HasLoad {
			v := im.Load
			x.Load = &v
		}
		if im.HasEntry {
			v := im.Entry
			x.Entry = &v
		}
		for _, h := range im.Hashes {
			x.Hashes = append(x.Hashes, fitHashJSON{Algo: h.Algo, Value: hex.EncodeToString(h.Value)})
		}
		j.Images = append(j.Images, x)
	}
	for _, c := range f.Configs {
		x := fitConfigJSON{Name: c.Name, Description: c.Description, Compatible: c.Compatible, Signatures: c.Signatures}
		if len(c.Refs) > 0 {
			x.Refs = map[string][]string{}
			for _, r := range c.Refs {
				x.Refs[r.Prop] = r.Names
			}
		}
		j.Configs = append(j.Configs, x)
	}
	b, _ := json.MarshalIndent(j, "", "  ")
	return append(b, '\n')
}

// errNoFITManifest is the refusal of --manifest for a FIT, which carries its
// own hashes.
var errNoFITManifest = errors.New("a FIT carries its own hashes: fwimg verify checks them without --manifest")
