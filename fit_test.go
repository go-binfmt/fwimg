package fwimg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/go-binfmt/fdt"
)

// smallFIT is an embedded FIT with a kernel, a device tree and a ramdisk.
func smallFIT(t testing.TB) []byte {
	t.Helper()
	b, err := WriteFIT(fitCase())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// edit parses blob, lets fn change the tree and marshals it again. The blob
// must be an embedded FIT: the data lives in the tree.
func edit(t testing.TB, blob []byte, fn func(root, images, conf *fdt.Node)) []byte {
	t.Helper()
	tr, err := fdt.Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	fn(tr.Root, tr.Root.Child("images"), tr.Root.Child("configurations"))
	out, err := tr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFITRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*FITOptions)
	}{
		{"embedded", func(o *FITOptions) {}},
		{"external", func(o *FITOptions) { o.External = true }},
		{"aligned", func(o *FITOptions) { o.External, o.Align = true, 0x100 }},
		{"positioned", func(o *FITOptions) { o.External, o.Position, o.HasPosition = true, 0x2001, true }},
		{"2cells", func(o *FITOptions) { o.AddressCells = 2; o.Images[0].Load = 0x1_0000_0000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := fitCase()
			tc.set(&o)
			b, err := WriteFIT(o)
			if err != nil {
				t.Fatal(err)
			}
			f, err := ParseFIT(b)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Verify(FITVerifyOptions{RequireHash: false}); err != nil {
				t.Fatal(err)
			}
			if len(f.Images) != 4 || f.Description != "test" || !f.HasTime || f.Time != 1700000000 {
				t.Fatalf("parsed %+v", f)
			}
			k := f.Image("kernel-1")
			if k == nil || !bytes.Equal(k.Data, o.Images[0].Data) || k.Load != o.Images[0].Load || !k.HasEntry || len(k.Hashes) != 2 {
				t.Fatalf("kernel %+v", k)
			}
			if k.External != o.External {
				t.Errorf("External = %v", k.External)
			}
			if f.Default != "conf-1" || len(f.Configs) != 1 || f.Configs[0].Ref("kernel")[0] != "kernel-1" {
				t.Errorf("configurations %+v", f.Configs)
			}
			if !strings.Contains(f.Listing(), "Image 0 (kernel-1)") {
				t.Errorf("listing:\n%s", f.Listing())
			}
			// Appending leaves what precedes untouched and is the same bytes.
			c, err := AppendFIT([]byte("xy"), o)
			if err != nil || string(c[:2]) != "xy" || !bytes.Equal(c[2:], b) {
				t.Errorf("AppendFIT: %v", err)
			}
		})
	}
}

func TestFITWriteRefusals(t *testing.T) {
	for name, set := range map[string]func(*FITOptions){
		"no images":          func(o *FITOptions) { o.Images = nil },
		"no type":            func(o *FITOptions) { o.Images[0].Type = "" },
		"align not pow2":     func(o *FITOptions) { o.External, o.Align = true, 12 },
		"align w/o external": func(o *FITOptions) { o.Align = 8 },
		"position w/o ext":   func(o *FITOptions) { o.Position, o.HasPosition = 0x1000, true },
		"position inside":    func(o *FITOptions) { o.External, o.Position, o.HasPosition = true, 16, true },
		"bad cells":          func(o *FITOptions) { o.AddressCells = 3 },
		"dangling ref":       func(o *FITOptions) { o.Configs[0].Refs[0].Names = []string{"nope"} },
		"bad default":        func(o *FITOptions) { o.Default = "nope" },
		"duplicate image":    func(o *FITOptions) { o.Images[1].Name = o.Images[0].Name },
		"unknown hash":       func(o *FITOptions) { o.Images[0].Hashes = []FITHash{{Algo: "rot13"}} },
		"wide load, 1 cell":  func(o *FITOptions) { o.Images[0].Load = 1 << 33 },
	} {
		t.Run(name, func(t *testing.T) {
			o := fitCase()
			set(&o)
			if _, err := WriteFIT(o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestFITDetect(t *testing.T) {
	if got := Detect(smallFIT(t)); got != FormatFIT {
		t.Errorf("Detect = %q", got)
	}
}

// --- one regression test per FIT CVE of docs/spec-notes.md section 6 ---

// CVE-2018-1000205, CVE-2020-10648, CVE-2021-27097: an image whose data was
// changed after the hash was computed (or whose hash was dropped from the
// check) must not verify.
func TestFITCVE_2018_1000205_2020_10648_2021_27097(t *testing.T) {
	b := edit(t, smallFIT(t), func(root, images, _ *fdt.Node) {
		d, _ := images.Child("kernel-1").Bytes("data")
		d[10] ^= 0xff
		_ = images.Child("kernel-1").Set("data", d)
	})
	f, err := ParseFIT(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(FITVerifyOptions{}); !errors.Is(err, ErrChecksum) {
		t.Fatalf("tampered data verified: %v", err)
	}
	// A hash value that was changed instead.
	b = edit(t, smallFIT(t), func(root, images, _ *fdt.Node) {
		h := images.Child("kernel-1").Child("hash-2")
		v, _ := h.Bytes("value")
		v[0] ^= 1
		_ = h.Set("value", v)
	})
	if f, err = ParseFIT(b); err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(FITVerifyOptions{}); !errors.Is(err, ErrChecksum) {
		t.Fatalf("wrong hash verified: %v", err)
	}
	// Every difference is reported, not only the first.
	b = edit(t, smallFIT(t), func(root, images, _ *fdt.Node) {
		for _, n := range []string{"kernel-1", "fdt-1"} {
			d, _ := images.Child(n).Bytes("data")
			d[0] ^= 1
			_ = images.Child(n).Set("data", d)
		}
	})
	f, _ = ParseFIT(b)
	if err := f.Verify(FITVerifyOptions{}); err == nil || !strings.Contains(err.Error(), "kernel-1") || !strings.Contains(err.Error(), "fdt-1") {
		t.Errorf("not every failure reported: %v", err)
	}
	// An image without any hash is refused when one is required.
	f, _ = ParseFIT(smallFIT(t))
	if err := f.Verify(FITVerifyOptions{RequireHash: true}); !errors.Is(err, ErrFITNoHash) {
		t.Errorf("hashless image under RequireHash: %v", err)
	}
	// A configuration that names an image that is not there.
	b = edit(t, smallFIT(t), func(root, images, conf *fdt.Node) {
		_ = conf.Child("conf-1").SetString("kernel", "kernel-9")
	})
	if _, err := ParseFIT(b); !errors.Is(err, ErrSyntax) {
		t.Errorf("dangling reference: %v", err)
	}
	b = edit(t, smallFIT(t), func(root, images, conf *fdt.Node) { _ = conf.SetString("default", "conf-9") })
	if _, err := ParseFIT(b); !errors.Is(err, ErrSyntax) {
		t.Errorf("dangling default: %v", err)
	}
}

// CVE-2018-3968 and CVE-2024-38433: a header of another format is not a FIT,
// and nodes that claim a signature are not silently skipped.
func TestFITCVE_2018_3968_2024_38433(t *testing.T) {
	legacy := make([]byte, 64)
	binary.BigEndian.PutUint32(legacy, 0x27051956)
	if got := Detect(legacy); got == FormatFIT {
		t.Errorf("a legacy header detected as a FIT")
	}
	if _, err := ParseFIT(legacy); err == nil {
		t.Error("a legacy header parsed as a FIT")
	}
	for _, n := range []int{0, 3, 4, 39} {
		if _, err := ParseFIT(smallFIT(t)[:n]); err == nil {
			t.Errorf("%d bytes parsed", n)
		}
	}
	b := edit(t, smallFIT(t), func(root, images, conf *fdt.Node) {
		s, _ := images.Child("kernel-1").AddChild("signature-1")
		_ = s.SetString("algo", "sha256,rsa2048")
		c, _ := conf.Child("conf-1").AddChild("signature-1")
		_ = c.SetString("algo", "sha256,rsa2048")
	})
	f, err := ParseFIT(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(FITVerifyOptions{}); !errors.Is(err, ErrFITSignature) {
		t.Errorf("signature nodes not flagged: %v", err)
	}
	if err := f.Verify(FITVerifyOptions{AllowSignatures: true}); err != nil {
		t.Errorf("AllowSignatures: %v", err)
	}
}

// CVE-2021-27138: a node and a reference that differ only by a unit address
// are not the same node.
func TestFITCVE_2021_27138(t *testing.T) {
	// Two images that differ only by a unit address.
	b := edit(t, smallFIT(t), func(root, images, _ *fdt.Node) {
		n, _ := images.AddChild("kernel-1@1")
		_ = n.SetString("type", "kernel")
		_ = n.SetString("compression", "none")
		_ = n.Set("data", []byte("x"))
	})
	if _, err := ParseFIT(b); !errors.Is(err, ErrSyntax) {
		t.Errorf("aliased image names: %v", err)
	}
	// A reference that only matches once the unit address is dropped.
	b = edit(t, smallFIT(t), func(root, images, conf *fdt.Node) {
		images.Child("fdt-1").Name = "fdt-1@0"
		_ = conf.Child("conf-1").SetString("fdt", "fdt-1")
	})
	if _, err := ParseFIT(b); !errors.Is(err, ErrSyntax) {
		t.Errorf("reference to an aliased name: %v", err)
	}
	// ... and the writer does not make one.
	o := fitCase()
	o.Configs[0].Refs[0].Names = []string{"kernel"}
	if _, err := WriteFIT(o); err == nil {
		t.Error("the writer accepted a reference to a name that is not an image")
	}
}

// CVE-2023-39902: external data must stay inside the file and out of the
// structure, images must not overlap, and load + size must not wrap.
func TestFITCVE_2023_39902(t *testing.T) {
	o := fitCase()
	o.External = true
	ext := func(mut func(b []byte, store int)) []byte {
		b, err := WriteFIT(o)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	good := ext(nil)
	f, err := ParseFIT(good)
	if err != nil {
		t.Fatal(err)
	}
	if f.Image("kernel-1").Data == nil {
		t.Fatal("no data")
	}
	// Past the end of the file.
	long := edit2(t, good, func(images *fdt.Node) { _ = images.Child("ramdisk-1").SetUint32("data-size", 0x100000) })
	if _, err := ParseFIT(long); !errors.Is(err, ErrRange) {
		t.Errorf("data past the end: %v", err)
	}
	// The offset wraps 32 bits.
	wrap := edit2(t, good, func(images *fdt.Node) { _ = images.Child("ramdisk-1").SetUint32("data-offset", 0xfffffff0) })
	if _, err := ParseFIT(wrap); !errors.Is(err, ErrRange) {
		t.Errorf("offset near 4 GiB: %v", err)
	}
	// Inside the structure (a position of 0).
	op := fitCase()
	op.External, op.Position, op.HasPosition = true, 0x2001, true
	posd, err := WriteFIT(op)
	if err != nil {
		t.Fatal(err)
	}
	inside := edit2(t, posd, func(images *fdt.Node) { _ = images.Child("kernel-1").SetUint32("data-position", 0) })
	if _, err := ParseFIT(inside); err == nil {
		t.Error("data placed over the structure")
	}
	// Two images over the same bytes.
	over := edit2(t, good, func(images *fdt.Node) { _ = images.Child("fdt-1").SetUint32("data-offset", 0) })
	if _, err := ParseFIT(over); err == nil {
		t.Error("overlapping images")
	}
	// Both an embedded and an external data.
	both := edit2(t, good, func(images *fdt.Node) { _ = images.Child("fdt-1").Set("data", []byte("x")) })
	if _, err := ParseFIT(both); err == nil {
		t.Error("data and data-offset together")
	}
	// An embedded size that is not the data's.
	emb := edit(t, smallFIT(t), func(root, images, _ *fdt.Node) { _ = images.Child("fdt-1").SetUint32("data-size", 4) })
	if _, err := ParseFIT(emb); err == nil {
		t.Error("data-size not the length of data")
	}
	// load + size wraps the address space.
	o2 := fitCase()
	o2.AddressCells = 2
	o2.Images[0].Load = 0xffff_ffff_ffff_fff0
	b, err := WriteFIT(o2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFIT(b); !errors.Is(err, ErrRange) {
		t.Errorf("load + size wrapping: %v", err)
	}
}

// edit2 edits an external FIT's structure and keeps the data behind it.
func edit2(t testing.TB, blob []byte, fn func(images *fdt.Node)) []byte {
	t.Helper()
	h, err := fdt.ParseHeader(blob)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := fdt.Parse(blob[:h.TotalSize])
	if err != nil {
		t.Fatal(err)
	}
	fn(tr.Root.Child("images"))
	st, err := tr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the structure the size it was (positions stay valid); an offset
	// is relative to the store, which follows the structure wherever it ends.
	for uint32(len(st)) < h.TotalSize || len(st)%4 != 0 {
		st = append(st, 0)
	}
	binary.BigEndian.PutUint32(st[4:], uint32(len(st)))
	return append(st, blob[h.TotalSize:]...)
}

// CVE-2026-46728: a hash node must name a known algorithm, carry a value of
// that algorithm's length, and nothing that cannot be checked passes.
func TestFITCVE_2026_46728(t *testing.T) {
	for name, fn := range map[string]func(h *fdt.Node){
		"no algo":      func(h *fdt.Node) { h.DeleteProp("algo") },
		"no value":     func(h *fdt.Node) { h.DeleteProp("value") },
		"unknown algo": func(h *fdt.Node) { _ = h.SetString("algo", "rot13") },
		"short value":  func(h *fdt.Node) { _ = h.Set("value", []byte{1, 2}) },
		"empty value":  func(h *fdt.Node) { _ = h.Set("value", nil) },
		"long value":   func(h *fdt.Node) { _ = h.Set("value", make([]byte, 33)) },
		"swapped algo": func(h *fdt.Node) { _ = h.SetString("algo", "sha1") },
	} {
		t.Run(name, func(t *testing.T) {
			b := edit(t, smallFIT(t), func(root, images, _ *fdt.Node) { fn(images.Child("kernel-1").Child("hash-2")) })
			f, err := ParseFIT(b)
			if err != nil {
				return // refused at parse: fine
			}
			if err := f.Verify(FITVerifyOptions{}); err == nil {
				t.Fatal("a broken hash node verified")
			}
		})
	}
	// An image whose only hash node is broken is not "hashed".
	b := edit(t, smallFIT(t), func(root, images, _ *fdt.Node) { images.Child("fdt-1").Child("hash-1").DeleteProp("value") })
	if f, err := ParseFIT(b); err == nil {
		if err := f.Verify(FITVerifyOptions{RequireHash: true}); err == nil {
			t.Error("a hash node without a value satisfied RequireHash")
		}
	}
}

// Bombs: a FIT that declares far more than it holds is refused, and the
// refusal costs no memory in proportion to the declaration.
func TestFITBombRefused(t *testing.T) {
	old := debug.SetMemoryLimit(256 << 20)
	defer debug.SetMemoryLimit(old)
	o := fitCase()
	o.External, o.Position, o.HasPosition = true, 0x2001, true
	good, _ := WriteFIT(o)
	for name, mut := range map[string]func(images *fdt.Node){
		"4 GiB size":     func(im *fdt.Node) { _ = im.Child("kernel-1").SetUint32("data-size", 0xffffffff) },
		"4 GiB position": func(im *fdt.Node) { _ = im.Child("kernel-1").SetUint32("data-position", 0xfffffff0) },
	} {
		t.Run(name, func(t *testing.T) {
			b := edit2(t, good, mut)
			var m0, m1 runtime.MemStats
			runtime.ReadMemStats(&m0)
			_, err := ParseFIT(b)
			runtime.ReadMemStats(&m1)
			if !errors.Is(err, ErrRange) {
				t.Fatalf("err = %v", err)
			}
			if d := m1.TotalAlloc - m0.TotalAlloc; d > 4<<20 {
				t.Errorf("the refusal allocated %d bytes", d)
			}
		})
	}
	// Many images: bounded by what the structure holds, never by a count it declares.
	if _, err := ParseFIT(append([]byte{0xd0, 0x0d, 0xfe, 0xed, 0xff, 0xff, 0xff, 0xff}, make([]byte, 32)...)); err == nil {
		t.Error("a header declaring 4 GiB parsed")
	}
}

func FuzzFIT(f *testing.F) {
	o := fitCase()
	for _, set := range []func(*FITOptions){
		func(*FITOptions) {},
		func(o *FITOptions) { o.External = true },
		func(o *FITOptions) { o.External, o.Align = true, 64 },
		func(o *FITOptions) { o.External, o.Position, o.HasPosition = true, 0x1003, true },
	} {
		c := o
		c.Images = append([]FITImage(nil), o.Images...)
		set(&c)
		if b, err := WriteFIT(c); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		fit, err := ParseFIT(b)
		if err != nil {
			return
		}
		_ = fit.Verify(FITVerifyOptions{RequireHash: true})
		_ = fit.Listing()
		for i := range fit.Images {
			if uint64(len(fit.Images[i].Data)) > uint64(len(b)) {
				t.Fatalf("image %d holds %d bytes of a %d-byte file", i, len(fit.Images[i].Data), len(b))
			}
		}
	})
}
