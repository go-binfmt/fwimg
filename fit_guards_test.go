package fwimg

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-binfmt/fdt"
)

// Each refusal of fit.go has a case here that names it: the error says which
// guard fired, so a guard that is deleted or inverted is not hidden by a later
// one that refuses the same input for another reason.

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted, want an error containing %q", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("error %q does not contain %q", err, sub)
	}
}

func TestFITWriteGuards(t *testing.T) {
	big := func(n int) []FITImage {
		var ims []FITImage
		for _, name := range []string{"a", "b", "c"} {
			ims = append(ims, FITImage{Name: name, Type: "kernel", Data: payloadFor(n)})
		}
		return ims
	}
	for _, tc := range []struct {
		name string
		set  func(*FITOptions)
		want string
	}{
		{"no images", func(o *FITOptions) { o.Images, o.Configs = nil, nil }, "no images"},
		{"description with NUL", func(o *FITOptions) { o.Description = "a\x00b" }, "NUL"},
		{"default without configurations", func(o *FITOptions) { o.Configs, o.Default = nil, "x" }, "without configurations"},
		{"default does not exist", func(o *FITOptions) { o.Default = "nope" }, `default configuration "nope"`},
		{"duplicate configuration", func(o *FITOptions) { o.Configs = append(o.Configs, o.Configs[0]) }, "configuration"},
		{"entry wider than a cell", func(o *FITOptions) { o.Images[0].Entry = 1 << 33 }, "entry:"},
		{"load wider than a cell", func(o *FITOptions) { o.Images[0].Load = 1 << 33 }, "load:"},
		{"duplicate hash name", func(o *FITOptions) {
			o.Images[0].Hashes = []FITHash{{Name: "h", Algo: "crc32"}, {Name: "h", Algo: "crc32"}}
		}, "image"},
		{"position past one cell", func(o *FITOptions) { o.External, o.Position, o.HasPosition = true, 0xFFFFFF00, true }, "one address cell"},
		{"position inside the structure", func(o *FITOptions) { o.External, o.Position, o.HasPosition = true, 16, true }, "inside the structure"},
		{"duplicate image", func(o *FITOptions) { o.Images[1].Name = o.Images[0].Name }, "image"},
		{"image without type", func(o *FITOptions) { o.Images[0].Type = "" }, "has no type"},
		{"cells", func(o *FITOptions) { o.AddressCells = 3 }, "address-cells"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := fitCase()
			tc.set(&o)
			noPanic(t, tc.name, func() {
				_, err := WriteFIT(o)
				wantErr(t, err, tc.want)
			})
		})
	}

	t.Run("image above the limit", func(t *testing.T) {
		old := maxFITSize
		maxFITSize = 500
		t.Cleanup(func() { maxFITSize = old })
		_, err := WriteFIT(FITOptions{Images: big(501)})
		wantErr(t, err, "4 GiB")
		if _, err := WriteFIT(FITOptions{Images: big(500)}); err != nil {
			t.Fatalf("an image at the limit: %v", err)
		}
	})
	t.Run("offset above the limit", func(t *testing.T) {
		old := maxFITSize
		maxFITSize = 1000
		t.Cleanup(func() { maxFITSize = old })
		_, err := WriteFIT(FITOptions{Images: big(600), External: true})
		wantErr(t, err, "data offset")
		if _, err := WriteFIT(FITOptions{Images: big(600)[:2], External: true}); err != nil {
			t.Fatalf("an offset at the limit: %v", err)
		}
	})
	t.Run("marshal fails", func(t *testing.T) {
		old := appendMarshal
		appendMarshal = func(*fdt.Tree, []byte) ([]byte, error) { return nil, errors.New("too big") }
		t.Cleanup(func() { appendMarshal = old })
		_, err := WriteFIT(fitCase())
		wantErr(t, err, "too big")
	})
}

// rawFIT marshals a tree built by hand: fn adds what the case needs.
func rawFIT(t *testing.T, fn func(root, images *fdt.Node)) []byte {
	t.Helper()
	tr := fdt.New()
	images, err := tr.Root.AddChild("images")
	if err != nil {
		t.Fatal(err)
	}
	fn(tr.Root, images)
	b, err := tr.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rawImage adds a well-formed embedded image to images.
func rawImage(t *testing.T, images *fdt.Node, name string) *fdt.Node {
	t.Helper()
	n, err := images.AddChild(name)
	if err != nil {
		t.Fatal(err)
	}
	_ = n.SetString("type", "kernel")
	_ = n.SetString("compression", "none")
	_ = n.Set("data", []byte("data"))
	return n
}

func TestFITParseGuards(t *testing.T) {
	cell := func(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
	// external is an image whose data is described by the properties fn sets.
	external := func(t *testing.T, images *fdt.Node, fn func(n *fdt.Node)) {
		n, _ := images.AddChild("k")
		_ = n.SetString("type", "kernel")
		_ = n.SetString("compression", "none")
		fn(n)
	}
	for _, tc := range []struct {
		name string
		want string
		err  error
		fit  func(t *testing.T) []byte
	}{
		{"not a devicetree", "", ErrSyntax, func(t *testing.T) []byte { return []byte("not a FIT at all, but long enough") }},
		{"root alias", "node", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				rawImage(t, images, "k")
				_, _ = root.AddChild("images@2")
			})
		}},
		{"no images node", "no /images", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) { root.DeleteChild("images") })
		}},
		{"image alias", "image", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) { rawImage(t, images, "k"); rawImage(t, images, "k@1") })
		}},
		{"no type", "lacks type", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) { rawImage(t, images, "k").DeleteProp("type") })
		}},
		{"no compression", "lacks type", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) { rawImage(t, images, "k").DeleteProp("compression") })
		}},
		{"load of 3 bytes", "load is 3 bytes", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) { _ = rawImage(t, images, "k").Set("load", []byte{1, 2, 3}) })
		}},
		{"entry of 3 bytes", "entry is 3 bytes", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) { _ = rawImage(t, images, "k").Set("entry", []byte{1, 2, 3}) })
		}},
		{"external without data-size", "without data-size", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				external(t, images, func(n *fdt.Node) { _ = n.Set("data-offset", cell(0)) })
			})
		}},
		{"data-size of 3 bytes", "data-size:", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				external(t, images, func(n *fdt.Node) { _ = n.Set("data-offset", cell(0)); _ = n.Set("data-size", []byte{1, 2, 3}) })
			})
		}},
		{"data-offset of 3 bytes", "data-offset:", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				external(t, images, func(n *fdt.Node) { _ = n.Set("data-offset", []byte{1, 2, 3}); _ = n.SetUint32("data-size", 4) })
			})
		}},
		{"data-position of 3 bytes", "data-position is 3 bytes", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				external(t, images, func(n *fdt.Node) { _ = n.Set("data-position", []byte{1, 2, 3}); _ = n.SetUint32("data-size", 4) })
			})
		}},
		{"offset past the file", "bytes at", ErrRange, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				external(t, images, func(n *fdt.Node) { _ = n.Set("data-offset", cell(0x7fffffff)); _ = n.SetUint32("data-size", 4) })
			})
		}},
		{"size past the file", "bytes at", ErrRange, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				external(t, images, func(n *fdt.Node) { _ = n.Set("data-offset", cell(0)); _ = n.SetUint32("data-size", 1<<20) })
			})
		}},
		{"configuration alias", "configuration", ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				rawImage(t, images, "k")
				cn, _ := root.AddChild("configurations")
				_, _ = cn.AddChild("c")
				_, _ = cn.AddChild("c@1")
			})
		}},
		{"unterminated reference", `configuration "c": kernel`, ErrSyntax, func(t *testing.T) []byte {
			return rawFIT(t, func(root, images *fdt.Node) {
				rawImage(t, images, "k")
				cn, _ := root.AddChild("configurations")
				c, _ := cn.AddChild("c")
				_ = c.Set("kernel", []byte("k"))
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noPanic(t, tc.name, func() {
				_, err := ParseFIT(tc.fit(t))
				wantErr(t, err, tc.want)
				if !errors.Is(err, tc.err) {
					t.Fatalf("error %v is not %v", err, tc.err)
				}
			})
		})
	}

	t.Run("an image without load or entry", func(t *testing.T) {
		b := rawFIT(t, func(root, images *fdt.Node) { rawImage(t, images, "k") })
		noPanic(t, "absent load", func() {
			f, err := ParseFIT(b)
			if err != nil {
				t.Fatal(err)
			}
			if im := f.Images[0]; im.HasLoad || im.HasEntry || string(im.Data) != "data" {
				t.Errorf("image %+v", im)
			}
		})
	})
}
