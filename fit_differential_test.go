package fwimg

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-binfmt/fdt"
)

// The FIT differential lane: what WriteFIT lays out against `mkimage -f`
// (-E, -B, -p), and what Listing prints against `mkimage -l`, `dumpimage -l`
// and `dtc -I dtb -O dts`. mkimage compiles an ITS with dtc, so both tools
// are needed. Unlike the other lanes this one also runs where the tools are
// (a macOS laptop with u-boot-tools and dtc), because the layout is what it pins;
// FWIMG_REQUIRE_DIFF still turns a missing tool into a failure.

func needFIT(t *testing.T) {
	t.Helper()
	if why := os.Getenv("FWIMG_SKIP_DIFF"); why != "" {
		t.Skip("differential lane skipped: " + why)
	}
	for _, tool := range []string{"mkimage", "dumpimage", "dtc"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("FWIMG_REQUIRE_DIFF") != "" {
				t.Fatalf("differential lane is REQUIRED here but %s is not on PATH", tool)
			}
			t.Skipf("differential lane needs %s on PATH", tool)
		}
	}
}

// oldMkimage reports whether mkimage predates 2026: Ubuntu's 2025.10 prints no
// "Compatible:" line and pads the external data to 4, not 8 (both measured in CI
// against 2025.10 and locally against 2026.10). An unreadable version counts as
// new, so a surprise shows as a failure rather than a skip.
func oldMkimage(t *testing.T) bool {
	t.Helper()
	out, err := exec.Command("mkimage", "-V").CombinedOutput()
	if err != nil {
		return false
	}
	var year, month int
	if _, err := fmt.Sscanf(string(out), "mkimage version %d.%d", &year, &month); err != nil {
		return false
	}
	return year < 2026
}

// withoutCompat drops the "Compatible:" lines of a listing, and the lines that
// continue them (the further strings, indented under the value).
func withoutCompat(s string) string {
	var keep []string
	in := false
	for _, l := range strings.SplitAfter(s, "\n") {
		switch {
		case strings.HasPrefix(strings.TrimSpace(l), "Compatible:"):
			in = true
		case in && strings.HasPrefix(l, strings.Repeat(" ", 24)):
		default:
			in = false
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "")
}

// tool runs a reference tool with the creation time and the time zone pinned,
// and returns its output.
func tool(t *testing.T, stamp uint32, name string, args ...string) string {
	t.Helper()
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), fmt.Sprintf("SOURCE_DATE_EPOCH=%d", stamp), "TZ=UTC")
	var out bytes.Buffer
	c.Stdout, c.Stderr = &out, &out
	if err := c.Run(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out.String())
	}
	return out.String()
}

// itsFor writes the images of o beside an ITS that describes the same FIT.
func itsFor(t *testing.T, dir string, o FITOptions) string {
	t.Helper()
	cells := cmpOrInt(o.AddressCells, 1)
	var b strings.Builder
	fmt.Fprintf(&b, "/dts-v1/;\n/ {\n\tdescription = %q;\n\t#address-cells = <%d>;\n\timages {\n", o.Description, cells)
	addr := func(v uint64) string {
		if cells == 2 {
			return fmt.Sprintf("<0x%x 0x%x>", v>>32, v&0xffffffff)
		}
		return fmt.Sprintf("<0x%x>", v)
	}
	for _, im := range o.Images {
		file := writeTemp(t, dir, im.Name+".bin", im.Data)
		fmt.Fprintf(&b, "\t\t%s {\n\t\t\tdescription = %q;\n\t\t\tdata = /incbin/(%q);\n\t\t\ttype = %q;\n", im.Name, im.Description, file, im.Type)
		if im.Arch != "" {
			fmt.Fprintf(&b, "\t\t\tarch = %q;\n", im.Arch)
		}
		if im.OS != "" {
			fmt.Fprintf(&b, "\t\t\tos = %q;\n", im.OS)
		}
		fmt.Fprintf(&b, "\t\t\tcompression = %q;\n", cmpOr(im.Comp, "none"))
		if im.HasLoad {
			fmt.Fprintf(&b, "\t\t\tload = %s;\n", addr(im.Load))
		}
		if im.HasEntry {
			fmt.Fprintf(&b, "\t\t\tentry = %s;\n", addr(im.Entry))
		}
		for i, h := range im.Hashes {
			fmt.Fprintf(&b, "\t\t\thash-%d { algo = %q; };\n", i+1, h.Algo)
		}
		b.WriteString("\t\t};\n")
	}
	b.WriteString("\t};\n")
	if len(o.Configs) > 0 {
		def := cmpOr(o.Default, o.Configs[0].Name)
		fmt.Fprintf(&b, "\tconfigurations {\n\t\tdefault = %q;\n", def)
		for _, c := range o.Configs {
			fmt.Fprintf(&b, "\t\t%s {\n\t\t\tdescription = %q;\n", c.Name, c.Description)
			for _, r := range c.Refs {
				q := make([]string, len(r.Names))
				for i, n := range r.Names {
					q[i] = fmt.Sprintf("%q", n)
				}
				fmt.Fprintf(&b, "\t\t\t%s = %s;\n", r.Prop, strings.Join(q, ", "))
			}
			if len(c.Compatible) > 0 {
				q := make([]string, len(c.Compatible))
				for i, n := range c.Compatible {
					q[i] = fmt.Sprintf("%q", n)
				}
				fmt.Fprintf(&b, "\t\t\tcompatible = %s;\n", strings.Join(q, ", "))
			}
			b.WriteString("\t\t};\n")
		}
		b.WriteString("\t};\n")
	}
	b.WriteString("};\n")
	return writeTemp(t, dir, "fit.its", []byte(b.String()))
}

func cmpOrInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// canon renders a tree with the properties of every node sorted: mkimage
// (libfdt) adds a property at the front of its node, and the order of the
// properties of a node carries no meaning.
func canon(n *fdt.Node, depth int, b *strings.Builder) {
	pad := strings.Repeat("  ", depth)
	fmt.Fprintf(b, "%s%s {\n", pad, n.Name)
	props := slices.Clone(n.Props)
	slices.SortFunc(props, func(x, y fdt.Prop) int { return strings.Compare(x.Name, y.Name) })
	for _, p := range props {
		if len(p.Value) > 64 {
			fmt.Fprintf(b, "%s  %s = <%d bytes>\n", pad, p.Name, len(p.Value))
			continue
		}
		fmt.Fprintf(b, "%s  %s = %x\n", pad, p.Name, p.Value)
	}
	for _, c := range n.Children {
		canon(c, depth+1, b)
	}
	fmt.Fprintf(b, "%s}\n", pad)
}

func canonOf(t *testing.T, blob []byte) string {
	t.Helper()
	tr, err := fdt.Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	canon(tr.Root, 0, &b)
	return b.String()
}

func fitImages() []FITImage {
	return []FITImage{
		{Name: "kernel-1", Description: "the kernel", Type: "kernel", Arch: "arm64", OS: "linux", Data: payloadFor(1001),
			Load: 0x80000, Entry: 0x80000, HasLoad: true, HasEntry: true, Hashes: []FITHash{{Algo: "crc32"}, {Algo: "sha256"}}},
		{Name: "fdt-1", Description: "board", Type: "flat_dt", Arch: "arm64", Comp: "none", Data: payloadFor(301), Hashes: []FITHash{{Algo: "sha1"}}},
		{Name: "fw-1", Description: "fw", Type: "firmware", Arch: "arm64", OS: "u-boot", Comp: "none", Data: payloadFor(21)},
		{Name: "ramdisk-1", Description: "rd", Type: "ramdisk", Arch: "arm64", OS: "linux", Comp: "gzip", Data: payloadFor(4096)},
	}
}

func fitCase() FITOptions {
	return FITOptions{
		Description: "test", Time: 1700000000, Images: fitImages(),
		Configs: []FITConfig{{Name: "conf-1", Description: "c", Refs: []FITRef{
			{Prop: "kernel", Names: []string{"kernel-1"}}, {Prop: "ramdisk", Names: []string{"ramdisk-1"}}, {Prop: "fdt", Names: []string{"fdt-1"}}},
			Compatible: []string{"a,b"}}},
	}
}

// The layout of the data, and the tree: ours against mkimage's, for every
// combination of -E, -B and -p, and odd sizes so that the padding shows.
func TestDifferential_FITLayoutAgainstMkimage(t *testing.T) {
	needFIT(t)
	type variant struct {
		name  string
		flags []string
		set   func(*FITOptions)
	}
	variants := []variant{
		{"embedded", nil, func(o *FITOptions) {}},
		{"E", []string{"-E"}, func(o *FITOptions) { o.External = true }},
		{"E-B4", []string{"-E", "-B", "4"}, func(o *FITOptions) { o.External, o.Align = true, 4 }},
		{"E-B8", []string{"-E", "-B", "8"}, func(o *FITOptions) { o.External, o.Align = true, 8 }},
		{"E-B40", []string{"-E", "-B", "40"}, func(o *FITOptions) { o.External, o.Align = true, 0x40 }},
		{"E-B200", []string{"-E", "-B", "200"}, func(o *FITOptions) { o.External, o.Align = true, 0x200 }},
		{"E-p1000", []string{"-E", "-p", "0x1000"}, func(o *FITOptions) { o.External, o.Position, o.HasPosition = true, 0x1000, true }},
		{"E-p1003", []string{"-E", "-p", "0x1003"}, func(o *FITOptions) { o.External, o.Position, o.HasPosition = true, 0x1003, true }},
		{"E-p1003-B8", []string{"-E", "-p", "0x1003", "-B", "8"}, func(o *FITOptions) {
			o.External, o.Position, o.HasPosition, o.Align = true, 0x1003, true, 8
		}},
		{"2cells", nil, func(o *FITOptions) { o.AddressCells = 2 }},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			dir := t.TempDir()
			o := fitCase()
			v.set(&o)
			old := oldMkimage(t)
			if old && o.External {
				t.Skip("mkimage before 2026 lays the external data out differently (pads to 4, not 8)")
			}
			its := itsFor(t, dir, o)
			ref := filepath.Join(dir, "ref.fit")
			tool(t, o.Time, "mkimage", append(slices.Clone(v.flags), "-f", its, ref)...)
			want := readFile(t, ref)
			got, err := WriteFIT(o)
			if err != nil {
				t.Fatal(err)
			}
			if g, w := canonOf(t, got), canonOf(t, want); g != w {
				t.Errorf("the trees differ\nours:\n%s\nmkimage:\n%s", g, w)
			}
			gh, _ := fdt.ParseHeader(got)
			wh, _ := fdt.ParseHeader(want)
			if o.External {
				// The structure may differ in size (libfdt and fdt order the
				// strings alike but not byte for byte); what follows it must not.
				if !bytes.Equal(got[gh.TotalSize:], want[wh.TotalSize:]) {
					t.Logf("totalsize ours %d, mkimage %d", gh.TotalSize, wh.TotalSize)
					t.Errorf("the data differs: ours %d bytes after the structure, mkimage %d; first difference at %d",
						len(got)-int(gh.TotalSize), len(want)-int(wh.TotalSize), firstDiff(got[gh.TotalSize:], want[wh.TotalSize:]))
				}
				if o.HasPosition {
					// Positions are absolute: the file ends at the same place.
					if len(got) != len(want) {
						t.Errorf("file is %d bytes, mkimage's %d", len(got), len(want))
					}
				}
				if gh.TotalSize%max(4, o.Align) != 0 {
					t.Errorf("totalsize %d is not a multiple of the alignment", gh.TotalSize)
				}
			} else if gh.TotalSize != uint32(len(got)) {
				t.Errorf("embedded FIT: totalsize %d, file %d", gh.TotalSize, len(got))
			}
			f, err := ParseFIT(got)
			if err != nil {
				t.Fatalf("our parser on our file: %v", err)
			}
			if err := f.Verify(FITVerifyOptions{}); err != nil {
				t.Errorf("our file does not verify: %v", err)
			}
			// ... and on mkimage's.
			if f, err = ParseFIT(want); err != nil {
				t.Fatalf("our parser on mkimage's file: %v", err)
			}
			if err := f.Verify(FITVerifyOptions{}); err != nil {
				t.Errorf("mkimage's file does not verify: %v", err)
			}
			// The reference tools read our file.
			fp := writeTemp(t, dir, "ours.fit", got)
			if g, w := tool(t, 0, "mkimage", "-l", fp), tool(t, 0, "mkimage", "-l", ref); g != w {
				t.Errorf("mkimage -l of our file and of its own differ\nours:\n%s\nits:\n%s", g, w)
			}
			tool(t, 0, "dtc", "-I", "dtb", "-O", "dts", "-o", "/dev/null", fp)
			if g, w := tool(t, 0, "dumpimage", "-l", fp), tool(t, 0, "dumpimage", "-l", ref); g != w {
				t.Errorf("dumpimage -l of our file and of its own differ\nours:\n%s\nits:\n%s", g, w)
			}
			// Our listing is theirs.
			g := f.Listing()
			if old {
				g = withoutCompat(g)
			}
			if w := tool(t, 0, "mkimage", "-l", ref); g != w {
				t.Errorf("Listing differs from mkimage -l\nours:\n%s\nmkimage:\n%s", g, w)
			}
		})
	}
}

// The listing for every image type, with and without addresses, and the
// configuration lines, against mkimage -l.
func TestDifferential_FITListingAgainstMkimage(t *testing.T) {
	needFIT(t)
	dir := t.TempDir()
	var images []FITImage
	for _, ty := range []string{"kernel", "ramdisk", "flat_dt", "firmware", "standalone", "script", "loadable", "kernel_noload", "filesystem", "fpga"} {
		for _, la := range []bool{false, true} {
			images = append(images, FITImage{Name: fmt.Sprintf("%s-%v", strings.ReplaceAll(ty, "_", "x"), la), Description: ty, Type: ty, Arch: "riscv", OS: "u-boot",
				Comp: map[bool]string{false: "none", true: "lz4"}[la], Data: payloadFor(70000), Load: 0x1000, Entry: 0x1004, HasLoad: la, HasEntry: la,
				Hashes: []FITHash{{Algo: "sha256"}}})
		}
	}
	o := FITOptions{Description: "listing", Time: 1700000123, Images: images, AddressCells: 2, Default: "c2", Configs: []FITConfig{
		{Name: "c1", Description: "first", Refs: []FITRef{{Prop: "firmware", Names: []string{"firmware-true"}},
			{Prop: "fdt", Names: []string{"flatxdt-true", "flatxdt-false"}}, {Prop: "loadables", Names: []string{"loadable-true", "standalone-false"}}},
			Compatible: []string{"a,b", "c,d"}},
		{Name: "c2", Description: "second", Refs: []FITRef{{Prop: "kernel", Names: []string{"kernel-true"}}, {Prop: "ramdisk", Names: []string{"ramdisk-false"}},
			{Prop: "firmware", Names: []string{"firmware-false"}}, {Prop: "fdt", Names: []string{"flatxdt-true"}}}},
	}}
	its := itsFor(t, dir, o)
	ref := filepath.Join(dir, "ref.fit")
	tool(t, o.Time, "mkimage", "-f", its, ref)
	for name, file := range map[string][]byte{"mkimage's": readFile(t, ref), "ours": must(WriteFIT(o))} {
		fp := writeTemp(t, dir, "x.fit", file)
		f, err := ParseFIT(file)
		if err != nil {
			t.Fatal(name, err)
		}
		g := f.Listing()
		if oldMkimage(t) {
			g = withoutCompat(g)
		}
		if w := tool(t, 0, "mkimage", "-l", fp); g != w {
			t.Errorf("%s file: Listing differs from mkimage -l (first difference at byte %d)\nours:\n%s\nmkimage:\n%s", name, firstDiff([]byte(g), []byte(w)), g, w)
		}
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
