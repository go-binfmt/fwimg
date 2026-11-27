package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-binfmt/fwimg"
	"github.com/spf13/cobra"
)

// inputFlags are the flags that say how to read an input, the same on every
// command that reads one.
type inputFlags struct {
	format, base, maxSize string
	useVaddr              bool
	vwidth                int
	vendian               string
}

func (f *inputFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVarP(&f.format, "input-target", "I", "", "input format: elf, ihex, srec, uimage, uf2, verilog, binary (default: detected; binary is never detected)")
	fl.IntVar(&f.vwidth, "verilog-data-width", 1, "data width in bytes of a Verilog input, 1 to 8")
	fl.StringVar(&f.vendian, "verilog-endian", "", "byte order within a word of a Verilog input: little (default) or big")
	fl.StringVar(&f.base, "base", "", "load address of a raw binary input, decimal or 0x-hex (required with -I binary)")
	fl.BoolVar(&f.useVaddr, "use-vaddr", false, "place ELF segments by virtual address instead of load address")
	fl.StringVar(&f.maxSize, "max-size", "", "largest image in bytes from lowest to highest address (default 256 MiB)")
}

// checkInput validates -I and --base and returns the address of a raw binary.
func checkInput(format, base string) (uint64, error) {
	switch format {
	case "", fwimg.FormatELF, fwimg.FormatIHEX, fwimg.FormatSREC, fwimg.FormatUImage, fwimg.FormatUF2, fwimg.FormatVerilog, fwimg.FormatBinary:
	default:
		return 0, usageErr{fmt.Sprintf("unknown --input-target %q (want elf, ihex, srec, uimage, uf2, verilog, binary)", format)}
	}
	switch {
	case format == fwimg.FormatBinary && base == "":
		return 0, usageErr{"-I binary needs --base ADDR: a raw file has no address, and none is guessed"}
	case format != fwimg.FormatBinary && base != "":
		return 0, usageErr{"--base is only for -I binary"}
	case base != "":
		return parseUint("base", base, 64)
	}
	return 0, nil
}

// loaded is an input read for info and verify.
type loaded struct {
	im     *fwimg.Image
	stored *fwimg.Image // a uImage as stored, compressed or not; nil for any other input
	src    *source
	format string
	data   []byte
	maxSz  uint64
}

// with reads input and calls fn with its image, while the bytes (mapped, for an
// ELF) are valid. A uImage is read as it is stored: compressed or not, with the
// payload as the image.
func (f *inputFlags) with(input string, fn func(*loaded) error) (err error) {
	rawBase, err := checkInput(f.format, f.base)
	if err != nil {
		return err
	}
	fo := fwimg.FlattenOptions{UseVaddr: f.useVaddr}
	if f.maxSize != "" {
		if fo.MaxSize, err = parseUint("max-size", f.maxSize, 64); err != nil {
			return err
		}
	}
	data, release, err := inputBytes(input)
	if err != nil {
		return err
	}
	defer release()
	defer mapGuard(&err)()
	in := f.format
	if in == "" {
		if in = fwimg.Detect(data); in == "" {
			return fmt.Errorf("%s: %w; a raw binary is read only with -I binary --base ADDR", input, fwimg.ErrUnknownFormat)
		}
	}
	l := &loaded{format: in, data: data, maxSz: fo.MaxSize}
	if in == fwimg.FormatUImage {
		l.src = &source{}
		if l.stored, err = fwimg.UImageStored(data); err != nil {
			return fmt.Errorf("%s: %w", input, err)
		}
		l.im = l.stored
		if l.stored.UImage.Comp != fwimg.CompNone {
			// The manifest and verify describe the program, not its gzip or lz4
			// form: the image a conversion wrote the manifest for.
			if l.im, err = fwimg.UImageImageOpts(data, fwimg.DecodeOptions{MaxSize: fo.MaxSize}); err != nil {
				return fmt.Errorf("%s: %w", input, err)
			}
		}
	} else if l.src, err = load(in, data, fo, fwimg.SectionSelect{}, rawBase, input, fwimg.VerilogOptions{DataWidth: f.vwidth, BigEndian: f.vendian == "big"}); err != nil {
		return err
	} else {
		l.im = l.src.img
	}
	return fn(l)
}

// manifestEpoch is the creation time SOURCE_DATE_EPOCH asks for, nil without it.
func manifestEpoch() (*int64, error) {
	s, ok := os.LookupEnv("SOURCE_DATE_EPOCH")
	if !ok {
		return nil, nil
	}
	v, err := fwimg.ParseEpoch(s)
	e := int64(v)
	return &e, err
}

// sourceOf describes the input file of a manifest.
func sourceOf(input, format string, data []byte) *fwimg.ManifestSource {
	_, sha := fwimg.SumBytes(data)
	return &fwimg.ManifestSource{File: filepath.Base(input), Format: format, Size: uint64(len(data)), SHA256: sha}
}

// uimageHeader is the header UImage writes for opts: its defaults applied and
// its name cut to 31 bytes.
func uimageHeader(o fwimg.UImageOptions) *fwimg.UImageHeader {
	h := &fwimg.UImageHeader{Time: o.Time, Load: o.Load, Entry: o.Entry, OS: o.OS, Arch: o.Arch, Type: o.Type, Comp: o.Comp, Name: o.Name}
	if h.OS == 0 {
		h.OS = fwimg.OSLinux
	}
	if h.Arch == 0 {
		h.Arch = fwimg.ArchARM
	}
	if h.Type == 0 {
		h.Type = fwimg.TypeKernel
	}
	if len(h.Name) > 31 {
		h.Name = h.Name[:31]
	}
	return h
}

func infoCmd() *cobra.Command {
	var f inputFlags
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "info FILE",
		Short: "List an image: a uImage header like mkimage -l, anything else as ranges, hashes and the start address",
		Long: `info reads an ELF, Intel HEX, Motorola S-record, legacy U-Boot uImage or (with
-I binary --base ADDR) a raw binary and describes the image it loads.

A uImage is listed the way mkimage -l does, after its magic and both CRCs are
checked. Every other input prints its format, start address, address ranges,
sizes, CRC-32 and SHA-256 of the whole image and of each range, in the order
srec_info gives its ranges. --json prints the same facts as a manifest (the
schema is manifest-1.schema.json, see the README), for every format.`,
		Example: `  fwimg info fw.hex
  fwimg info --json kernel.elf
  fwimg info -I binary --base 0x8000000 fw.bin`,
		Args: func(c *cobra.Command, a []string) error {
			if err := cobra.ExactArgs(1)(c, a); err != nil {
				return usageErr{err.Error()}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return f.with(args[0], func(l *loaded) error {
				out := cmd.OutOrStdout()
				if l.format == fwimg.FormatUImage && !asJSON {
					comps, err := l.stored.UImage.Components(payload(l.stored))
					if err != nil {
						return fmt.Errorf("%s: %w", args[0], err)
					}
					_, err = io.WriteString(out, l.im.UImage.Listing(comps))
					return err
				}
				m, err := manifestOf(l, args[0])
				if err != nil {
					return err
				}
				if asJSON {
					_, err = out.Write(m.JSON())
					return err
				}
				_, err = io.WriteString(out, describeManifest(m))
				return err
			})
		},
	}
	f.bind(cmd)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the manifest (schema manifest-1) instead of the listing")
	return cmd
}

// manifestOf is the manifest of an input read for info.
func manifestOf(l *loaded, input string) (*fwimg.Manifest, error) {
	epoch, err := manifestEpoch()
	if err != nil {
		return nil, err
	}
	o := fwimg.ManifestOptions{
		Version: version(), Format: l.format, Source: sourceOf(input, l.format, l.data),
		Epoch: epoch, MaxSize: l.maxSz, UImage: l.im.UImage,
	}
	if l.format == fwimg.FormatELF {
		if o.Sections, err = fwimg.ELFManifestSections(l.data); err != nil {
			return nil, fmt.Errorf("%s: %w", input, err)
		}
	}
	m, err := fwimg.NewManifest(l.im, o)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", input, err)
	}
	return m, nil
}

// describeManifest is the human listing of a manifest.
func describeManifest(m *fwimg.Manifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Format:   %s\n", m.Format)
	entry := "none"
	if m.Entry != nil {
		entry = *m.Entry
	}
	fmt.Fprintf(&b, "Entry:    %s\n", entry)
	fmt.Fprintf(&b, "Base:     %s\n", m.Base)
	fmt.Fprintf(&b, "Size:     %d bytes, of which %d are data\n", m.Size, m.DataSize)
	fmt.Fprintf(&b, "CRC-32:   %s\n", m.CRC32)
	fmt.Fprintf(&b, "SHA-256:  %s\n", m.SHA256)
	fmt.Fprintf(&b, "Segments: %d\n", len(m.Segments))
	for _, s := range m.Segments {
		fmt.Fprintf(&b, "  %s  %d bytes  crc32 %s  sha256 %s\n", s.Address, s.Size, s.CRC32, s.SHA256)
	}
	if len(m.Sections) > 0 {
		b.WriteString("Sections:\n")
		for _, s := range m.Sections {
			fmt.Fprintf(&b, "  %-20s %s  %d bytes\n", s.Name, s.Address, s.Size)
		}
	}
	return b.String()
}

// readManifest reads a manifest file, never more than the library accepts.
func readManifest(path string) (*fwimg.Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, fwimg.MaxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	m, err := fwimg.ReadManifest(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

func verifyCmd() *cobra.Command {
	var f inputFlags
	var manifest string
	cmd := &cobra.Command{
		Use:   "verify --manifest FILE IMAGE",
		Short: "Check an image, in any format, against the hashes of a manifest",
		Long: `verify reads IMAGE (an ELF, Intel HEX, S-record, uImage or, with -I binary --base
ADDR, a raw binary) and recomputes from its bytes the base address, size, start
address and the CRC-32 and SHA-256 of the whole image and of every segment and
region the manifest lists. The format need not be the one the manifest was
written for: a manifest made with -O ihex checks the flat binary of the same
image. Every difference is listed; the exit status is 1 if there is one.`,
		Example: `  fwimg -O ihex --manifest fw.json -o fw.hex fw.elf
  fwimg verify --manifest fw.json fw.hex
  fwimg verify --manifest fw.json -I binary --base 0x8000000 fw.bin`,
		Args: func(c *cobra.Command, a []string) error {
			if err := cobra.ExactArgs(1)(c, a); err != nil {
				return usageErr{err.Error()}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if manifest == "" {
				return usageErr{"--manifest FILE is required"}
			}
			m, err := readManifest(manifest)
			if err != nil {
				return err
			}
			return f.with(args[0], func(l *loaded) error {
				if err := m.Verify(l.im, fwimg.VerifyOptions{MaxSize: l.maxSz}); err != nil {
					return fmt.Errorf("%s: %w", args[0], err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s: matches %s (%d segments, %d bytes)\n", args[0], manifest, len(m.Segments), m.Size)
				return nil
			})
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&manifest, "manifest", "", "the manifest to check against (required)")
	return cmd
}

// payload is the stored bytes of a uImage's image.
func payload(im *fwimg.Image) []byte {
	if len(im.Segments) == 0 {
		return nil
	}
	return im.Segments[0].Data
}
