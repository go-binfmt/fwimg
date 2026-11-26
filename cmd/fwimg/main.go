// Command fwimg converts an ELF executable into a flat binary, a Motorola
// S-record, an Intel HEX file or a legacy U-Boot uImage, in pure Go. The
// flags mirror `objcopy -O` and `mkimage`.
package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime/debug"
	"strconv"

	"github.com/go-binfmt/elfpatch"
	"github.com/go-binfmt/fwimg"
	"github.com/spf13/cobra"
)

// Version may be set with -ldflags "-X main.Version=..."; otherwise the module
// version Go stamped into the binary is used, and "dev" for an unstamped build.
var Version = "dev"

// readBuildInfo is replaceable in tests.
var readBuildInfo = debug.ReadBuildInfo

func version() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := readBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return Version
}

// osExit is replaceable in tests.
var osExit = os.Exit

func main() {
	cmd := RootCmd()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), "fwimg:", err)
		var u usageErr
		if errors.As(err, &u) {
			osExit(2)
		} else {
			osExit(1)
		}
	}
}

// usageErr is a mistake in the command line, exit status 2.
type usageErr struct{ msg string }

func (e usageErr) Error() string { return e.msg }

// maxInput is the largest ELF the command reads: the library addresses the
// input with int on 32-bit platforms, and a firmware ELF is far smaller.
var maxInput int64 = math.MaxInt32

// statFile is replaceable in tests: an open descriptor's Stat does not fail on
// demand.
// readSized reads r to EOF into a buffer of the file's own length: one read
// for the body and one for the EOF, where io.ReadAll starts at 512 bytes and
// grows, which cost five read calls on a 1 KiB input (strace, CI). A file
// that grew since the stat is still read in full, up to maxInput+1 bytes.
func readSized(r io.Reader, size int64) ([]byte, error) {
	lr := io.LimitReader(r, maxInput+1)
	buf := make([]byte, size)
	n, err := io.ReadFull(lr, buf)
	switch err {
	case nil: // the stated size was there; read whatever follows it
		rest, err := io.ReadAll(lr)
		if err != nil {
			return nil, err
		}
		return append(buf, rest...), nil
	case io.EOF, io.ErrUnexpectedEOF: // shorter than stated
		return buf[:n], nil
	}
	return nil, err
}

var statFile = func(f *os.File) (os.FileInfo, error) { return f.Stat() }

type options struct {
	output, format, pad, load, entry, name string
	input, base                            string
	arch                                   string
	useVaddr                               bool
	maxSize                                string
	osCode, typeCode                       uint8

	// L2: what objcopy's options of the same names do.
	only, remove []string // -j, -R
	padTo        string
	gapFill      string
	crlf         bool
	ihexMode     string
	srecAddrLen  string
	srecCount    bool
	// --change-addresses and --change-start both set the start-address
	// increment, and the later one on the command line wins, as in objcopy;
	// --change-addresses also moves every section.
	shift, startIncr string
}

// hook is a flag whose value is handled by a function, so that two flags can
// write one variable in command-line order.
type hook struct {
	f func(string) error
}

func (h hook) String() string     { return "" }
func (h hook) Set(s string) error { return h.f(s) }
func (h hook) Type() string       { return "int" }

// RootCmd builds the command.
func RootCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "fwimg [flags] INPUT",
		Short: "Convert an ELF, Intel HEX, S-record, uImage or raw binary into a flat binary / SREC / Intel HEX / U-Boot uImage",
		Long: `fwimg converts an image for a target that is loaded at a fixed address from one
format to another: ELF, Intel HEX, Motorola S-record, legacy U-Boot uImage or
a raw binary in; a flat binary (like objcopy -O binary), a Motorola S-record
(objcopy -O srec), an Intel HEX file (objcopy -O ihex) or a legacy U-Boot
uImage (like mkimage) out. No binutils, no U-Boot tools.

The input format is detected from its magic bytes or syntax (ELF, uImage,
Intel HEX, S-record); -I names it instead. A raw binary has neither: it is
never guessed, and is read only with -I binary --base ADDR.

The input is treated as untrusted: a segment outside the file, an address
range that wraps, a record with a bad checksum, an image above --max-size or a
value that does not fit the format is refused, with exit status 1 and nothing
written.

fwimg info FILE lists the header of a uImage the way mkimage -l does.`,
		Example: `  fwimg -O binary -o kernel.img kernel.elf
  fwimg -O ihex -o fw.hex fw.elf
  fwimg -I ihex -O binary -o fw.bin fw.hex
  fwimg -I binary --base 0x8000000 -O srec -o fw.srec fw.bin
  fwimg -O uimage --load 0x80000 --entry 0x80000 --name linux -o uImage kernel.elf
  fwimg info uImage`,
		Args: func(c *cobra.Command, a []string) error {
			if v, _ := c.Flags().GetBool("version"); v {
				return nil
			}
			if err := cobra.ExactArgs(1)(c, a); err != nil {
				return usageErr{err.Error()}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if v, _ := cmd.Flags().GetBool("version"); v {
				fmt.Fprintf(cmd.OutOrStdout(), "fwimg %s\n", version())
				return nil
			}
			return run(&o, args[0])
		},
	}
	fl := cmd.Flags()
	fl.Bool("version", false, "print the version")
	fl.StringVarP(&o.output, "output", "o", "", "output file (required)")
	fl.StringVarP(&o.input, "input-target", "I", "", "input format: elf, ihex, srec, uimage, binary (default: detected; binary is never detected)")
	fl.StringVar(&o.base, "base", "", "load address of a raw binary input, decimal or 0x-hex (required with -I binary)")
	fl.StringVarP(&o.format, "output-target", "O", "binary", "output format: binary, srec, ihex, uimage")
	fl.BoolVar(&o.useVaddr, "use-vaddr", false, "place segments by virtual address instead of load address")
	fl.StringVar(&o.pad, "pad", "", "gap fill byte for the image, decimal or 0x-hex (default 0x00)")
	fl.StringVar(&o.maxSize, "max-size", "", "largest image in bytes from lowest to highest address (default 256 MiB)")
	fl.StringVar(&o.load, "load", "", "load address for srec/ihex/uimage, decimal or 0x-hex (default: image base)")
	fl.StringVar(&o.entry, "entry", "", "entry address for srec/uimage, decimal or 0x-hex (default: ELF e_entry)")
	fl.StringVar(&o.name, "name", "", "image name (srec S0 / uimage header)")
	fl.StringVar(&o.arch, "uimage-arch", "", "uimage arch: arm, arm64, x86_64, riscv, loongarch (default: from ELF)")
	fl.Uint8Var(&o.osCode, "uimage-os", 0, "uimage OS code (default 5 = Linux)")
	fl.Uint8Var(&o.typeCode, "uimage-type", 0, "uimage type code (default 2 = kernel)")
	fl.StringVar(&o.entry, "set-start", "", "alias of --entry (objcopy's name)")
	fl.StringVar(&o.gapFill, "gap-fill", "", "fill the gaps between sections with this byte (objcopy's name; --pad is the same for a flat binary)")
	fl.StringVar(&o.padTo, "pad-to", "", "pad the image with the gap fill byte up to this address")
	fl.Var(hook{func(s string) error { o.startIncr = s; return nil }}, "change-start", "add this (signed) amount to the start address, after --set-start")
	changeAddr := hook{func(s string) error { o.shift, o.startIncr = s, s; return nil }}
	fl.Var(changeAddr, "change-addresses", "add this (signed) amount to every section address, and to the start address; the later of this and --change-start wins")
	fl.Var(changeAddr, "adjust-vma", "alias of --change-addresses")
	fl.StringArrayVarP(&o.only, "only-section", "j", nil, "keep only the sections matching this pattern (* ? and a leading ! to exclude); repeatable; ELF input")
	fl.StringArrayVarP(&o.remove, "remove-section", "R", nil, "drop the sections matching this pattern; repeatable; ELF input; not with -j")
	fl.BoolVar(&o.crlf, "crlf", false, "end the lines of an S-record or Intel HEX file with CR LF, as objcopy and srec_cat do")
	fl.StringVar(&o.ihexMode, "ihex-mode", "linear", "Intel HEX address records: linear (type 04, like srec_cat) or objcopy (type 02/03 below 1 MiB, 04/05 above)")
	fl.StringVar(&o.srecAddrLen, "srec-addr-len", "32", "S-record address length: 16 (S1), 24 (S2), 32 (S3) or auto (objcopy's choice by the highest address)")
	fl.BoolVar(&o.srecCount, "srec-count", false, "write an S5/S6 count record before the terminator, as srec_cat does")
	cmd.AddCommand(&cobra.Command{
		Use:   "info FILE",
		Short: "List a uImage header the way mkimage -l does",
		Long: `info reads a legacy U-Boot uImage, verifies the magic and both CRCs, and prints
its header like mkimage -l: name, creation time (UTC), type, data size, load
address, entry point, and for a multi-file image the size of each file. A file
that is not a uImage is refused; later releases list the other formats.`,
		Args: func(c *cobra.Command, a []string) error {
			if err := cobra.ExactArgs(1)(c, a); err != nil {
				return usageErr{err.Error()}
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := readInput(args[0])
			if err != nil {
				return err
			}
			if f := fwimg.Detect(data); f != fwimg.FormatUImage {
				return fmt.Errorf("%s: info lists uImage headers only, and this is %s", args[0], describe(f))
			}
			h, payload, err := fwimg.ParseUImage(data)
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			comps, err := h.Components(payload)
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			_, err = io.WriteString(cmd.OutOrStdout(), h.Listing(comps))
			return err
		},
	})
	return cmd
}

// describe names a detected format for an error message.
func describe(f string) string {
	if f == "" {
		return "not a format fwimg recognises"
	}
	return "a " + f + " file"
}

// readInput reads a whole input file, bounded by maxInput.
func readInput(input string) ([]byte, error) {
	f, err := os.Open(input)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := statFile(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", input, err)
	}
	if st.Size() > maxInput {
		return nil, fmt.Errorf("%s is %d bytes, above the %d byte input limit", input, st.Size(), maxInput)
	}
	data, err := readSized(f, st.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", input, err)
	}
	return data, nil
}

func parseUint(flag, s string, bits int) (uint64, error) {
	v, err := strconv.ParseUint(s, 0, bits)
	if err != nil {
		return 0, usageErr{fmt.Sprintf("--%s: %q is not an unsigned %d-bit number", flag, s, bits)}
	}
	return v, nil
}

func parseInt(flag, s string) (int64, error) {
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0, usageErr{fmt.Sprintf("--%s: %q is not a signed 64-bit number", flag, s)}
	}
	return v, nil
}

func run(o *options, input string) error {
	if o.output == "" {
		return usageErr{"-o/--output is required"}
	}
	switch o.format {
	case "binary", "srec", "ihex", "uimage":
	default:
		return usageErr{fmt.Sprintf("unknown --output-target %q (want binary, srec, ihex, uimage)", o.format)}
	}
	switch o.input {
	case "", fwimg.FormatELF, fwimg.FormatIHEX, fwimg.FormatSREC, fwimg.FormatUImage, fwimg.FormatBinary:
	default:
		return usageErr{fmt.Sprintf("unknown --input-target %q (want elf, ihex, srec, uimage, binary)", o.input)}
	}
	var rawBase uint64
	switch {
	case o.input == fwimg.FormatBinary && o.base == "":
		return usageErr{"-I binary needs --base ADDR: a raw file has no address, and none is guessed"}
	case o.input != fwimg.FormatBinary && o.base != "":
		return usageErr{"--base is only for -I binary"}
	case o.base != "":
		v, err := parseUint("base", o.base, 64)
		if err != nil {
			return err
		}
		rawBase = v
	}
	arch, err := fwimg.ArchFromName(o.arch)
	if err != nil {
		return usageErr{err.Error()}
	}
	fo := fwimg.FlattenOptions{UseVaddr: o.useVaddr}
	if o.pad != "" {
		v, err := parseUint("pad", o.pad, 8)
		if err != nil {
			return err
		}
		fo.Pad = byte(v)
	}
	if o.maxSize != "" {
		if fo.MaxSize, err = parseUint("max-size", o.maxSize, 64); err != nil {
			return err
		}
	}
	var loadAddr, entryAddr uint64
	if o.load != "" {
		if loadAddr, err = parseUint("load", o.load, 32); err != nil {
			return err
		}
	}
	if o.entry != "" {
		if entryAddr, err = parseUint("entry", o.entry, 32); err != nil {
			return err
		}
	}

	if o.gapFill != "" {
		v, err := parseUint("gap-fill", o.gapFill, 8)
		if err != nil {
			return err
		}
		if o.pad != "" && byte(v) != fo.Pad {
			return usageErr{"--pad and --gap-fill are the same option and give different bytes"}
		}
		fo.Pad = byte(v)
	}
	var padTo uint64
	if o.padTo != "" {
		if padTo, err = parseUint("pad-to", o.padTo, 64); err != nil {
			return err
		}
	}
	var shift, startIncr int64
	if o.shift != "" {
		if shift, err = parseInt("change-addresses", o.shift); err != nil {
			return err
		}
	}
	if o.startIncr != "" {
		if startIncr, err = parseInt("change-start", o.startIncr); err != nil {
			return err
		}
	}
	if len(o.only) > 0 && len(o.remove) > 0 {
		return usageErr{"-j and -R together are undefined (objcopy says so too): give one"}
	}
	var ihexMode fwimg.IHEXMode
	switch o.ihexMode {
	case "linear":
	case "objcopy":
		ihexMode = fwimg.IHEXObjcopy
	default:
		return usageErr{fmt.Sprintf("unknown --ihex-mode %q (want linear, objcopy)", o.ihexMode)}
	}
	srecBits := fwimg.SRECAuto
	if o.srecAddrLen != "auto" {
		switch o.srecAddrLen {
		case "16", "24", "32":
			srecBits = int(o.srecAddrLen[0]-'0')*10 + int(o.srecAddrLen[1]-'0')
		default:
			return usageErr{fmt.Sprintf("unknown --srec-addr-len %q (want 16, 24, 32, auto)", o.srecAddrLen)}
		}
	}

	data, err := readInput(input)
	if err != nil {
		return err
	}
	in := o.input
	if in == "" {
		if in = fwimg.Detect(data); in == "" {
			return fmt.Errorf("%s: %w; a raw binary is read only with -I binary --base ADDR", input, fwimg.ErrUnknownFormat)
		}
	}
	if (len(o.only) > 0 || len(o.remove) > 0) && in != fwimg.FormatELF {
		return usageErr{"-j and -R select the sections of an ELF input; this input has none"}
	}
	sel := fwimg.SectionSelect{Only: o.only, Remove: o.remove}
	src, err := load(in, data, fo, sel, rawBase, input)
	if err != nil {
		return err
	}
	im := src.img

	// The start address: the input's, unless --set-start/--entry gives one,
	// then moved by --change-start (objcopy's order).
	entry, hasEntry := im.Entry, im.HasEntry
	if o.entry != "" {
		entry, hasEntry = entryAddr, true
	}
	if o.startIncr != "" {
		if startIncr < 0 && entry < uint64(-startIncr) || startIncr > 0 && entry > math.MaxUint64-uint64(startIncr) {
			return fmt.Errorf("%w: start address 0x%x moved by %d", fwimg.ErrAddrOverflow, entry, startIncr)
		}
		entry, hasEntry = entry+uint64(startIncr), true
	}
	if o.shift != "" {
		if err := im.Offset(shift); err != nil {
			return err
		}
	}
	if o.load != "" {
		// Cannot fail here: a 32-bit address moves no image whose end is
		// within 2^32 of 2^64 past 2^64 (Shift's own test covers the refusal).
		_ = im.Shift(loadAddr)
	}
	if o.pad != "" || o.gapFill != "" {
		if err := im.GapFill(fo.Pad, fo.MaxSize); err != nil {
			return err
		}
	}
	if o.padTo != "" {
		if err := im.PadTo(padTo, fo.Pad, fo.MaxSize); err != nil {
			return err
		}
	}

	var out []byte
	var emit func(io.Writer) error // set when the output is streamed, not built
	switch o.format {
	case "binary":
		// The refusal comes before the output file is touched; the segments are
		// then written from the input's own bytes, with no assembled image.
		_, err = im.CheckFlat(fo.MaxSize)
		emit = func(w io.Writer) error { _, err := im.WriteFlat(w, fo.Pad, fo.MaxSize); return err }
	case "srec", "ihex":
		// Addresses come from the input, which may be 64-bit: one that does
		// not fit the format's 32 bits is refused, not truncated.
		if im.Base() > math.MaxUint32 {
			return fmt.Errorf("image base 0x%x does not fit 32 bits: give --load", im.Base())
		}
		if hasEntry && entry > math.MaxUint32 {
			return fmt.Errorf("ELF entry 0x%x does not fit 32 bits: give --entry", entry)
		}
		im.Entry, im.HasEntry = entry, hasEntry
		if o.format == "srec" {
			out, err = fwimg.EncodeSRECOpts(im, fwimg.SRECOptions{
				Name: cmp.Or(o.name, im.Name), AddrBits: srecBits, Count: o.srecCount, CRLF: o.crlf,
			})
		} else {
			out, err = fwimg.EncodeIHEXOpts(im, fwimg.IHEXOptions{Mode: ihexMode, CRLF: o.crlf})
		}
	case "uimage":
		out, err = uimage(o, im, src, arch, hasEntry, entry, fo)
	}
	if err != nil {
		return err
	}
	if emit == nil {
		emit = func(w io.Writer) error { _, err := w.Write(out); return err }
	}
	return writeOutput(o.output, emit)
}

// removeFile is replaceable in tests: a refused unlink cannot be provoked as
// root.
var removeFile = os.Remove

// writeOutput creates path and fills it. An existing regular file is unlinked
// first, as objcopy does, and its permission bits are kept: truncating it in
// place makes ext4 write the whole file out at close (auto_da_alloc), which
// took 90 ms for 32 MiB, against 20 us for a new file (go-binfmt/fwimg#17).
// The cost is that the path gets a new inode (a hard link or an owner is not
// kept); a file that cannot be unlinked is truncated, as before.
func writeOutput(path string, fill func(io.Writer) error) (err error) {
	perm := os.FileMode(0o644)
	if st, e := os.Lstat(path); e == nil && st.Mode().IsRegular() {
		if removeFile(path) == nil {
			perm = st.Mode().Perm()
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() {
		if e := f.Close(); err == nil {
			err = e
		}
	}()
	return fill(f)
}

// source is a loaded input: its image, and what only the ELF knows.
type source struct {
	img     *fwimg.Image
	elf     bool
	machine uint16
}

// load builds the Image of an input of the given format.
func load(format string, data []byte, fo fwimg.FlattenOptions, sel fwimg.SectionSelect, rawBase uint64, input string) (*source, error) {
	var (
		s   = &source{}
		err error
	)
	switch format {
	case fwimg.FormatELF:
		var ef *elfpatch.File
		if ef, err = elfpatch.Parse(data); err != nil {
			return nil, fmt.Errorf("%s: %w", input, err)
		}
		if len(sel.Only) > 0 || len(sel.Remove) > 0 {
			s.img, err = fwimg.ELFSections(data, sel, fo)
		} else {
			// data is ours and is not written to again: no copy of the image.
			s.img, err = fwimg.ELFImageView(data, fo)
		}
		if err != nil {
			return nil, err
		}
		s.elf, s.machine = true, ef.Machine
	case fwimg.FormatIHEX:
		s.img, err = fwimg.DecodeIHEX(data, fwimg.DecodeOptions{MaxSize: fo.MaxSize})
	case fwimg.FormatSREC:
		s.img, err = fwimg.DecodeSREC(data, fwimg.DecodeOptions{MaxSize: fo.MaxSize})
	case fwimg.FormatUImage:
		s.img, err = fwimg.UImageImage(data)
	default: // fwimg.FormatBinary
		s.img, err = fwimg.RawImage(data, rawBase)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", input, err)
	}
	return s, nil
}

// uimage wraps the image in a uImage header. The architecture, OS and type
// come from the flags, else from the input (an ELF's machine, a uImage's
// header); an input that has none is refused rather than given ARM.
func uimage(o *options, im *fwimg.Image, src *source, arch byte, hasEntry bool, entry uint64, fo fwimg.FlattenOptions) ([]byte, error) {
	flat, base, err := im.Flat(fo.Pad, fo.MaxSize)
	if err != nil {
		return nil, err
	}
	osCode, typeCode := o.osCode, o.typeCode
	switch {
	case im.UImage != nil:
		arch = cmp.Or(arch, im.UImage.Arch)
		osCode = cmp.Or(osCode, im.UImage.OS)
		typeCode = cmp.Or(typeCode, im.UImage.Type)
	case src.elf:
		arch = cmp.Or(arch, fwimg.ArchFromELF(src.machine))
	case arch == 0:
		return nil, usageErr{"--uimage-arch is required: the input does not say which architecture it is for"}
	}
	if !hasEntry {
		return nil, usageErr{"--entry is required: the input has no start address"}
	}
	if base > math.MaxUint32 {
		return nil, fmt.Errorf("image base 0x%x does not fit 32 bits: give --load", base)
	}
	if entry > math.MaxUint32 {
		return nil, fmt.Errorf("ELF entry 0x%x does not fit 32 bits: give --entry", entry)
	}
	return fwimg.UImage(flat, fwimg.UImageOptions{
		Load: uint32(base), Entry: uint32(entry), Name: cmp.Or(o.name, im.Name),
		OS: osCode, Arch: arch, Type: typeCode,
	})
}
