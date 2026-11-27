// Command fwimg converts an ELF executable into a flat binary, a Motorola
// S-record, an Intel HEX file or a legacy U-Boot uImage, in pure Go. The
// flags mirror `objcopy -O` and `mkimage`.
package main

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

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

	// L3: memory regions, the gap warning, the check of the written file and
	// the uImage time.
	region   []string
	gapWarn  uint64
	noVerify bool
	timeFlag string
	stamp    uint32

	// L4: the manifest file.
	manifest string
	errw     io.Writer // warnings

	// L5: uImage compression, UF2 family, Verilog data width and byte order.
	uimageComp    string
	uf2Family     string
	verilogWidth  int
	verilogEndian string

	family uint32               // --uf2-family, parsed
	vopts  fwimg.VerilogOptions // the Verilog options, once the input is known
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

--manifest FILE also writes a JSON manifest of the image: format, base, entry,
sizes, CRC-32 and SHA-256 of the whole image and of each segment. fwimg info
FILE describes any input (a uImage the way mkimage -l does, --json as a
manifest) and fwimg verify --manifest FILE IMAGE checks an image against one.`,
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
			o.errw = cmd.ErrOrStderr()
			return run(&o, args[0])
		},
	}
	fl := cmd.Flags()
	fl.Bool("version", false, "print the version")
	fl.StringVarP(&o.output, "output", "o", "", "output file (required)")
	fl.StringVarP(&o.input, "input-target", "I", "", "input format: elf, ihex, srec, uimage, uf2, verilog, binary (default: detected; binary is never detected)")
	fl.StringVar(&o.base, "base", "", "load address of a raw binary input, decimal or 0x-hex (required with -I binary)")
	fl.StringVarP(&o.format, "output-target", "O", "binary", "output format: binary, srec, ihex, uimage, uf2, verilog")
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
	fl.StringArrayVar(&o.region, "region", nil, "memory region NAME=START:SIZE (K, M, G suffixes); repeatable; refuse a segment that overflows a region or lies outside every one")
	fl.Uint64Var(&o.gapWarn, "gap-warn", 8, "warn on stderr when a flat output (binary, uimage) holds more than this many times its data as filler, from 64 KiB of it; 0 turns the warning off")
	fl.BoolVar(&o.noVerify, "no-verify", false, "do not read the output back and compare it with the image (the check is on by default)")
	fl.StringVar(&o.timeFlag, "time", "", "uimage creation time in seconds, decimal or 0x-hex (default: SOURCE_DATE_EPOCH when set, else 0)")
	fl.StringVar(&o.manifest, "manifest", "", "write a JSON manifest of the image (schema manifest-1) to this file, after the output is written and checked")
	fl.StringVar(&o.uimageComp, "uimage-comp", "none", "uimage payload compression: none, gzip, lz4 (the payload is compressed here, mkimage does not)")
	fl.StringVar(&o.uf2Family, "uf2-family", "", "UF2 family: a name of utils/uf2families.json (rp2040, samd21, ...) or a number; none by default")
	fl.IntVar(&o.verilogWidth, "verilog-data-width", 1, "Verilog data width in bytes, 1 to 8 (objcopy's name); also how a Verilog input is read")
	fl.StringVar(&o.verilogEndian, "verilog-endian", "", "Verilog byte order within a word: little or big (default: big for a big-endian ELF, else little); also for a Verilog input")
	cmd.AddCommand(infoCmd(), verifyCmd())
	return cmd
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

// afterMap is replaceable in tests: it runs once an input is mapped, where a
// test changes the file under the mapping.
var afterMap = func(string) {}

// inputBytes returns the bytes of an input and the function that releases
// them. An ELF is mapped (elfpatch.Open: read-only, the pages are faulted in
// as they are used, and a system without mmap reads the file), so the 4 or
// 32 MiB of a firmware are not copied into a buffer first
// (go-binfmt/fwimg#17). Anything else, and any input Open refuses, is read as
// before, so the error of a bad input is the one readInput and the parsers
// always gave. Use the bytes under mapGuard: a file truncated while mapped
// faults on access.
func inputBytes(input string) ([]byte, func() error, error) {
	if f, err := elfpatch.Open(input); err == nil {
		if b := f.Bytes(); int64(len(b)) <= maxInput {
			afterMap(input)
			return b, f.Close, nil
		}
		f.Close()
	}
	data, err := readInput(input)
	return data, func() error { return nil }, err
}

// mapGuard makes a fault on mapped memory a panic of this goroutine for as long
// as it runs, and turns that panic into *errp: the input was truncated while
// it was mapped. Use it as `defer mapGuard(&err)()`.
func mapGuard(errp *error) func() {
	old := debug.SetPanicOnFault(true)
	return func() {
		debug.SetPanicOnFault(old)
		if r := recover(); r != nil {
			// Linux reports "unexpected fault address"; macOS gives SIGBUS no
			// address, which Go reads as a nil dereference. The message is kept.
			if re, ok := r.(runtime.Error); ok && (strings.Contains(re.Error(), "fault") || strings.Contains(re.Error(), "nil pointer")) {
				*errp = fmt.Errorf("the input file changed while it was mapped: %v", re)
				return
			}
			panic(r)
		}
	}
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

func run(o *options, input string) (err error) {
	if o.output == "" {
		return usageErr{"-o/--output is required"}
	}
	switch o.format {
	case "binary", "srec", "ihex", "uimage", "uf2", "verilog":
	default:
		return usageErr{fmt.Sprintf("unknown --output-target %q (want binary, srec, ihex, uimage, uf2, verilog)", o.format)}
	}
	comp, err := fwimg.CompFromName(o.uimageComp)
	if err != nil {
		return usageErr{err.Error()}
	}
	if comp != fwimg.CompNone && o.format != "uimage" {
		return usageErr{"--uimage-comp is only for -O uimage"}
	}
	if o.uf2Family != "" {
		if o.format != "uf2" {
			return usageErr{"--uf2-family is only for -O uf2"}
		}
		if o.family, err = fwimg.ParseUF2Family(o.uf2Family); err != nil {
			return usageErr{err.Error()}
		}
	}
	if o.verilogEndian != "" && o.verilogEndian != "little" && o.verilogEndian != "big" {
		return usageErr{fmt.Sprintf("unknown --verilog-endian %q (want little or big)", o.verilogEndian)}
	}
	if o.verilogWidth < 1 || o.verilogWidth > 8 {
		return usageErr{fmt.Sprintf("--verilog-data-width %d: want 1 to 8 bytes", o.verilogWidth)}
	}
	o.vopts = fwimg.VerilogOptions{DataWidth: o.verilogWidth, BigEndian: o.verilogEndian == "big"}
	rawBase, err := checkInput(o.input, o.base)
	if err != nil {
		return err
	}
	if o.manifest != "" && o.manifest == o.output {
		return usageErr{"--manifest and -o name the same file"}
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

	regions, err := fwimg.ParseRegions(o.region)
	if err != nil {
		return usageErr{err.Error()}
	}
	if o.timeFlag != "" && o.format != "uimage" {
		return usageErr{"--time is only for -O uimage"}
	}
	if o.format == "uimage" {
		if o.stamp, err = uimageTime(o.timeFlag); err != nil {
			return err
		}
	}

	data, release, err := inputBytes(input)
	if err != nil {
		return err
	}
	defer release()
	defer mapGuard(&err)()
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
	src, err := load(in, data, fo, sel, rawBase, input, o.vopts)
	if err != nil {
		return err
	}
	if o.verilogEndian == "" && src.elf && len(data) > 5 && data[5] == 2 {
		o.vopts.BigEndian = true // objcopy: the byte order of the ELF
	}
	im := src.img
	// The layout of the ELF, for the messages that name what lies where: read
	// only when one is written, and not once the addresses have been moved.
	var lay *fwimg.Layout
	var laid bool
	layout := func() *fwimg.Layout {
		if !laid {
			laid = true
			if src.elf && o.shift == "" && o.load == "" {
				lay = fwimg.ELFLayout(data, o.useVaddr)
			}
		}
		return lay
	}
	// explain adds what makes the hole to a refusal for size.
	explain := func(err error) error {
		if t := im.ExplainGap(layout()); t != "" && errors.Is(err, fwimg.ErrTooLarge) {
			return fmt.Errorf("%w\n  %s", err, t)
		}
		return err
	}

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
			return explain(err)
		}
	}
	if o.padTo != "" {
		if err := im.PadTo(padTo, fo.Pad, fo.MaxSize); err != nil {
			return explain(err)
		}
	}
	if len(regions) > 0 {
		if err := im.CheckRegions(regions, func(lo, hi uint64) string { return layout().Describe(lo, hi) }); err != nil {
			return err
		}
	}

	var out []byte
	var emit func(io.Writer) error // set when the output is streamed, not built
	var uopts fwimg.UImageOptions
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
		out, uopts, err = uimage(o, im, src, arch, hasEntry, entry, fo)
	case "uf2":
		out, err = fwimg.EncodeUF2(im, fwimg.UF2Options{Family: o.family})
	case "verilog":
		out, err = fwimg.EncodeVerilog(im, o.vopts)
	}
	if err != nil {
		return explain(err)
	}
	if (o.format == "binary" || o.format == "uimage") && o.gapWarn != 0 {
		if w := im.GapWarning(o.gapWarn); w != "" {
			fmt.Fprintf(o.errw, "fwimg: warning: %s\n  %s\n", w, im.ExplainGap(layout()))
		}
	}
	if emit == nil {
		emit = func(w io.Writer) error { _, err := w.Write(out); return err }
	}
	if err := writeOutput(o.output, emit); err != nil {
		return err
	}
	if !o.noVerify {
		afterWrite(o.output)
		if err := verifyOutput(o, im, fo.Pad, uopts, out); err != nil {
			if rerr := removeFile(o.output); rerr != nil {
				err = errors.Join(err, rerr)
			}
			return fmt.Errorf("%s: %w (the file was removed)", o.output, err)
		}
	}
	if o.manifest == "" {
		return nil
	}
	return writeManifest(o, im, src, in, data, input, fo, uopts)
}

// writeManifest describes the image just written, and the input it came from.
func writeManifest(o *options, im *fwimg.Image, src *source, in string, data []byte, input string, fo fwimg.FlattenOptions, uopts fwimg.UImageOptions) error {
	regions, _ := fwimg.ParseRegions(o.region) // parsed before, in run
	epoch, err := manifestEpoch()
	if err != nil {
		return err
	}
	mo := fwimg.ManifestOptions{
		Version: version(), Format: o.format, Source: sourceOf(input, in, data),
		Regions: regions, Pad: fo.Pad, MaxSize: fo.MaxSize, Epoch: epoch,
	}
	if src.elf {
		if mo.Sections, err = fwimg.ELFManifestSections(data); err != nil {
			return fmt.Errorf("%s: %w", input, err)
		}
	}
	if o.format == "uimage" {
		mo.UImage = uimageHeader(uopts)
	}
	m, err := fwimg.NewManifest(im, mo)
	if err != nil {
		return err
	}
	return writeOutput(o.manifest, func(w io.Writer) error { _, err := w.Write(m.JSON()); return err })
}

// afterWrite is replaceable in tests: it runs once the output is written and
// before it is read back, where a test damages the file.
var afterWrite = func(string) {}

// readBack reads a differing output whole, to name its first difference; it is
// replaceable in tests, where the file goes away between the two reads.
var readBack = readInput

// verifyOutput reads the file just written back and compares it with the image:
// the flat binary byte for byte, an S-record or Intel HEX file decoded to an
// image and compared by address with the start address, a uImage by its CRCs,
// header and payload. Only a regular file is checked: a device, a pipe or a
// symbolic link (/dev/stdout) cannot be read back, or removed, as this file can.
//
// For the formats built in memory (everything but the flat binary) the check has
// two steps. The file is first compared, in chunks, with the bytes that were
// written: when they are equal there is nothing more to say, and that costs a
// read and a memcmp. Decoding the file back, which took twice as long as writing
// it (go-binfmt/fwimg, bench at v0.5.0: +196 % at 32 MiB), is only the way to
// name the first difference when they are not equal.
func verifyOutput(o *options, im *fwimg.Image, pad byte, uopts fwimg.UImageOptions, written []byte) error {
	if st, err := os.Lstat(o.output); err == nil && !st.Mode().IsRegular() {
		return nil
	}
	if o.format == "binary" {
		f, err := os.Open(o.output)
		if err != nil {
			return err
		}
		defer f.Close()
		return fwimg.VerifyFlat(f, im, pad)
	}
	same, err := sameBytes(o.output, written)
	if err != nil || same {
		return err
	}
	b, err := readBack(o.output)
	if err != nil {
		return err
	}
	var got *fwimg.Image
	dopts := fwimg.DecodeOptions{MaxSize: math.MaxInt32}
	switch o.format {
	case "uimage":
		err = fwimg.VerifyUImage(b, im, pad, uopts)
	case "srec":
		got, err = fwimg.DecodeSREC(b, dopts)
	case "uf2":
		err = fwimg.VerifyUF2(b, im, fwimg.UF2Options{Family: o.family})
	case "verilog":
		got, err = fwimg.DecodeVerilog(b, o.vopts, dopts)
	default:
		got, err = fwimg.DecodeIHEX(b, dopts)
	}
	switch {
	case err != nil && (o.format == "uimage" || o.format == "uf2"):
		return err
	case err != nil:
		return fmt.Errorf("%w: %v", fwimg.ErrVerify, err)
	case got != nil:
		if err := fwimg.CompareImages(im, got); err != nil {
			return err
		}
	}
	// It reads back as the same image but is not the file that was written.
	return fmt.Errorf("%w: the file is not the %d bytes that were written", fwimg.ErrVerify, len(written))
}

// verifyChunk is the buffer sameBytes reads in: small enough to stay in cache,
// so the file is read once into memory that is already mapped.
const verifyChunk = 256 << 10

// sameBytes reports whether the file at path holds exactly want. An error is a
// failure to read it, not a difference.
func sameBytes(path string, want []byte) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf := make([]byte, min(len(want)+1, verifyChunk))
	for len(want) > 0 {
		got := buf[:min(len(want), len(buf))]
		if _, err := io.ReadFull(f, got); err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		} else if err != nil {
			return false, err
		}
		if !bytes.Equal(got, want[:len(got)]) {
			return false, nil
		}
		want = want[len(got):]
	}
	switch n, err := f.Read(buf[:1]); {
	case n > 0:
		return false, nil // longer than what was written
	case err == io.EOF:
		return true, nil
	default:
		return false, err
	}
}

// uimageTime is the creation time of a uImage: --time, else SOURCE_DATE_EPOCH
// as mkimage reads it (but a value that is not seconds is refused where mkimage
// writes 0), else 0 where mkimage takes the input file's mtime: the same
// command line makes the same file.
func uimageTime(flagValue string) (uint32, error) {
	if flagValue != "" {
		v, err := parseUint("time", flagValue, 32)
		return uint32(v), err
	}
	if v, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		return fwimg.ParseEpoch(v)
	}
	return 0, nil
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
	if err := fill(f); err != nil {
		// A refusal made while writing (the output's own budget, a full disk)
		// leaves no partial file behind, in a directory nobody looks at.
		_ = os.Remove(path)
		return err
	}
	return nil
}

// source is a loaded input: its image, and what only the ELF knows.
type source struct {
	img     *fwimg.Image
	elf     bool
	machine uint16
}

// load builds the Image of an input of the given format.
func load(format string, data []byte, fo fwimg.FlattenOptions, sel fwimg.SectionSelect, rawBase uint64, input string, vo fwimg.VerilogOptions) (*source, error) {
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
		s.elf, s.machine = true, ef.Machine // an error is returned below, with the others
	case fwimg.FormatIHEX:
		s.img, err = fwimg.DecodeIHEX(data, fwimg.DecodeOptions{MaxSize: fo.MaxSize})
	case fwimg.FormatSREC:
		s.img, err = fwimg.DecodeSREC(data, fwimg.DecodeOptions{MaxSize: fo.MaxSize})
	case fwimg.FormatUImage:
		s.img, err = fwimg.UImageImageOpts(data, fwimg.DecodeOptions{MaxSize: fo.MaxSize})
	case fwimg.FormatUF2:
		s.img, err = fwimg.DecodeUF2(data, fwimg.DecodeOptions{MaxSize: fo.MaxSize})
	case fwimg.FormatVerilog:
		s.img, err = fwimg.DecodeVerilog(data, vo, fwimg.DecodeOptions{MaxSize: fo.MaxSize})
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
func uimage(o *options, im *fwimg.Image, src *source, arch byte, hasEntry bool, entry uint64, fo fwimg.FlattenOptions) ([]byte, fwimg.UImageOptions, error) {
	none := fwimg.UImageOptions{}
	flat, base, err := im.Flat(fo.Pad, fo.MaxSize)
	if err != nil {
		return nil, none, err
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
		return nil, none, usageErr{"--uimage-arch is required: the input does not say which architecture it is for"}
	}
	if !hasEntry {
		return nil, none, usageErr{"--entry is required: the input has no start address"}
	}
	if base > math.MaxUint32 {
		return nil, none, fmt.Errorf("image base 0x%x does not fit 32 bits: give --load", base)
	}
	if entry > math.MaxUint32 {
		return nil, none, fmt.Errorf("ELF entry 0x%x does not fit 32 bits: give --entry", entry)
	}
	opts := fwimg.UImageOptions{
		Load: uint32(base), Entry: uint32(entry), Name: cmp.Or(o.name, im.Name),
		OS: osCode, Arch: arch, Type: typeCode, Time: o.stamp,
	}
	// The name was checked where the flags are, and CompressPayload refuses
	// only a comp CompFromName never returns: neither error is reachable here.
	comp, _ := fwimg.CompFromName(o.uimageComp)
	if comp != fwimg.CompNone {
		flat, _ = fwimg.CompressPayload(flat, comp)
		opts.Comp = comp
	}
	out, err := fwimg.UImage(flat, opts)
	return out, opts, err
}
