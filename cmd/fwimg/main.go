// Command fwimg converts an ELF executable into a flat binary, a Motorola
// S-record, an Intel HEX file or a legacy U-Boot uImage, in pure Go. The
// flags mirror `objcopy -O` and `mkimage`.
package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime/debug"
	"strconv"

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
var statFile = func(f *os.File) (os.FileInfo, error) { return f.Stat() }

type options struct {
	output, format, pad, load, entry, name string
	arch                                   string
	useVaddr                               bool
	maxSize                                string
	osCode, typeCode                       uint8
}

// RootCmd builds the command.
func RootCmd() *cobra.Command {
	var o options
	cmd := &cobra.Command{
		Use:   "fwimg [flags] INPUT.elf",
		Short: "Convert an ELF into a flat binary / SREC / Intel HEX / U-Boot uImage",
		Long: `fwimg converts an ELF executable into an image for a target that is loaded at
a fixed address: a flat binary (like objcopy -O binary), a Motorola S-record
(objcopy -O srec), an Intel HEX file (objcopy -O ihex) or a legacy U-Boot
uImage (like mkimage). No binutils, no U-Boot tools.

The input is treated as untrusted: a segment outside the file, an address
range that wraps, an image above --max-size or a value that does not fit the
format is refused, with exit status 1 and nothing written.`,
		Example: `  fwimg -O binary -o kernel.img kernel.elf
  fwimg -O ihex -o fw.hex fw.elf
  fwimg -O uimage --load 0x80000 --entry 0x80000 --name linux -o uImage kernel.elf`,
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
	return cmd
}

func parseUint(flag, s string, bits int) (uint64, error) {
	v, err := strconv.ParseUint(s, 0, bits)
	if err != nil {
		return 0, usageErr{fmt.Sprintf("--%s: %q is not an unsigned %d-bit number", flag, s, bits)}
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

	f, err := os.Open(input)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := statFile(f)
	if err != nil {
		return fmt.Errorf("%s: %w", input, err)
	}
	if st.Size() > maxInput {
		return fmt.Errorf("%s is %d bytes, above the %d byte input limit", input, st.Size(), maxInput)
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return fmt.Errorf("%s: %w", input, err)
	}
	flat, base, err := fwimg.Flatten(f, st.Size(), fo)
	if err != nil {
		return err
	}

	var out []byte
	if o.format == "binary" {
		out = flat
	} else {
		// Default addresses come from the ELF, which is 64-bit: one that
		// does not fit the format's 32 bits is refused, not truncated.
		if o.load == "" {
			if base > math.MaxUint32 {
				return fmt.Errorf("image base 0x%x does not fit 32 bits: give --load", base)
			}
			loadAddr = base
		}
		if o.entry == "" && o.format != "ihex" {
			if ef.Entry > math.MaxUint32 {
				return fmt.Errorf("ELF entry 0x%x does not fit 32 bits: give --entry", ef.Entry)
			}
			entryAddr = ef.Entry
		}
		switch o.format {
		case "srec":
			out, err = fwimg.SREC(uint32(loadAddr), flat, o.name, uint32(entryAddr), 0)
		case "ihex":
			out, err = fwimg.IHEX(uint32(loadAddr), flat, 0)
		case "uimage":
			if arch == 0 {
				arch = fwimg.ArchFromELF(ef.Machine)
			}
			out, err = fwimg.UImage(flat, fwimg.UImageOptions{
				Load: uint32(loadAddr), Entry: uint32(entryAddr), Name: o.name,
				OS: o.osCode, Arch: arch, Type: o.typeCode,
			})
		}
		if err != nil {
			return err
		}
	}
	return os.WriteFile(o.output, out, 0o644)
}
