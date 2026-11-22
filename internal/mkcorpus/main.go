// Command mkcorpus writes the committed FuzzFlatten seed corpus into
// testdata/fuzz/FuzzFlatten: the valid shapes and each hostile one the
// refusals exist for. Run it from the repository root: go run ./internal/mkcorpus
package main

import (
	"debug/elf"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

type seg = elfgen.Seg

func main() {
	if err := run("testdata/fuzz/FuzzFlatten"); err != nil {
		fmt.Fprintln(os.Stderr, "mkcorpus:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	seeds := map[string][]byte{
		"valid-one-segment": elfgen.Build(elf.EM_ARM, 0x1000, []seg{
			{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}}),
		"valid-gap": elfgen.Build(elf.EM_AARCH64, 0x1000, []seg{
			{Paddr: 0x1000, Off: 0x200, Filesz: 4, Memsz: 8, Data: []byte("AAAA")},
			{Paddr: 0x1010, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")}}),
		"valid-top-of-4GiB": elfgen.Build(elf.EM_RISCV, 0, []seg{
			{Paddr: 0xFFFFFFF0, Off: 0x200, Filesz: 16, Memsz: 16, Data: []byte("0123456789abcdef")}}),
		"bomb-distant-segments": elfgen.Build(elf.EM_X86_64, 0, []seg{
			{Paddr: 0, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")},
			{Paddr: 0x7fff_ffff_0000, Off: 0x300, Filesz: 4, Memsz: 4, Data: []byte("BBBB")}}),
		"filesz-beyond-file": elfgen.Build(elf.EM_X86_64, 0, []seg{
			{Paddr: 0x1000, Off: 0x200, Filesz: 1 << 40, Memsz: 1 << 40}}),
		"address-wraps": elfgen.Build(elf.EM_X86_64, 0, []seg{
			{Paddr: math.MaxUint64 - 1, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("AAAA")}}),
		"overlap": elfgen.Build(elf.EM_ARM, 0, []seg{
			{Paddr: 0x1000, Off: 0x200, Filesz: 8, Memsz: 8, Data: []byte("AAAAAAAA")},
			{Paddr: 0x1004, Off: 0x300, Filesz: 8, Memsz: 8, Data: []byte("BBBBBBBB")}}),
	}
	for name, b := range seeds {
		body := fmt.Sprintf("go test fuzz v1\n[]byte(%q)\n", b)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}
