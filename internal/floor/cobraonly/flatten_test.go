//go:build floor_flatten && floor_osio

package main

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// With floor_flatten the control writes the flat image, as fwimg -O binary
// does: the bytes of the segment, not the ELF around it.
func TestFlattenWritesTheImage(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	img := elfgen.Build(elf.EM_AARCH64, 0, []elfgen.Seg{{Paddr: 0x80000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("ABCD")}})
	if err := os.WriteFile(in, img, 0o644); err != nil {
		t.Fatal(err)
	}
	read, written, err := work(in, out, 0)
	if err != nil || read != len(img) || written != 4 {
		t.Fatalf("read %d written %d err %v, want %d and 4", read, written, err, len(img))
	}
	if got, _ := os.ReadFile(out); string(got) != "ABCD" {
		t.Errorf("output = %q, want ABCD", got)
	}
	if err := os.WriteFile(in, []byte("not an elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := work(in, out, 0); err == nil {
		t.Error("a file that is not an ELF was flattened")
	}
}
