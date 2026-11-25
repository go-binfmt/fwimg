//go:build floor_parse && floor_osio

package main

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-binfmt/fwimg/internal/elfgen"
)

// With floor_parse the control parses what it read and writes it unchanged.
func TestParseRefusesNonELF(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	img := elfgen.Build(elf.EM_AARCH64, 0, []elfgen.Seg{{Paddr: 0x80000, Off: 0x200, Filesz: 4, Memsz: 4, Data: []byte("ABCD")}})
	if err := os.WriteFile(in, img, 0o644); err != nil {
		t.Fatal(err)
	}
	read, written, err := work(in, out, 0)
	if err != nil || read != len(img) || written != len(img) {
		t.Fatalf("read %d written %d err %v, want %d and %d", read, written, err, len(img), len(img))
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, img) {
		t.Error("the parsed bytes were not written unchanged")
	}
	if err := os.WriteFile(in, []byte("not an elf"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := work(in, out, 0); err == nil {
		t.Error("a file that is not an ELF was parsed")
	}
}
