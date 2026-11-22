//go:build floor_osio || (floor_sysio && linux)

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Both ways of doing the I/O copy a file larger than the system-call
// version's first buffer, over an existing output, and refuse a missing input.
func TestIOCopies(t *testing.T) {
	if work == nil {
		t.Fatal("the build tag installed no work")
	}
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	want := bytes.Repeat([]byte("0123456789abcdef"), 1000)
	if err := os.WriteFile(in, want, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, bytes.Repeat([]byte{9}, 50000), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := work(in, out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, want) {
		t.Errorf("copy differs: %d bytes, want %d", len(got), len(want))
	}
	if err := work(filepath.Join(dir, "none"), out); err == nil {
		t.Error("a missing input was accepted")
	}
	if err := work(in, filepath.Join(dir, "none", "out")); err == nil {
		t.Error("a missing output directory was accepted")
	}
}
