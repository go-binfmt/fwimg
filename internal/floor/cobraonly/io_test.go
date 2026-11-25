//go:build (floor_osio || (floor_sysio && linux)) && !floor_parse && !floor_flatten

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The control must do what fwimg does with the same input: read it whole and
// write n bytes to an output opened O_WRONLY|O_CREATE|O_TRUNC with mode 0644.
// The counts are asserted, not only the file, so a control that quietly reads
// less than the input, or writes a different size, fails here.
func TestIOReadsAllAndWritesN(t *testing.T) {
	if work == nil {
		t.Fatal("the build tag installed no work")
	}
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	src := bytes.Repeat([]byte("0123456789abcdef"), 1000) // larger than the first buffer
	if err := os.WriteFile(in, src, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, bytes.Repeat([]byte{9}, 50000), 0o644); err != nil {
		t.Fatal(err)
	}
	read, written, err := work(in, out, 0)
	if err != nil || read != len(src) || written != len(src) {
		t.Fatalf("n=0: read %d written %d err %v, want %d and %d", read, written, err, len(src), len(src))
	}
	if got, _ := os.ReadFile(out); !bytes.Equal(got, src) {
		t.Errorf("copy differs: %d bytes, want %d", len(got), len(src))
	}
	read, written, err = work(in, out, 1024)
	if err != nil || read != len(src) || written != 1024 {
		t.Fatalf("n=1024: read %d written %d err %v, want %d and 1024", read, written, err, len(src))
	}
	st, err := os.Stat(out)
	if err != nil || st.Size() != 1024 {
		t.Fatalf("output after n=1024: %v, %v (the old 50000 bytes must be truncated)", st, err)
	}
	// A new output file gets mode 0644 (before the umask).
	fresh := filepath.Join(dir, "fresh")
	old := umask(0)
	_, _, err = work(in, fresh, 16)
	umask(old)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(fresh); st.Mode().Perm() != 0o644 {
		t.Errorf("new output mode = %v, want 0644", st.Mode().Perm())
	}
	if _, _, err := work(filepath.Join(dir, "none"), out, 0); err == nil {
		t.Error("a missing input was accepted")
	}
	if _, _, err := work(in, filepath.Join(dir, "none", "out"), 0); err == nil {
		t.Error("a missing output directory was accepted")
	}
}
