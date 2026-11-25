//go:build floor_osread || floor_oswrite

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The two halves of the I/O: osread reads and writes nothing, oswrite writes
// n zero bytes (1024 by default) and reads nothing.
func TestHalves(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	if err := os.WriteFile(in, make([]byte, 5000), 0o644); err != nil {
		t.Fatal(err)
	}
	read, written, err := work(in, out, 77)
	if err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(out)
	if readHalf {
		if read != 5000 || written != 0 || statErr == nil {
			t.Errorf("osread: read %d written %d, output exists %v", read, written, statErr == nil)
		}
		if _, _, err := work(filepath.Join(dir, "none"), out, 0); err == nil {
			t.Error("a missing input was accepted")
		}
		return
	}
	st, _ := os.Stat(out)
	if read != 0 || written != 77 || statErr != nil || st.Size() != 77 {
		t.Errorf("oswrite: read %d written %d, stat %v", read, written, statErr)
	}
	if _, written, _ = work(in, out, 0); written != 1024 {
		t.Errorf("default size = %d, want 1024", written)
	}
	if _, _, err := work(in, filepath.Join(dir, "none", "out"), 0); err == nil {
		t.Error("a missing output directory was accepted")
	}
}
