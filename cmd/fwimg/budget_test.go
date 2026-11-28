package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A write that fails part-way leaves no file: the budget refusal in the
// library (and a full disk) must not leave up to a limit's worth of partial
// output behind. The fill writes a little and fails; nothing is large.
func TestWriteOutputRemovesAPartialFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out")
	boom := errors.New("budget")
	err := writeOutput(p, func(w io.Writer) error {
		_, _ = w.Write([]byte("partial"))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, e := os.Lstat(p); !os.IsNotExist(e) {
		t.Fatalf("a failed write left %s (%v)", p, e)
	}
	// A write that succeeds still leaves its file.
	if err := writeOutput(p, func(w io.Writer) error { _, e := w.Write([]byte("x")); return e }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Fatalf("content %q", b)
	}
}
