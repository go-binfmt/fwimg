package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The generator must reproduce the committed corpus exactly: a seed edited by
// hand, or a generator changed without regenerating, is a failure here.
func TestRunReproducesTheCommittedCorpus(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "testdata", "fuzz", "FuzzFlatten")
	made, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadDir(committed)
	if err != nil {
		t.Fatal(err)
	}
	if len(made) != len(want) || len(made) != 7 {
		t.Fatalf("generated %d seeds, committed %d, want 7", len(made), len(want))
	}
	for _, e := range made {
		a, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(committed, e.Name()))
		if err != nil {
			t.Fatalf("seed %s is not committed: %v", e.Name(), err)
		}
		if string(a) != string(b) {
			t.Errorf("seed %s differs from the committed one: run go run ./internal/mkcorpus", e.Name())
		}
		if !strings.HasPrefix(string(a), "go test fuzz v1\n[]byte(") {
			t.Errorf("seed %s is not in the fuzz corpus format", e.Name())
		}
	}
}

func TestRunRefusals(t *testing.T) {
	t.Run("directory cannot be made", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(file, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		// The refusal comes from MkdirAll, not from a later write.
		if err := run(filepath.Join(file, "sub")); err == nil || !strings.HasPrefix(err.Error(), "mkdir ") {
			t.Fatalf("err = %v, want a mkdir refusal", err)
		}
	})
	t.Run("seed cannot be written", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "overlap"), 0o755); err != nil {
			t.Fatal(err)
		}
		err := run(dir)
		if err == nil || !strings.Contains(err.Error(), "overlap") {
			t.Fatalf("err = %v, want it to name the seed", err)
		}
	})
}
