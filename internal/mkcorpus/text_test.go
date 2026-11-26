package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
)

// The text seeds are checked against the decoders they feed: a seed named
// valid-* must decode, every other one must be refused, so a hand-written
// checksum that is wrong cannot pass for a hostile case, nor the reverse.
func TestTextSeedsMeanWhatTheirNamesSay(t *testing.T) {
	for _, c := range []struct {
		name   string
		seeds  map[string][]byte
		decode func([]byte) error
	}{
		{"FuzzIHEX", ihexSeeds(), func(b []byte) error { _, err := fwimg.DecodeIHEX(b, fwimg.DecodeOptions{MaxSize: 1 << 10}); return err }},
		{"FuzzSREC", srecSeeds(), func(b []byte) error { _, err := fwimg.DecodeSREC(b, fwimg.DecodeOptions{MaxSize: 1 << 10}); return err }},
		{"FuzzUImage", uimageSeeds(), func(b []byte) error {
			h, p, err := fwimg.ParseUImage(b)
			if err == nil {
				_, err = h.Components(p)
			}
			return err
		}},
	} {
		for name, b := range c.seeds {
			err := c.decode(b)
			if valid := strings.HasPrefix(name, "valid-"); valid != (err == nil) {
				t.Errorf("%s/%s: err = %v", c.name, name, err)
			}
		}
	}
}

func TestTextSeedsReproduceTheCommittedCorpus(t *testing.T) {
	dir := t.TempDir()
	if err := all(dir); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"FuzzFlatten", "FuzzIHEX", "FuzzSREC", "FuzzUImage"} {
		made, err := os.ReadDir(filepath.Join(dir, d))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadDir(filepath.Join("..", "..", "testdata", "fuzz", d))
		if err != nil {
			t.Fatal(err)
		}
		if len(made) != len(want) || len(made) == 0 {
			t.Fatalf("%s: generated %d seeds, committed %d", d, len(made), len(want))
		}
		for _, e := range made {
			a, _ := os.ReadFile(filepath.Join(dir, d, e.Name()))
			b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fuzz", d, e.Name()))
			if err != nil || string(a) != string(b) {
				t.Errorf("%s/%s differs from the committed seed (%v): run go run ./internal/mkcorpus", d, e.Name(), err)
			}
		}
	}
}

func TestTextRefusals(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runText(filepath.Join(file, "sub")); err == nil || !strings.HasPrefix(err.Error(), "mkdir ") {
		t.Errorf("err = %v, want a mkdir refusal", err)
	}
	if err := all(filepath.Join(file, "sub")); err == nil {
		t.Error("all wrote under a file")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "FuzzIHEX", "valid-empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runText(dir); err == nil || !strings.Contains(err.Error(), "valid-empty") {
		t.Errorf("err = %v, want it to name the seed", err)
	}
	// The seeds that panic on a library error are only reached with a broken
	// encoder: the helper itself is checked here.
	defer func() {
		if recover() == nil {
			t.Error("must did not panic on an error")
		}
	}()
	must(nil, os.ErrClosed)
}
