package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-binfmt/fwimg"
)

func TestSameBytes(t *testing.T) {
	dir := t.TempDir()
	// A body of more than two chunks, so the loop turns more than once.
	want := bytes.Repeat([]byte("0123456789abcdef"), 3*verifyChunk/16+5)
	put := func(b []byte) string {
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	flip := func(i int) []byte {
		b := bytes.Clone(want)
		b[i] ^= 1
		return b
	}
	for name, c := range map[string]struct {
		file []byte
		want bool
	}{
		"equal":              {want, true},
		"first byte":         {flip(0), false},
		"last byte":          {flip(len(want) - 1), false},
		"second chunk":       {flip(verifyChunk + 1), false},
		"one byte short":     {want[:len(want)-1], false},
		"a chunk short":      {want[:len(want)-verifyChunk], false},
		"empty":              {nil, false},
		"one byte long":      {append(bytes.Clone(want), 'x'), false},
		"a whole chunk long": {append(bytes.Clone(want), make([]byte, verifyChunk)...), false},
	} {
		if got, err := sameBytes(put(c.file), want); err != nil || got != c.want {
			t.Errorf("%s: %v, %v, want %v", name, got, err, c.want)
		}
	}
	// Nothing written, nothing found: the empty file is the empty body.
	if got, err := sameBytes(put(nil), nil); err != nil || !got {
		t.Errorf("empty body: %v, %v", got, err)
	}
	if got, err := sameBytes(put([]byte("x")), nil); err != nil || got {
		t.Errorf("empty body, one byte: %v, %v", got, err)
	}
	// A failure to read is an error, not a difference, whichever read fails.
	if _, err := sameBytes(filepath.Join(dir, "absent"), want); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("absent: %v", err)
	}
	if _, err := sameBytes(dir, want); err == nil {
		t.Error("a directory read as a file")
	}
	if _, err := sameBytes(dir, nil); err == nil {
		t.Error("a directory read as an empty file")
	}
}

func TestVerifyReportsAFileThatVanishesBetweenTheTwoReads(t *testing.T) {
	boom := errors.New("gone")
	readBack = func(string) ([]byte, error) { return nil, boom }
	defer func() { readBack = readInput }()
	corrupt(t, func(p string) { _ = os.WriteFile(p, []byte("XXXX"), 0o644) })
	if _, _, err := runCmd(t, "-O", "srec", "-o", out(t), simple(t)); !errors.Is(err, boom) || errors.Is(err, fwimg.ErrVerify) {
		t.Errorf("err = %v", err)
	}
}

// A file that is not the one written is refused even when it reads back as the
// same image: the check is on the bytes, and the decoder only names the place.
func TestVerifyRefusesAFileThatIsNotWhatWasWritten(t *testing.T) {
	in := simple(t)
	for _, f := range []string{"srec", "ihex", "uimage"} {
		corrupt(t, func(p string) {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		})
		o := out(t)
		_, _, err := runCmd(t, "-O", f, "-o", o, in)
		if !errors.Is(err, fwimg.ErrVerify) || !strings.Contains(err.Error(), "(the file was removed)") {
			t.Errorf("%s: %v", f, err)
		}
		absent(t, o)
	}
}
