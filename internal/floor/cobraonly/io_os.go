//go:build floor_osio

package main

import "os"

// Read with os.ReadFile and write with os.WriteFile, which is what
// cmd/fwimg does: O_WRONLY|O_CREATE|O_TRUNC, mode 0644.
func init() {
	work = func(in, out string, n int) (int, int, error) {
		b, err := os.ReadFile(in)
		if err != nil {
			return 0, 0, err
		}
		w, err := shape(b, n)
		if err != nil {
			return len(b), 0, err
		}
		if err := os.WriteFile(out, w, 0o644); err != nil {
			return len(b), 0, err
		}
		return len(b), len(w), nil
	}
}
