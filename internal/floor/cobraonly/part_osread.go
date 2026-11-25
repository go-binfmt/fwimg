//go:build floor_osread

package main

import "os"

// Only the read half of floor_osio: the input is read and nothing is written,
// to time what the read costs on its own.
func init() {
	work = func(in, _ string, _ int) (int, int, error) {
		b, err := os.ReadFile(in)
		return len(b), 0, err
	}
}
