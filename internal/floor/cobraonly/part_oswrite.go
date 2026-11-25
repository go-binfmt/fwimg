//go:build floor_oswrite

package main

import "os"

// Only the write half of floor_osio: n zero bytes (1024 when n is 0) are
// written to the output, to time what the write costs on its own.
func init() {
	work = func(_, out string, n int) (int, int, error) {
		if n == 0 {
			n = 1024
		}
		if err := os.WriteFile(out, make([]byte, n), 0o644); err != nil {
			return 0, 0, err
		}
		return 0, n, nil
	}
}
