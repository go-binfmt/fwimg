//go:build floor_osio

package main

import "os"

func init() {
	work = func(in, out string) error {
		b, err := os.ReadFile(in)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o644)
	}
}
