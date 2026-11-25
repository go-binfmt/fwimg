//go:build floor_parse

package main

import "github.com/go-binfmt/elfpatch"

// One elfpatch.Parse of the bytes just read, as cmd/fwimg does; the bytes go
// on unchanged.
func init() {
	transform = func(b []byte) ([]byte, error) {
		_, err := elfpatch.Parse(b)
		return b, err
	}
}
