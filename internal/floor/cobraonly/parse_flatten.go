//go:build floor_flatten

package main

import "github.com/go-binfmt/fwimg"

// One fwimg.FlattenBytes of the bytes just read, as cmd/fwimg does for -O
// binary: what is written is the flat image.
func init() {
	transform = func(b []byte) ([]byte, error) {
		flat, _, err := fwimg.FlattenBytes(b, fwimg.FlattenOptions{})
		return flat, err
	}
}
