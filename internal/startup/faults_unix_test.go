//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import "testing"

// A process that starts takes at least one minor page fault, so a count of 0
// means the Rusage type assertion failed.
func TestMinorFaultsAreReported(t *testing.T) {
	_, f, err := timeOne([]string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if f <= 0 {
		t.Errorf("minor faults = %d, want > 0", f)
	}
}
