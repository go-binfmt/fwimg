//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import (
	"syscall"
	"testing"
)

// Minor and major come from their own fields, not swapped.
func TestRusageFaults(t *testing.T) {
	if mi, ma := rusageFaults(&syscall.Rusage{Minflt: 7, Majflt: 3}); mi != 7 || ma != 3 {
		t.Errorf("rusageFaults = %d, %d; want 7, 3", mi, ma)
	}
}

// A process that starts takes at least one minor page fault, so a count of 0
// means the Rusage type assertion failed. Major faults are read from the same
// struct: a warm start takes few, and never a negative number.
func TestFaultsAreReported(t *testing.T) {
	_, f, err := timeOne([]string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if f.minor <= 0 {
		t.Errorf("minor faults = %d, want > 0", f.minor)
	}
	if f.major < 0 {
		t.Errorf("major faults = %d", f.major)
	}
}
