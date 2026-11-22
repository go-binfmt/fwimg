//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import (
	"os"
	"syscall"
)

// minorFaults is the number of minor page faults the finished process took,
// or 0 when the system did not report them.
func minorFaults(ps *os.ProcessState) int64 {
	if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
		return int64(ru.Minflt)
	}
	return 0
}
