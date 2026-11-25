//go:build linux || darwin || freebsd || netbsd || openbsd

package main

import (
	"os"
	"syscall"
)

// faults is the number of minor and major page faults the finished process
// took, or 0 and 0 when the system did not report them (getrusage of the
// child, through os.ProcessState).
func faults(ps *os.ProcessState) (minor, major int64) {
	if ru, ok := ps.SysUsage().(*syscall.Rusage); ok {
		return rusageFaults(ru)
	}
	return 0, 0
}

func rusageFaults(ru *syscall.Rusage) (minor, major int64) {
	return int64(ru.Minflt), int64(ru.Majflt)
}
