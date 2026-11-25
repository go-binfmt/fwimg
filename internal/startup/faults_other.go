//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package main

import "os"

// faults: this system exposes no page-fault count through os, so the columns
// read 0.
func faults(*os.ProcessState) (minor, major int64) { return 0, 0 }
