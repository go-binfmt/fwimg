//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package main

import "os"

// minorFaults: this system exposes no page-fault count through os, so the
// column reads 0.
func minorFaults(*os.ProcessState) int64 { return 0 }
