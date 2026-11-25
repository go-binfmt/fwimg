//go:build (floor_osio || floor_sysio) && (linux || darwin)

package main

import "syscall"

func umask(m int) int { return syscall.Umask(m) }
