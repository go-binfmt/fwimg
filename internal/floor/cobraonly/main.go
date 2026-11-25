// Command cobraonly is a cobra root command that does nothing. internal/bench
// times it next to fwimg to show what cobra's initialisation costs on top of
// the Go runtime, before fwimg does any work.
//
// It is also the base of an ablation: files behind the floor_* build tags add
// one import (floor_crc32, floor_binary, floor_debug, floor_elfpatch,
// floor_fwimg) or one way of doing the input/output (floor_osio with package
// os, floor_sysio with raw system calls), so the CI job can time what each one
// adds to a process that otherwise does nothing.
package main

import (
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

// osExit is replaceable in tests.
var osExit = os.Exit

// work, when a build tag sets it, reads args[0] whole and writes args[1],
// opened like fwimg opens its output (create, truncate, mode 0644). n, the
// optional third argument, is the number of bytes to write, so the control
// writes as many as fwimg does; 0 writes everything it read. It returns the
// bytes read and the bytes written.
var work func(in, out string, n int) (read, written int, err error)

// transform, when a build tag sets it, runs between the read and the write:
// an elfpatch Parse, or a fwimg Flatten, on the bytes that were just read.
var transform func([]byte) ([]byte, error)

// shape applies transform and then cuts the result to n bytes when n asks for
// fewer than it holds.
func shape(b []byte, n int) ([]byte, error) {
	if transform != nil {
		var err error
		if b, err = transform(b); err != nil {
			return nil, err
		}
	}
	if n > 0 && n < len(b) {
		b = b[:n]
	}
	return b, nil
}

// RootCmd returns the command tree: one root, no flags, no work unless a
// build tag installed one and two or three arguments were given.
func RootCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "cobraonly",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if work == nil || len(args) < 2 || len(args) > 3 {
				return nil
			}
			n := 0
			if len(args) == 3 {
				var err error
				if n, err = strconv.Atoi(args[2]); err != nil {
					return err
				}
			}
			_, _, err := work(args[0], args[1], n)
			return err
		},
	}
}

func main() {
	if err := RootCmd().Execute(); err != nil {
		osExit(1)
	}
}
