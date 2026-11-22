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

	"github.com/spf13/cobra"
)

// osExit is replaceable in tests.
var osExit = os.Exit

// work, when a build tag sets it, copies args[0] to args[1].
var work func(in, out string) error

// RootCmd returns the command tree: one root, no flags, no work unless a
// build tag installed one and two arguments were given.
func RootCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "cobraonly",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if work != nil && len(args) == 2 {
				return work(args[0], args[1])
			}
			return nil
		},
	}
}

func main() {
	if err := RootCmd().Execute(); err != nil {
		osExit(1)
	}
}
