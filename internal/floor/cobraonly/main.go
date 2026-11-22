// Command cobraonly is a cobra root command that does nothing. internal/bench
// times it next to fwimg to show what cobra's initialisation costs on top of
// the Go runtime, before fwimg does any work.
package main

import (
	"os"

	"github.com/spf13/cobra"
)

// osExit is replaceable in tests.
var osExit = os.Exit

// RootCmd returns the command tree: one root, no flags, no work.
func RootCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "cobraonly",
		SilenceUsage: true,
		Run:          func(*cobra.Command, []string) {},
	}
}

func main() {
	if err := RootCmd().Execute(); err != nil {
		osExit(1)
	}
}
