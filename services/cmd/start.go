package cmd

import (
	"github.com/opentdf/platform/services/pkg/server"
	"github.com/spf13/cobra"
)

func init() {
	startCmd := cobra.Command{
		Use:   "start",
		Short: "Start the opentdf services",
		RunE:  start,
	}
	startCmd.SilenceUsage = true
	rootCmd.AddCommand(&startCmd)
}

func start(_ *cobra.Command, _ []string) error {
	return server.Start(server.WithWaitForShutdownSignal())
}
