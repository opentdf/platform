/*
'Copyright 2023 Virtru Corporation'
*/
package cmd

import (
	"github.com/opentdf/opentdf-v2-poc/pkg/server"

	// "github.com/opentdf/opentdf-v2-poc/services/acre"

	// "github.com/opentdf/opentdf-v2-poc/services/keyaccessgrants"
	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals // startCmd represents the start command.
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the opentdf service",
	RunE:  start,
}

func init() {
	startCmd.SilenceUsage = true
	rootCmd.AddCommand(startCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func start(_ *cobra.Command, _ []string) error {
	return server.Start(server.WithWaitForShutdownSignal())
}
