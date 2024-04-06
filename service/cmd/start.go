package cmd

import (
	"github.com/arkavo-org/opentdf-platform/service/pkg/server"
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

func start(cmd *cobra.Command, _ []string) error {
	configFile, _ := cmd.Flags().GetString(configFileFlag)
	configKey, _ := cmd.Flags().GetString(configKeyFlag)

	return server.Start(
		server.WithWaitForShutdownSignal(),
		server.WithConfigFile(configFile),
		server.WithConfigKey(configKey),
	)
}
