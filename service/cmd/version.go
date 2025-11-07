package cmd

import "github.com/spf13/cobra"

const Version = "0.11.0" // Service Version // x-release-please-version

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Platform version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Println(Version)
			return nil
		},
	})
}
