package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const Version = "0.5.2" // Service Version // x-release-please-version

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Platform version information",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Println(Version) //nolint:forbidigo // Print version to stdout
			return nil
		},
	})
}
