package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const Version = "0.4.37" // Service Version // x-release-please-version

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Platform version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Println(Version)
			return nil
		},
	})
}
