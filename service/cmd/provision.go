package cmd

import "github.com/spf13/cobra"

var provisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Run local provision of data",
}

func init() {
	rootCmd.AddCommand(provisionCmd)
}
