package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var GenDocsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Generates docs for the e2e commands",
	RunE: func(cmd *cobra.Command, args []string) error {
		println("Generating Docs")
		err := doc.GenMarkdownTree(E2ECmd, "./docs")
		return err
	},
}

func init() {
	E2ECmd.AddCommand(GenDocsCmd)
}
