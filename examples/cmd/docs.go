package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var GenDocsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Generates docs for the example commands",
	RunE: func(_ *cobra.Command, _ []string) error {
		err := doc.GenMarkdownTree(ExamplesCmd, "./docs")
		return err
	},
}

func init() {
	ExamplesCmd.AddCommand(GenDocsCmd)
}
