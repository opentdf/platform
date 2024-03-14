package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals // rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "opentdf",
	Short: "A platform for trusted data",
	Long: `Start, manage, and control an OpenTDF platform.

The OpenTDF Platform provides services to support Attribute Based Access Control
of TDF protected data files. This includes storing attribute policy information,
user authorization, and performing access checks. Use this tool to start, stop,
manage, configure, or upgrade one or more of the OpenTDF Platform services.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		slog.Error("issue starting opentdf", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
