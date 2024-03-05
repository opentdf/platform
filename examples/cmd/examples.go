package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type configKey string

const RootConfigKey configKey = "example-config"

type ExampleConfig struct {
	PlatformEndpoint string
}

var ExamplesCmd = &cobra.Command{
	Use: "examples",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		platformEndpoint, err := cmd.Parent().PersistentFlags().GetString("platformEndpoint")
		if err != nil {
			return err
		}
		config := &ExampleConfig{
			PlatformEndpoint: platformEndpoint,
		}
		ctx := context.WithValue(cmd.Context(), RootConfigKey, config)
		cmd.SetContext(ctx)
		return nil
	},
}

func init() {
	ExamplesCmd.PersistentFlags().StringP("platformEndpoint", "e", "localhost:9000", "Platform Endpoint")
}

func Execute() {
	if err := ExamplesCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
