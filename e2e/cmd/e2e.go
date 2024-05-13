package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type configKey string

const RootConfigKey configKey = "test-config"

type TestConfig struct {
	PlatformEndpoint string
	TokenEndpoint    string
	ClientID         string
	ClientSecret     string
}

var E2ECmd = &cobra.Command{
	Use: "e2e",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		platformEndpoint, err := cmd.Parent().PersistentFlags().GetString("platformEndpoint")
		if err != nil {
			return err
		}
		tokenEndpoint, err := cmd.Parent().PersistentFlags().GetString("tokenEndpoint")
		if err != nil {
			return err
		}
		clientID, err := cmd.Parent().PersistentFlags().GetString("clientId")
		if err != nil {
			return err
		}
		clientSecret, err := cmd.Parent().PersistentFlags().GetString("clientSecret")
		if err != nil {
			return err
		}
		config := &TestConfig{
			PlatformEndpoint: platformEndpoint,
			ClientID:         clientID,
			ClientSecret:     clientSecret,
			TokenEndpoint:    tokenEndpoint,
		}
		ctx := context.WithValue(cmd.Context(), RootConfigKey, config)
		cmd.SetContext(ctx)
		return nil
	},
}

func init() {
	E2ECmd.PersistentFlags().StringP("platformEndpoint", "e", "localhost:8080", "Platform Endpoint")
	E2ECmd.PersistentFlags().StringP("tokenEndpoint", "t", "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token", "Token Endpoint")
	E2ECmd.PersistentFlags().StringP("clientId", "c", "opentdf-sdk", "Client to use in tests")
	E2ECmd.PersistentFlags().StringP("clientSecret", "s", "secret", "Secret for client to use in tests")
}

func Execute() {
	if err := E2ECmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
