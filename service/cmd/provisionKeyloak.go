package cmd

import (
	"github.com/opentdf/platform/service/internal/config"
	"github.com/spf13/cobra"
)

const (
	provKcEndpoint = "endpoint"
	provKcUsername = "admin"
	provKcPassword = "password"
	provKcRealm    = "realm"
)

var (
	provisionKeycloakCmd = &cobra.Command{
		Use:   "keycloak",
		Short: "Run local provision of keycloak data",
		Long: `
 ** Local Development and Testing Only **
 This command will create the following Keyclaok resource:
 - Realm
 - Roles
 - Client
 - Users

 This command is intended for local development and testing purposes only.
 `,
		RunE: func(cmd *cobra.Command, args []string) error {
			kcEndpoint, _ := cmd.Flags().GetString(provKcEndpoint)
			realmName, _ := cmd.Flags().GetString(provKcRealm)
			kcUsername, _ := cmd.Flags().GetString(provKcUsername)
			kcPassword, _ := cmd.Flags().GetString(provKcPassword)
			configFile, _ := cmd.Flags().GetString(configFileFlag)
			configKey, _ := cmd.Flags().GetString(configKeyFlag)

			config, err := config.LoadConfig(configKey, configFile)
			if err != nil {
				return err
			}

			kcConnectParams := keycloakConnectParams{
				BasePath:         kcEndpoint,
				Username:         kcUsername,
				Password:         kcPassword,
				Realm:            realmName,
				Audience:         config.Server.Auth.Audience,
				AllowInsecureTLS: true,
			}

			return CreateStockKeycloakSetup(kcConnectParams)
		},
	}
)

func init() {
	provisionKeycloakCmd.Flags().StringP(provKcEndpoint, "e", "http://localhost:8888/auth", "Keycloak endpoint")
	provisionKeycloakCmd.Flags().StringP(provKcUsername, "u", "admin", "Keycloak username")
	provisionKeycloakCmd.Flags().StringP(provKcPassword, "p", "changeme", "Keycloak password")
	provisionKeycloakCmd.Flags().StringP(provKcRealm, "r", "opentdf", "OpenTDF Keycloak Realm name")

	provisionCmd.AddCommand(provisionKeycloakCmd)

	rootCmd.AddCommand(provisionKeycloakCmd)
}
