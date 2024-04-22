package cmd

import (
	"context"

	"github.com/opentdf/platform/lib/fixtures"
	"github.com/opentdf/platform/service/internal/config"
	"github.com/spf13/cobra"
)

const (
	provKcEndpointFlag = "endpoint"
	provKcUsernameFlag = "username"
	provKcPasswordFlag = "password"
	provKcRealmFlag    = "realm"
	provKcInsecure     = "insecure"
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			kcEndpoint, _ := cmd.Flags().GetString(provKcEndpointFlag)
			realmName, _ := cmd.Flags().GetString(provKcRealmFlag)
			kcUsername, _ := cmd.Flags().GetString(provKcUsernameFlag)
			kcPassword, _ := cmd.Flags().GetString(provKcPasswordFlag)
			configFile, _ := cmd.Flags().GetString(configFileFlag)
			configKey, _ := cmd.Flags().GetString(configKeyFlag)
			insecure, _ := cmd.Flags().GetBool(provKcInsecure)

			config, err := config.LoadConfig(configKey, configFile)
			if err != nil {
				return err
			}

			kcConnectParams := fixtures.KeycloakConnectParams{
				BasePath:         kcEndpoint,
				Username:         kcUsername,
				Password:         kcPassword,
				Realm:            realmName,
				Audience:         config.Server.Auth.Audience,
				AllowInsecureTLS: insecure,
			}

			return fixtures.SetupKeycloak(context.Background(), kcConnectParams)
		},
	}
)

func init() {
	provisionKeycloakCmd.Flags().StringP(provKcEndpointFlag, "e", "http://localhost:8888/auth", "Keycloak endpoint")
	provisionKeycloakCmd.Flags().StringP(provKcUsernameFlag, "u", "admin", "Keycloak username")
	provisionKeycloakCmd.Flags().StringP(provKcPasswordFlag, "p", "changeme", "Keycloak password")
	provisionKeycloakCmd.Flags().StringP(provKcRealmFlag, "r", "opentdf", "OpenTDF Keycloak Realm name")
	provisionKeycloakCmd.Flags().BoolP(provKcInsecure, "", false, "Ignore tls verification when connecting to keycloak. --insecure to disable.")

	provisionCmd.AddCommand(provisionKeycloakCmd)

	rootCmd.AddCommand(provisionKeycloakCmd)
}
