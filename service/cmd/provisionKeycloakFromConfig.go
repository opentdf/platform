package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/opentdf/platform/lib/fixtures"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	provKeycloakFilename = "./cmd/keycloak_data.yaml"
	keycloakData         fixtures.KeycloakData
)

var (
	provisionKeycloakFromConfigCmd = &cobra.Command{
		Use:   "keycloak-from-config",
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
			kcUsername, _ := cmd.Flags().GetString(provKcUsernameFlag)
			kcPassword, _ := cmd.Flags().GetString(provKcPasswordFlag)
			keycloakFilename, _ := cmd.Flags().GetString(provKeycloakFilename)

			// config, err := config.LoadConfig("")
			LoadKeycloakData(keycloakFilename)
			ctx := context.Background()

			kcParams := fixtures.KeycloakConnectParams{
				BasePath:         kcEndpoint,
				Username:         kcUsername,
				Password:         kcPassword,
				Realm:            "",
				AllowInsecureTLS: true,
			}

			err := fixtures.SetupCustomKeycloak(ctx, kcParams, keycloakData)
			if err != nil {
				return err
			}

			return nil
		},
	}
)

func convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k.(string)] = convert(v) //nolint:forcetypeassert // allow type assert
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return i
}

func LoadKeycloakData(file string) {
	var yamlData = make(map[interface{}]interface{})

	f, err := os.Open(file)
	if err != nil {
		panic(fmt.Errorf("error when opening YAML file: %s", err.Error()))
	}

	fileData, err := io.ReadAll(f)
	if err != nil {
		panic(fmt.Errorf("error reading YAML file: %s", err.Error()))
	}

	err = yaml.Unmarshal(fileData, &yamlData)
	if err != nil {
		panic(fmt.Errorf("error unmarshaling yaml file %s", err.Error()))
	}

	cleanedYaml := convert(yamlData)

	kcData, err := json.Marshal(cleanedYaml)
	if err != nil {
		panic(fmt.Errorf("error converting yaml to json: %s", err.Error()))
	}
	// slog.Info("", slog.Any("kcData", kcData))

	if err := json.Unmarshal(kcData, &keycloakData); err != nil {
		slog.Error("could not unmarshal json into data object", slog.String("error", err.Error()))
		panic(err)
	}

	// slog.Info("Fully loaded keycloak data", slog.Any("keycloakData", keycloakData))
	// panic("hi")
}

func init() {
	provisionKeycloakFromConfigCmd.Flags().StringP(provKcEndpointFlag, "e", "http://localhost:8888/auth", "Keycloak endpoint")
	provisionKeycloakFromConfigCmd.Flags().StringP(provKcUsernameFlag, "u", "admin", "Keycloak username")
	provisionKeycloakFromConfigCmd.Flags().StringP(provKcPasswordFlag, "p", "changeme", "Keycloak password")
	provisionKeycloakFromConfigCmd.Flags().StringP(provKeycloakFilename, "f", "./cmd/keycloak_data.yaml", "Keycloak config file")
	// provisionKeycloakFromConfigCmd.Flags().StringP(provKcRealm, "r", "opentdf", "OpenTDF Keycloak Realm name")

	provisionCmd.AddCommand(provisionKeycloakFromConfigCmd)

	rootCmd.AddCommand(provisionKeycloakFromConfigCmd)
}
