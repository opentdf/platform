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

const (
	provKcEndpointFlag = "endpoint"
	provKcUsernameFlag = "username"
	provKcPasswordFlag = "password"
	provKcRealmFlag    = "realm"
	provKcFilenameFlag = "file"
	provKcInsecure     = "insecure"
)

var (
	provKeycloakFilename = "./service/cmd/keycloak_data.yaml"
	keycloakData         fixtures.KeycloakData
)

var provisionKeycloakCmd = &cobra.Command{
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
		kcUsername, _ := cmd.Flags().GetString(provKcUsernameFlag)
		kcPassword, _ := cmd.Flags().GetString(provKcPasswordFlag)
		keycloakFilename, _ := cmd.Flags().GetString(provKcFilenameFlag)

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

var provisionKeycloakFromConfigCmd = &cobra.Command{
	Use: "keycloak-from-config",
	RunE: func(_ *cobra.Command, _ []string) error {
		slog.Info("Command keycloak-from-config has been deprecated. Please use command 'keycloak' instead.")
		return nil
	},
}

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
	yamlData := make(map[interface{}]interface{})

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

	if err := json.Unmarshal(kcData, &keycloakData); err != nil {
		slog.Error("could not unmarshal json into data object", slog.String("error", err.Error()))
		panic(err)
	}
}

func init() {
	provisionKeycloakCmd.Flags().StringP(provKcEndpointFlag, "e", "http://localhost:8888/auth", "Keycloak endpoint")
	provisionKeycloakCmd.Flags().StringP(provKcUsernameFlag, "u", "admin", "Keycloak username")
	provisionKeycloakCmd.Flags().StringP(provKcPasswordFlag, "p", "changeme", "Keycloak password")
	provisionKeycloakCmd.Flags().StringP(provKcFilenameFlag, "f", provKeycloakFilename, "Keycloak config file")

	provisionCmd.AddCommand(provisionKeycloakCmd)

	// Deprecated command
	provisionCmd.AddCommand(provisionKeycloakFromConfigCmd)
}
