package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/opentdf/platform/lib/fixtures"
	"gopkg.in/yaml.v2"
)

func main() {
	endpoint := flag.String("endpoint", "http://localhost:8888/auth", "Keycloak endpoint")
	username := flag.String("username", "admin", "Keycloak username")
	password := flag.String("password", "changeme", "Keycloak password")
	filename := flag.String("file", "../../service/cmd/keycloak_data.yaml", "Keycloak config file")
	flag.Parse()

	keycloakData := loadKeycloakData(*filename)
	ctx := context.Background()

	kcParams := fixtures.KeycloakConnectParams{
		BasePath:         *endpoint,
		Username:         *username,
		Password:         *password,
		Realm:            "",
		AllowInsecureTLS: true,
	}

	if err := fixtures.SetupCustomKeycloak(ctx, kcParams, keycloakData); err != nil {
		fmt.Fprintf(os.Stderr, "error provisioning keycloak: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("keycloak provision fully applied")
}

func convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			sk, ok := k.(string)
			if !ok {
				panic(fmt.Errorf("key is not a string: %v", k))
			}
			m2[sk] = convert(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return i
}

func loadKeycloakData(file string) fixtures.KeycloakData {
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
	var keycloakData fixtures.KeycloakData
	if err := json.Unmarshal(kcData, &keycloakData); err != nil {
		slog.Error("could not unmarshal json into data object", slog.String("error", err.Error()))
		panic(err)
	}
	return keycloakData
}
