package util

import (
	"encoding/json"
	"testing"
)

type DBConfig struct {
	Host             string `json:"host"`
	Port             int    `json:"port"`
	Database         string `json:"database"`
	User             string `json:"user"`
	Password         string `json:"password" secret:"true"`
	RunMigrations    bool   `json:"runMigrations"`
	SSLMode          string `json:"sslmode"`
	Schema           string `json:"schema"`
	VerifyConnection bool   `json:"verifyConnection"`
}

type Config struct {
	DevMode  bool     `json:"devMode"`
	DB       DBConfig `json:"db"`
	Services map[string]struct {
		Enabled bool `json:"enabled"`
		Remote  struct {
			Endpoint string `json:"endpoint"`
		} `json:"remote"`
		ExtraProps map[string]interface{} `json:"extraProps"`
	} `json:"services"`
}

func TestRedactSensitiveData_WithSensitiveFieldsInNestedStruct(t *testing.T) {
	rawConfig := `{
		"DevMode": false,
		"DB": {
			"Host": "localhost",
			"Port": 5432,
			"Database": "opentdf",
			"User": "postgres",
			"Password": "changeme",
			"RunMigrations": true,
			"SSLMode": "prefer",
			"Schema": "opentdf",
			"VerifyConnection": true
		},
		"Services": {
			"authorization": {
				"Enabled": true,
				"Remote": {
					"Endpoint": ""
				},
				"ExtraProps": {
					"clientid": "tdf-authorization-svc",
					"clientsecret": "secret",
					"ersurl": "http://localhost:8080/entityresolution/resolve",
					"tokenendpoint": "http://localhost:8888/auth/realms/opentdf/protocol/openid-connect/token"
				}
			},
			"entityresolution": {
				"Enabled": true,
				"Remote": {
					"Endpoint": ""
				},
				"ExtraProps": {
					"clientid": "tdf-entity-resolution",
					"clientsecret": "secret",
					"legacykeycloak": true,
					"realm": "opentdf",
					"url": "http://localhost:8888/auth"
				}
			},
			"health": {
				"Enabled": true,
				"Remote": {
					"Endpoint": ""
				},
				"ExtraProps": {}
			},
			"kas": {
				"Enabled": true,
				"Remote": {
					"Endpoint": ""
				},
				"ExtraProps": {
					"keyring": [
						{"alg": "ec:secp256r1", "kid": "e1"},
						{"alg": "ec:secp256r1", "kid": "e1", "legacy": true},
						{"alg": "rsa:2048", "kid": "r1"},
						{"alg": "rsa:2048", "kid": "r1", "legacy": true}
					]
				}
			},
			"policy": {
				"Enabled": true,
				"Remote": {
					"Endpoint": ""
				},
				"ExtraProps": {}
			},
			"wellknown": {
				"Enabled": true,
				"Remote": {
					"Endpoint": ""
				},
				"ExtraProps": {}
			}
		}
	}`

	var config Config
	err := json.Unmarshal([]byte(rawConfig), &config)
	if err != nil {
		t.Fatalf("Failed to unmarshal rawConfig: %v", err)
	}

	redacted := RedactSensitiveData(config)

	redactedConfig, ok1 := redacted.(Config)
	if !ok1 {
		t.Fatalf("Expected redacted data to be of type Config")
	}

	if redactedConfig.DB.Password != "***" {
		t.Errorf("Expected DB.Password to be redacted")
	}
}
