package providers

import (
	"github.com/opentdf/opentdf-v2-poc/pkg/entitlements/providers/keycloak"
	"github.com/opentdf/opentdf-v2-poc/pkg/entitlements/providers/ldap"
	"golang.org/x/exp/slog"
)

type Config struct {
	Type     string          `yaml:"type"`
	Name     string          `yaml:"name"`
	Ldap     ldap.Config     `yaml:"ldap,omitempty"`
	KeyCloak keycloak.Config `yaml:"keycloak,omitempty"`
}

type Provider interface {
	GetAttributes(string) (map[string]string, error)
	GetType() string
}

func BuildProviders(configs []Config) ([]Provider, error) {
	var (
		providers = make([]Provider, len(configs))
		err       error
	)
	for i, config := range configs {
		switch config.Type {
		case "ldap":
			slog.Info("building ldap provider", slog.String("name", config.Name))
			providers[i], err = ldap.NewLDAP(config.Ldap)
			if err != nil {
				slog.Error("error building ldap provider", slog.String("error", err.Error()))
				continue
			}
		case "keycloak":
			slog.Info("building keycloak provider", slog.String("name", config.Name))
			providers[i], err = keycloak.NewKeycloak(config.KeyCloak)
			if err != nil {
				slog.Error("error building keycloak provider", slog.String("error", err.Error()))
				continue
			}
		default:
			slog.Error("provider not found", slog.Any("type", config.Type), slog.Any("name", config.Name))
			continue
		}
	}
	return providers, nil
}
