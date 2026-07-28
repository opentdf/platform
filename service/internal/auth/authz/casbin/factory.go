// Package casbin registers the Casbin authorization engine and dispatches to
// the configured versioned implementation.
package casbin

import (
	"errors"
	"fmt"

	"github.com/opentdf/platform/service/internal/auth/authz"
	casbinv1 "github.com/opentdf/platform/service/internal/auth/authz/casbin/v1"
	casbinv2 "github.com/opentdf/platform/service/internal/auth/authz/casbin/v2"
	"github.com/opentdf/platform/service/logger"
)

func init() {
	authz.RegisterFactory("casbin", NewAuthorizer)
}

// NewAuthorizer creates a Casbin authorizer based on configuration.
func NewAuthorizer(cfg authz.Config) (authz.Authorizer, error) {
	log, ok := cfg.Logger.(*logger.Logger)
	if !ok || log == nil {
		return nil, errors.New("logger is required for CasbinAuthorizer")
	}

	adapterCfg := authz.AdapterConfigFromExternal(cfg)
	switch typedCfg := adapterCfg.(type) {
	case authz.CasbinV1Config:
		return casbinv1.NewAuthorizer(typedCfg, log)
	case authz.CasbinV2Config:
		return casbinv2.NewAuthorizer(typedCfg, log)
	default:
		return nil, fmt.Errorf("unsupported adapter config type: %T", adapterCfg)
	}
}
