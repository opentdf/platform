package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"
)

type jwtClaimsRoleProvider struct {
	groupsClaim string
	logger      *logger.Logger
}

func newJWTClaimsRoleProvider(groupsClaim string, logger *logger.Logger) authz.RoleProvider {
	return &jwtClaimsRoleProvider{
		groupsClaim: groupsClaim,
		logger:      logger,
	}
}

func (p *jwtClaimsRoleProvider) Roles(_ context.Context, token jwt.Token, _ authz.RoleRequest) ([]string, error) {
	p.logger.Debug("extracting roles from token")
	if p.groupsClaim == "" {
		p.logger.Warn("groups claim not configured")
		return nil, nil
	}

	return authz.RolesFromTokenClaim(token, p.groupsClaim), nil
}

func resolveRoleProvider(ctx context.Context, cfg Config, logger *logger.Logger) (authz.RoleProvider, error) {
	if cfg.Policy.RolesProvider.Name != "" {
		if cfg.RoleProvider != nil && cfg.RoleProviderFactories != nil {
			logger.Warn(
				"role provider configured in start options is ignored because roles_provider is set",
				slog.String("roles_provider", cfg.Policy.RolesProvider.Name),
			)
		}
		if cfg.RoleProviderFactories == nil {
			return nil, fmt.Errorf("no role provider factories are registered, cannot create provider %q", cfg.Policy.RolesProvider.Name)
		}
		factory, ok := cfg.RoleProviderFactories[cfg.Policy.RolesProvider.Name]
		if !ok {
			return nil, fmt.Errorf("role provider factory not registered: %s", cfg.Policy.RolesProvider.Name)
		}
		providerCfg := authz.ProviderConfig{
			Config:        cfg.Policy.RolesProvider.Config,
			UsernameClaim: cfg.Policy.UserNameClaim,
			GroupsClaim:   cfg.Policy.GroupsClaim,
			ClientIDClaim: cfg.Policy.ClientIDClaim,
		}
		provider, err := factory(ctx, providerCfg)
		if err != nil {
			return nil, fmt.Errorf("role provider factory failed: %w", err)
		}
		return provider, nil
	}
	if cfg.RoleProvider != nil {
		return cfg.RoleProvider, nil
	}
	return newJWTClaimsRoleProvider(cfg.Policy.GroupsClaim, logger), nil
}
