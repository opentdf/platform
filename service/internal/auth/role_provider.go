package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

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

	selectors := strings.Split(p.groupsClaim, ".")
	claim, exists := token.Get(selectors[0])
	if !exists {
		p.logger.Warn("claim not found",
			slog.String("claim", p.groupsClaim),
			slog.Any("claims", claim),
		)
		return nil, nil
	}
	p.logger.Debug("root claim found",
		slog.String("claim", p.groupsClaim),
		slog.Any("claims", claim),
	)

	if len(selectors) > 1 {
		claimMap, ok := claim.(map[string]interface{})
		if !ok {
			p.logger.Warn("claim is not of type map[string]interface{}",
				slog.String("claim", p.groupsClaim),
				slog.Any("claims", claim),
			)
			return nil, nil
		}
		claim = dotNotation(claimMap, strings.Join(selectors[1:], "."))
		if claim == nil {
			p.logger.Warn("claim not found",
				slog.String("claim", p.groupsClaim),
				slog.Any("claims", claim),
			)
			return nil, nil
		}
	}

	roles := []string{}
	switch v := claim.(type) {
	case string:
		roles = append(roles, v)
	case []interface{}:
		for _, rr := range v {
			if r, ok := rr.(string); ok {
				roles = append(roles, r)
			}
		}
	default:
		p.logger.Warn("could not get claim type",
			slog.String("selector", p.groupsClaim),
			slog.Any("claims", claim),
		)
		return nil, nil
	}

	return roles, nil
}

func resolveRoleProvider(ctx context.Context, cfg Config, logger *logger.Logger) (authz.RoleProvider, error) {
	if cfg.Policy.RolesProvider != "" {
		if cfg.RoleProvider != nil && cfg.RoleProviderFactories != nil {
			logger.Warn(
				"role provider configured in start options is ignored because roles_provider is set",
				slog.String("roles_provider", cfg.Policy.RolesProvider),
			)
		}
		if cfg.RoleProviderFactories == nil {
			return nil, fmt.Errorf("role provider not registered: %s", cfg.Policy.RolesProvider)
		}
		factory, ok := cfg.RoleProviderFactories[cfg.Policy.RolesProvider]
		if !ok {
			return nil, fmt.Errorf("role provider not registered: %s", cfg.Policy.RolesProvider)
		}
		provider, err := factory(ctx)
		if err != nil {
			return nil, fmt.Errorf("role provider factory failed: %w", err)
		}
		return provider, nil
	}
	if cfg.RoleProvider != nil {
		return cfg.RoleProvider, nil
	}
	return nil, nil
}
