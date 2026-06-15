package authz

import (
	"context"
	"log/slog"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
	"github.com/opentdf/platform/service/pkg/util"
)

// JWTClaimsRoleProvider extracts role/group values from a configured JWT claim.
type JWTClaimsRoleProvider struct {
	groupsClaim string
	logger      *logger.Logger
}

// NewJWTClaimsRoleProvider constructs the default JWT claims role provider.
func NewJWTClaimsRoleProvider(groupsClaim string, logger *logger.Logger) platformauthz.RoleProvider {
	return &JWTClaimsRoleProvider{
		groupsClaim: groupsClaim,
		logger:      logger,
	}
}

func (p *JWTClaimsRoleProvider) Roles(_ context.Context, token jwt.Token, _ platformauthz.RoleRequest) ([]string, error) {
	if p.logger != nil {
		p.logger.Debug("extracting roles from token")
	}
	if token == nil {
		return nil, nil
	}
	if p.groupsClaim == "" {
		if p.logger != nil {
			p.logger.Warn("groups claim not configured")
		}
		return nil, nil
	}

	selectors := strings.Split(p.groupsClaim, ".")
	claim, exists := token.Get(selectors[0])
	if !exists {
		if p.logger != nil {
			p.logger.Warn(
				"claim not found",
				slog.String("claim", p.groupsClaim),
				slog.Any("claims", claim),
			)
		}
		return nil, nil
	}
	if p.logger != nil {
		p.logger.Debug(
			"root claim found",
			slog.String("claim", p.groupsClaim),
			slog.Any("claims", claim),
		)
	}

	if len(selectors) > 1 {
		claim = p.nestedClaim(claim, selectors[1:])
		if claim == nil {
			return nil, nil
		}
	}

	roles := []string{}
	switch v := claim.(type) {
	case string:
		roles = append(roles, v)
	case []string:
		roles = append(roles, v...)
	case []interface{}:
		for _, rr := range v {
			if r, ok := rr.(string); ok {
				roles = append(roles, r)
			}
		}
	default:
		if p.logger != nil {
			p.logger.Warn(
				"could not get claim type",
				slog.String("selector", p.groupsClaim),
				slog.Any("claims", claim),
			)
		}
		return nil, nil
	}

	return roles, nil
}

func (p *JWTClaimsRoleProvider) nestedClaim(claim any, selectors []string) any {
	claimMap, ok := claim.(map[string]interface{})
	if !ok {
		if p.logger != nil {
			p.logger.Warn(
				"claim is not of type map[string]interface{}",
				slog.String("claim", p.groupsClaim),
				slog.Any("claims", claim),
			)
		}
		return nil
	}

	nested := util.Dotnotation(claimMap, strings.Join(selectors, "."))
	if nested == nil && p.logger != nil {
		p.logger.Warn(
			"claim not found",
			slog.String("claim", p.groupsClaim),
			slog.Any("claims", nested),
		)
	}
	return nested
}
