package authz

import (
	"context"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// RoleProvider returns role/group identifiers used as Casbin subjects.
type RoleProvider interface {
	Roles(ctx context.Context, token jwt.Token, req RoleRequest) ([]string, error)
}

// RoleProviderFactory constructs a RoleProvider at startup.
type RoleProviderFactory func(ctx context.Context, cfg ProviderConfig) (RoleProvider, error)

// ProviderConfig carries provider-specific configuration and claim selectors.
type ProviderConfig struct {
	Config        map[string]any
	UsernameClaim string
	GroupsClaim   string
	ClientIDClaim string
}

// RoleRequest provides request context to role providers.
type RoleRequest struct {
	Issuer   string
	Resource string
	Action   string
}

// RolesFromTokenClaim extracts role values from a JWT claim selector.
//
// The selector uses the same dot notation as the built-in Casbin groups_claim
// configuration. Missing claims, non-map intermediate values, and unsupported
// claim value types return nil.
func RolesFromTokenClaim(token jwt.Token, groupsClaim string) []string {
	if token == nil || groupsClaim == "" {
		return nil
	}

	selectors := strings.Split(groupsClaim, ".")
	claim, exists := token.Get(selectors[0])
	if !exists {
		return nil
	}

	if len(selectors) > 1 {
		claimMap, ok := claim.(map[string]any)
		if !ok {
			return nil
		}
		claim = dotNotation(claimMap, strings.Join(selectors[1:], "."))
		if claim == nil {
			return nil
		}
	}

	roles := []string{}
	switch v := claim.(type) {
	case string:
		roles = append(roles, v)
	case []any:
		for _, rr := range v {
			if r, ok := rr.(string); ok {
				roles = append(roles, r)
			}
		}
	case []string:
		roles = append(roles, v...)
	default:
		return nil
	}

	return roles
}

func dotNotation(m map[string]any, key string) any {
	keys := strings.Split(key, ".")
	for i, k := range keys {
		if i == len(keys)-1 {
			return m[k]
		}
		if m[k] == nil {
			return nil
		}
		var ok bool
		m, ok = m[k].(map[string]any)
		if !ok {
			return nil
		}
	}
	return nil
}
