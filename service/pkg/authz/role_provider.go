package authz

import (
	"context"

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
