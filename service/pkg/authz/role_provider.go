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
type RoleProviderFactory func(ctx context.Context) (RoleProvider, error)

// RoleRequest provides request context to role providers.
type RoleRequest struct {
	Issuer   string
	Resource string
	Action   string
}
