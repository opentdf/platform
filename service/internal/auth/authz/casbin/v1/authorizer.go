// Package v1 provides the legacy path-based Casbin authorization implementation.
package v1

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
)

// Authorizer implements legacy path-based authorization.
type Authorizer struct {
	issuer   string
	enforcer *Enforcer
	logger   *logger.Logger
}

// NewAuthorizer creates a v1 path-based Casbin authorizer.
func NewAuthorizer(cfg authz.CasbinV1Config, log *logger.Logger) (*Authorizer, error) {
	enforcer, err := newCasbinEnforcer(casbinConfig{
		PolicyConfig: cfg.PolicyConfig,
		Adapter:      cfg.Adapter,
		RoleProvider: cfg.RoleProvider,
	}, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create v1 casbin enforcer: %w", err)
	}

	authorizer := &Authorizer{
		issuer:   cfg.Issuer,
		enforcer: enforcer,
		logger:   log,
	}

	log.Info(
		"casbin authorizer initialized",
		slog.String("version", authorizer.Version()),
		slog.Bool("supportsResourceAuth", authorizer.SupportsResourceAuthorization()),
	)

	return authorizer, nil
}

// Authorize implements authz.Authorizer.Authorize.
func (a *Authorizer) Authorize(ctx context.Context, req *authz.Request) (*authz.Decision, error) {
	if req == nil {
		return nil, errors.New("authorization request is required")
	}
	if req.Token == nil {
		return nil, errors.New("authorization token is required")
	}

	return a.authorize(ctx, req)
}

// Version implements authz.Authorizer.Version.
func (a *Authorizer) Version() string {
	return string(authz.ModeV1)
}

// SupportsResourceAuthorization implements authz.Authorizer.SupportsResourceAuthorization.
func (a *Authorizer) SupportsResourceAuthorization() bool {
	return false
}

// authorize performs legacy path-based authorization.
//
// Path handling heuristic for v1 policy compatibility:
// The v1 Casbin policy file (casbin_policy.csv) uses two different path formats:
//   - gRPC paths WITHOUT leading slash: kas.AccessService/Rewrap, policy.*, authorization.AuthorizationService/GetDecisions
//   - HTTP paths WITH leading slash: /kas/v2/rewrap, /attributes*, /namespaces*
//
// ConnectRPC always provides paths with a leading slash (e.g., /kas.AccessService/Rewrap).
// We distinguish gRPC from HTTP paths using a simple heuristic: gRPC service names contain "."
// (e.g., "kas.AccessService"), while HTTP paths do not (e.g., "/kas/v2/rewrap").
//
// This preserves full backwards compatibility with the existing v1 policy format.
func (a *Authorizer) authorize(ctx context.Context, req *authz.Request) (*authz.Decision, error) {
	resource := req.RPC
	if strings.Contains(req.RPC, ".") {
		// gRPC-style path (contains '.'): strip leading slash for v1 policy compatibility
		// Example: /kas.AccessService/Rewrap -> kas.AccessService/Rewrap
		resource = strings.TrimPrefix(req.RPC, "/")
	}
	// HTTP paths (no '.') keep their leading slash
	// Example: /kas/v2/rewrap -> /kas/v2/rewrap

	result, err := a.enforcer.enforce(ctx, req.Token, platformauthz.RoleRequest{
		Issuer:   a.issuer,
		Resource: resource,
		Action:   req.Action,
	})
	if err != nil {
		return nil, fmt.Errorf("v1 authorization system error: %w", err)
	}

	reason := fmt.Sprintf("v1: %s %s", req.Action, resource)
	if !result.Allowed {
		reason = fmt.Sprintf("v1: denied %s %s", req.Action, resource)
	}

	return &authz.Decision{
		Allowed: result.Allowed,
		Reason:  reason,
		Mode:    authz.ModeV1,
		Metadata: authz.DecisionMetadata{
			GroupsClaim: result.GroupsClaim,
		},
	}, nil
}
