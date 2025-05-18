package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/oidcuserinfo"
	"github.com/opentdf/platform/service/pkg/util"

	_ "embed"
)

var (
	rolePrefix  = "role:"
	defaultRole = "unknown"
)

//go:embed casbin_policy.csv
var builtinPolicy string

//go:embed casbin_model.conf
var defaultModel string

type Enforcer struct {
	*casbin.Enforcer
	Config CasbinConfig
	Policy string
	logger *logger.Logger

	isDefaultPolicy bool
	isDefaultModel  bool

	// OIDC UserInfo cache
	oidc *oidcuserinfo.UserInfo
}

type casbinSubject []string

type CasbinConfig struct {
	PolicyConfig
	// OIDC UserInfo enrichment fields
	UserInfoEnrichment bool
	UserInfoEndpoint   string
	TokenEndpoint      string
	ClientID           string
	ClientSecret       string
}

type AuthToken struct {
	Token    jwt.Token
	RawToken string
}

// newCasbinEnforcer creates a new Casbin enforcer with the provided configuration and logger.
// It sets up the Casbin model, policy, and adapter, and returns an Enforcer instance.
func NewCasbinEnforcer(c CasbinConfig, logger *logger.Logger) (*Enforcer, error) {
	// Set Casbin config defaults if not provided
	isDefaultModel := false
	if c.Model == "" {
		c.Model = defaultModel
		isDefaultModel = true
	}

	isDefaultPolicy := false
	if c.Csv == "" {
		// Set the Bultin Policy if provided
		if c.Builtin != "" {
			c.Csv = c.Builtin
		} else {
			c.Csv = builtinPolicy
		}
		isDefaultPolicy = true
	}

	if c.RoleMap != nil {
		for k, v := range c.RoleMap {
			c.Csv = strings.Join([]string{
				c.Csv,
				strings.Join([]string{"g", v, "role:" + k}, ", "),
			}, "\n")
		}
	}

	isPolicyExtended := false
	if c.Extension != "" {
		c.Csv = strings.Join([]string{c.Csv, c.Extension}, "\n")
		isPolicyExtended = true
	}

	// Because we provided built in group mappings we need to add them
	// if extensions and rolemap are not provided
	if c.RoleMap == nil && c.Extension == "" {
		c.Csv = strings.Join([]string{
			c.Csv,
			"g, opentdf-admin, role:admin",
			"g, opentdf-standard, role:standard",
		}, "\n")
	}

	isDefaultAdapter := false
	// If adapter is not provided, use the default string adapter
	if c.Adapter == nil {
		isDefaultAdapter = true
		c.Adapter = stringadapter.NewAdapter(c.Csv)
	}

	logger.Debug("creating casbin enforcer",
		slog.Any("config", c),
		slog.Bool("isDefaultModel", isDefaultModel),
		slog.Bool("isBuiltinPolicy", isDefaultPolicy),
		slog.Bool("isPolicyExtended", isPolicyExtended),
		slog.Bool("isDefaultAdapter", isDefaultAdapter),
	)

	m, err := casbinModel.NewModelFromString(c.Model)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin model: %w", err)
	}

	e, err := casbin.NewEnforcer(m, c.Adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}

	return &Enforcer{
		Enforcer:        e,
		Config:          c,
		Policy:          c.Csv,
		isDefaultPolicy: isDefaultPolicy,
		isDefaultModel:  isDefaultModel,
		logger:          logger,
	}, nil
}

// Enforce checks if the given AuthToken is allowed to perform the specified action on the resource.
// It builds the subject from the token, checks all possible roles, and returns true if any are allowed.
// Returns an error if permission is denied or if an internal error occurs during enforcement.
func (e *Enforcer) Enforce(ctx context.Context, authToken AuthToken, resource, action string) (bool, error) {
	// extract the role claim from the token
	s := e.buildSubjectFromToken(ctx, authToken)
	s = append(s, rolePrefix+defaultRole)

	for _, info := range s {
		allowed, err := e.Enforcer.Enforce(info, resource, action)
		if err != nil {
			e.logger.Error("enforce by role error", slog.String("subject info", info), slog.String("resource", resource), slog.String("action", action), slog.String("error", err.Error()))
		}
		if allowed {
			e.logger.Debug("allowed by policy", slog.String("subject info", info), slog.String("resource", resource), slog.String("action", action))
			return true, nil
		}
	}
	e.logger.Debug("permission denied by policy", slog.Any("subject.info", s), slog.String("resource", resource), slog.String("action", action))
	return false, errors.New("permission denied")
}

// buildSubjectFromToken constructs the Casbin subject slice from the AuthToken.
// It extracts roles and the username claim, and returns them as a subject list for policy enforcement.
func (e *Enforcer) buildSubjectFromToken(ctx context.Context, authToken AuthToken) casbinSubject {
	var subject string
	info := casbinSubject{}

	e.logger.Debug("building subject from token", slog.Any("token", authToken.Token))
	roles := e.extractRolesFromToken(ctx, authToken)

	if claim, found := authToken.Token.Get(e.Config.UserNameClaim); found {
		sub, ok := claim.(string)
		subject = sub
		if !ok {
			e.logger.Warn("username claim not of type string", slog.String("claim", e.Config.UserNameClaim), slog.Any("claims", claim))
			subject = ""
		}
	}
	info = append(info, roles...)
	info = append(info, subject)
	return info
}

// extractRolesFromToken extracts the roles from the AuthToken based on the configured claim.
// If the claim is missing and UserInfo enrichment is enabled, it fetches roles from the OIDC UserInfo endpoint.
// Returns a slice of role strings, or nil if no roles are found.
func (e *Enforcer) extractRolesFromToken(ctx context.Context, authToken AuthToken) []string {
	e.logger.Debug("extracting roles from token", slog.Any("token", authToken.Token))
	roleClaim := e.Config.GroupsClaim
	selectors := strings.Split(roleClaim, ".")

	claim, exists := e.getClaimFromToken(authToken, selectors[0])
	if !exists && e.Config.UserInfoEnrichment {
		claim, exists = e.getClaimFromUserInfo(ctx, authToken, selectors[0])
	}
	if !exists {
		e.logger.Warn("claim not found", slog.String("claim", roleClaim), slog.Any("token", authToken.Token))
		return nil
	}

	claim = e.resolveNestedClaim(claim, selectors)
	if claim == nil {
		return nil
	}

	return e.parseRolesFromClaim(claim, roleClaim)
}

// getClaimFromToken tries to get the claim from the JWT token.
func (e *Enforcer) getClaimFromToken(authToken AuthToken, claimKey string) (interface{}, bool) {
	claim, exists := authToken.Token.Get(claimKey)
	return claim, exists
}

// getClaimFromUserInfo fetches the claim from the OIDC UserInfo endpoint if available.
func (e *Enforcer) getClaimFromUserInfo(ctx context.Context, authToken AuthToken, claimKey string) (interface{}, bool) {
	issuer := authToken.Token.Issuer()
	sub := authToken.Token.Subject()
	userinfo, err := e.oidc.FetchUserInfo(
		ctx,
		authToken.RawToken, // pass the raw access token
		issuer,
		sub,
		e.Config.UserInfoEndpoint,
		e.Config.TokenEndpoint,
		e.Config.ClientID,
		e.Config.ClientSecret,
	)
	if err == nil {
		if claimVal, ok := userinfo[claimKey]; ok {
			return claimVal, true
		}
	}
	return nil, false
}

// resolveNestedClaim resolves nested claims using dot notation if needed.
func (e *Enforcer) resolveNestedClaim(claim interface{}, selectors []string) interface{} {
	if len(selectors) > 1 {
		claimMap, ok := claim.(map[string]interface{})
		if !ok {
			e.logger.Warn("claim is not of type map[string]interface{}", slog.String("claim", strings.Join(selectors, ".")), slog.Any("claims", claim))
			return nil
		}
		claim = util.Dotnotation(claimMap, strings.Join(selectors[1:], "."))
		if claim == nil {
			e.logger.Warn("claim not found", slog.String("claim", strings.Join(selectors, ".")), slog.Any("claims", claim))
			return nil
		}
	}
	return claim
}

// parseRolesFromClaim parses the roles from the claim value.
func (e *Enforcer) parseRolesFromClaim(claim interface{}, roleClaim string) []string {
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
		e.logger.Warn("could not get claim type", slog.String("selector", roleClaim), slog.Any("claims", claim))
		return nil
	}
	return roles
}
