package auth

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/util"
)

var (
	rolePrefix            = "role:"
	defaultRole           = "unknown"
	defaultPolicyPartsLen = 5
)

var defaultPolicy = `
## Roles (prefixed with role:)
# admin - admin
# standard - standard
# unknown - unknown role or no role

## Resources
# Resources beginning with / are HTTP routes. Generally, this does not matter, but when HTTP routes don't map well
# with the protos this may become important.

## Actions
# read - read the resource
# write - write to the resource
# delete - delete the resource
# unsafe - unsafe actions

## Grouping Statements - Maps users/groups to roles
g, opentdf-admin, role:admin
g, opentdf-standard, role:standard

# Role: Admin
## gRPC and HTTP routes
p,	role:admin,		*,					*,			allow

## Role: Standard
## gRPC routes
p,	role:standard,		policy.*,																read,			allow
p,	role:standard,		kasregistry.*,													read,			allow
p,	role:standard,      kas.AccessService/Rewrap, 			           *,			allow
p,  role:standard,      authorization.AuthorizationService/GetDecisions,        read, allow
p,  role:standard,      authorization.AuthorizationService/GetDecisionsByToken, read, allow

## HTTP routes
p,	role:standard,		/attributes*,														read,			allow
p,	role:standard,		/namespaces*,														read,			allow
p,	role:standard,		/subject-mappings*,											read,			allow
p,	role:standard,		/resource-mappings*,										read,			allow
p,	role:standard,		/key-access-servers*,										read,			allow
p,	role:standard,		/kas/v2/rewrap,													write,		allow
p,  role:standard,      /v1/authorization,                                                              write,          allow
p,  role:standard,      /v1/token/authorization,                                                        write,          allow

# Public routes
## gRPC routes
## for ERS, right now we don't care about requester role, just that a valid jwt is provided when the OPA engine calls (enforced in the ERS itself, not casbin)
p,	role:unknown,     kas.AccessService/Rewrap, 			                                  *,	  allow
## HTTP routes
## for ERS, right now we don't care about requester role, just that a valid jwt is provided when the OPA engine calls (enforced in the ERS itself, not casbin)
p,	role:unknown,		  /kas/v2/rewrap,													  *,		allow
`

var defaultModel = `
[request_definition]
r = sub,	res,	act

[policy_definition]
p = sub,	res,	act,	eft

[role_definition]
g = _,	_

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = g(r.sub,	p.sub) && keyMatch(r.res,	p.res) && keyMatch(r.act,	p.act)
`

type Enforcer struct {
	*casbin.Enforcer
	Config CasbinConfig
	Policy string
	logger *logger.Logger

	isDefaultRoleClaim bool
	isDefaultRoleMap   bool
	isDefaultPolicy    bool
	isDefaultModel     bool
}

type casbinSubject []string

type CasbinConfig struct {
	PolicyConfig
}

// newCasbinEnforcer creates a new casbin enforcer
func NewCasbinEnforcer(c CasbinConfig, logger *logger.Logger) (*Enforcer, error) {
	// Set Casbin config defaults if not provided
	isDefaultModel := false
	if c.Model == "" {
		c.Model = defaultModel
		isDefaultModel = true
	}

	isDefaultPolicy := false
	if c.Csv == "" {
		// Set the Default Policy if provided
		if c.Default != "" {
			c.Csv = c.Default
		} else {
			c.Csv = defaultPolicy
		}
		isDefaultPolicy = true
	}

	if c.RoleMap != nil {
		for k, v := range c.RoleMap {
			c.Csv = strings.Join([]string{
				c.Csv,
				strings.Join([]string{"g", v, fmt.Sprintf("role:%s", k)}, ", "),
			}, "\n")
		}
	}

	if c.PolicyExtension != "" {
		c.Csv = strings.Join([]string{c.Csv, c.PolicyExtension}, "\n")
	}

	isDefaultAdapter := false
	if c.Adapter == nil {
		isDefaultAdapter = true
		// Set empty policy string so we can load the default policy
		// later if a different adapter is provided
		c.Adapter = stringadapter.NewAdapter(c.Csv)
	}

	logger.Debug("creating casbin enforcer",
		slog.Any("config", c),
		slog.Bool("isDefaultModel", isDefaultModel),
		slog.Bool("isDefaultPolicy", isDefaultPolicy),
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

// casbinEnforce is a helper function to enforce the policy with casbin
// TODO implement a common type so this can be used for both http and grpc
func (e *Enforcer) Enforce(token jwt.Token, resource, action string) (bool, error) {
	var err error
	permDeniedError := fmt.Errorf("permission denied")

	// extract the role claim from the token
	s := e.buildSubjectFromToken(token)

	if len(s) == 0 {
		sub := rolePrefix + defaultRole
		e.logger.Debug("enforcing policy", slog.Any("subject", sub), slog.String("resource", resource), slog.String("action", action))
		return e.Enforcer.Enforce(sub, resource, action)
	}

	allowed := false
	for _, info := range s {
		allowed, err = e.Enforcer.Enforce(info, resource, action)
		if err != nil {
			e.logger.Error("enforce by role error", slog.String("subject info", info), slog.String("resource", resource), slog.String("action", action), slog.String("error", err.Error()))
			continue
		}
		if allowed {
			e.logger.Debug("allowed by policy", slog.String("subject info", info), slog.String("resource", resource), slog.String("action", action))
			break
		}
	}
	if !allowed {
		e.logger.Debug("permission denied by policy", slog.Any("subject info", s), slog.String("resource", resource), slog.String("action", action))
		return false, permDeniedError
	}

	return true, nil
}

func (e *Enforcer) buildSubjectFromToken(t jwt.Token) casbinSubject {
	var subject string
	info := casbinSubject{}

	e.logger.Debug("building subject from token", slog.Any("token", t))
	roles := e.extractRolesFromToken(t)

	if claim, found := t.Get(e.Config.UserNameClaim); found {
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

func (e *Enforcer) extractRolesFromToken(t jwt.Token) []string {
	e.logger.Debug("extracting roles from token", slog.Any("token", t))
	roles := []string{}

	roleClaim := e.Config.GroupsClaim
	// roleMap := e.Config.RoleMap

	selectors := strings.Split(roleClaim, ".")
	claim, exists := t.Get(selectors[0])
	if !exists {
		e.logger.Warn("claim not found", slog.String("claim", roleClaim), slog.Any("token", t))
		return nil
	}
	e.logger.Debug("root claim found", slog.String("claim", roleClaim), slog.Any("claims", claim))
	// use dotnotation if the claim is nested
	if len(selectors) > 1 {
		claimMap, ok := claim.(map[string]interface{})
		if !ok {
			e.logger.Warn("claim is not of type map[string]interface{}", slog.String("claim", roleClaim), slog.Any("claims", claim))
			return nil
		}
		claim = util.Dotnotation(claimMap, strings.Join(selectors[1:], "."))
		if claim == nil {
			e.logger.Warn("claim not found", slog.String("claim", roleClaim), slog.Any("claims", claim))
			return nil
		}
	}

	// check the type of the role claim
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
