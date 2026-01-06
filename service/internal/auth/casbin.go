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

// Enforcer is the Casbin enforcer with platform-specific configuration
type Enforcer struct {
	*casbin.Enforcer
	Config CasbinConfig
	Policy string
	logger *logger.Logger

	isDefaultPolicy bool
	isDefaultModel  bool
}

type casbinSubject []string

type CasbinConfig struct {
	PolicyConfig
}

// NewCasbinEnforcer creates a new casbin enforcer
func NewCasbinEnforcer(c CasbinConfig, logger *logger.Logger) (*Enforcer, error) {
	// Set Casbin config defaults if not provided
	isDefaultModel := false
	if c.Model == "" {
		c.Model = defaultModel
		isDefaultModel = true
	}

	isDefaultPolicy := false
	if c.Csv == "" {
		// Set the Builtin Policy if provided
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

// Enforce checks if the token is allowed to perform the action on the resource.
// The userInfo parameter is accepted for interface compatibility but not used in v1.
// This method implements authz.V1Enforcer interface.
func (e *Enforcer) Enforce(token jwt.Token, _ []byte, resource, action string) bool {
	// extract the role claim from the token
	s := e.buildSubjectFromToken(token)
	s = append(s, rolePrefix+defaultRole)

	for _, info := range s {
		allowed, err := e.Enforcer.Enforce(info, resource, action)
		if err != nil {
			e.logger.Error("enforce by role error",
				slog.String("subject info", info),
				slog.String("resource", resource),
				slog.String("action", action),
				slog.String("error", err.Error()),
			)
		}
		if allowed {
			e.logger.Debug("allowed by policy",
				slog.String("subject info", info),
				slog.String("resource", resource),
				slog.String("action", action),
			)
			return true
		}
	}
	e.logger.Debug("permission denied by policy",
		slog.Any("subject.info", s),
		slog.String("resource", resource),
		slog.String("action", action),
	)
	return false
}

// BuildSubjectFromTokenAndUserInfo builds the subject info from the token.
// The userInfo parameter is accepted for interface compatibility but not used in v1.
// This method implements authz.V1Enforcer interface.
func (e *Enforcer) BuildSubjectFromTokenAndUserInfo(token jwt.Token, _ []byte) []string {
	return e.buildSubjectFromToken(token)
}

// buildSubjectFromToken extracts subject information from a JWT token
func (e *Enforcer) buildSubjectFromToken(t jwt.Token) casbinSubject {
	var subject string
	info := casbinSubject{}

	e.logger.Debug("building subject from token",
		slog.Any("token", t),
	)
	roles := e.extractRolesFromToken(t)

	if claim, found := t.Get(e.Config.UserNameClaim); found {
		sub, ok := claim.(string)
		subject = sub
		if !ok {
			e.logger.Warn("username claim not of type string",
				slog.String("claim", e.Config.UserNameClaim),
				slog.Any("claims", claim),
			)
			subject = ""
		}
	}
	info = append(info, roles...)
	info = append(info, subject)
	return info
}

// extractRolesFromToken extracts roles from a jwt.Token based on the configured claim path
func (e *Enforcer) extractRolesFromToken(t jwt.Token) []string {
	e.logger.Debug("extracting roles from token",
		slog.Any("token", t),
	)
	roles := []string{}

	roleClaim := e.Config.GroupsClaim

	selectors := strings.Split(roleClaim, ".")
	claim, exists := t.Get(selectors[0])
	if !exists {
		e.logger.Warn("claim not found",
			slog.String("claim", roleClaim),
			slog.Any("token", t),
		)
		return nil
	}
	e.logger.Debug("root claim found",
		slog.String("claim", roleClaim),
		slog.Any("claims", claim),
	)
	// use dotnotation if the claim is nested
	if len(selectors) > 1 {
		claimMap, ok := claim.(map[string]interface{})
		if !ok {
			e.logger.Warn("claim is not of type map[string]interface{}",
				slog.String("claim", roleClaim),
				slog.Any("claims", claim),
			)
			return nil
		}
		claim = util.Dotnotation(claimMap, strings.Join(selectors[1:], "."))
		if claim == nil {
			e.logger.Warn("claim not found",
				slog.String("claim", roleClaim),
				slog.Any("claims", claim),
			)
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
		e.logger.Warn("could not get claim type",
			slog.String("selector", roleClaim),
			slog.Any("claims", claim),
		)
		return nil
	}

	return roles
}
