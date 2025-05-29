package auth

import (
	"encoding/json"
	"errors"
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
	// OIDC UserInfo enrichment fields
	UserInfoEnrichment bool
	UserInfoEndpoint   string
	TokenEndpoint      string
	ClientID           string
	ClientSecret       string
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

// casbinEnforce is a helper function to enforce the policy with casbin
func (e *Enforcer) Enforce(token jwt.Token, userInfo []byte, resource, action string) (bool, error) {
	// extract the role claim from the token and userInfo
	s := e.buildSubjectFromTokenAndUserInfo(token, userInfo)
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

// buildSubjectFromTokenAndUserInfo combines roles from both token and userInfo
func (e *Enforcer) buildSubjectFromTokenAndUserInfo(t jwt.Token, userInfo []byte) casbinSubject {
	var subject string
	info := casbinSubject{}

	e.logger.Debug("building subject from token and userInfo", slog.Any("token", t), slog.Any("userInfo", userInfo))
	roles := e.extractRolesFromToken(t)
	roles = append(roles, e.extractRolesFromUserInfo(userInfo)...)

	// Prefix all roles with role:
	for _, r := range roles {
		info = append(info, rolePrefix+r)
	}

	if claim, found := t.Get(e.Config.UserNameClaim); found {
		sub, ok := claim.(string)
		subject = sub
		if !ok {
			e.logger.Warn("username claim not of type string", slog.String("claim", e.Config.UserNameClaim), slog.Any("claims", claim))
			subject = ""
		}
	}
	if subject != "" {
		info = append(info, subject)
	}
	return info
}

// extractRolesFromToken extracts roles from a jwt.Token based on the configured claim path
func (e *Enforcer) extractRolesFromToken(token jwt.Token) []string {
	roles := []string{}
	for _, roleClaim := range e.Config.GroupsClaim {
		selectors := strings.Split(roleClaim, ".")
		claim, exists := token.Get(selectors[0])
		if !exists {
			e.logger.Warn("claim not found in token", slog.String("claim", roleClaim), slog.Any("token", token))
			continue
		}
		if len(selectors) > 1 {
			claimMap, ok := claim.(map[string]interface{})
			if !ok {
				e.logger.Warn("claim is not of type map[string]interface{}", slog.String("claim", roleClaim), slog.Any("claims", claim))
				continue
			}
			claim = util.Dotnotation(claimMap, strings.Join(selectors[1:], "."))
			if claim == nil {
				e.logger.Warn("nested claim not found", slog.String("claim", roleClaim), slog.Any("claims", claim))
				continue
			}
		}
		roles = append(roles, extractRolesFromClaim(claim, e.logger)...)
	}
	if len(roles) == 0 {
		e.logger.Warn("no roles found in accessToken claims", slog.Any("claims", e.Config.GroupsClaim))
	}
	return roles
}

// extractRolesFromUserInfo extracts roles from a userInfo JSON ([]byte) based on the configured claim path
func (e *Enforcer) extractRolesFromUserInfo(userInfo []byte) []string {
	roles := []string{}
	if userInfo == nil {
		return roles
	}
	var userInfoMap map[string]interface{}
	if err := json.Unmarshal(userInfo, &userInfoMap); err != nil {
		e.logger.Warn("failed to unmarshal userInfo JSON", slog.Any("error", err))
		return roles
	}
	for _, roleClaim := range e.Config.GroupsClaim {
		selectors := strings.Split(roleClaim, ".")
		claim := util.Dotnotation(userInfoMap, strings.Join(selectors, "."))
		if claim == nil {
			e.logger.Warn("claim not found in userInfo JSON", slog.String("claim", roleClaim), slog.Any("userInfo", userInfoMap))
			continue
		}
		roles = append(roles, extractRolesFromClaim(claim, e.logger)...)
	}
	if len(roles) == 0 {
		e.logger.Warn("no roles found in userInfo claims", slog.Any("claims", e.Config.GroupsClaim))
	}
	return roles
}

func extractRolesFromClaim(claim interface{}, logger *logger.Logger) []string {
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
	case []string:
		roles = append(roles, v...)
	default:
		logger.Warn("could not get claim type", slog.Any("claim", claim))
	}
	return roles
}
