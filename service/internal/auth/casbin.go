package auth

import (
	"encoding/json"
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

// Enforcer is the custom Casbin enforcer with additional functionality
type Enforcer struct {
	*casbin.Enforcer
	Config              CasbinConfig
	Policy              string // CSV policy string (empty if using non-CSV adapter)
	logger              *logger.Logger
	isDefaultPolicy     bool
	isDefaultModel      bool
	groupClaimSelectors [][]string // precomputed selectors for GroupsClaim
}

type casbinSubject []string

type CasbinConfig struct {
	PolicyConfig
}

// NewCasbinEnforcer creates a new Casbin enforcer with the provided configuration and logger.
// It sets up the Casbin model, policy, and adapter, and returns an Enforcer instance.
func NewCasbinEnforcer(c CasbinConfig, logger *logger.Logger) (*Enforcer, error) {
	// Set Casbin config defaults if not provided
	isDefaultModel := false
	if c.Model == "" {
		c.Model = defaultModel
		isDefaultModel = true
	}

	// Precompute group claim selectors for efficiency (adapter-agnostic)
	groupClaimSelectors := make([][]string, len(c.GroupsClaim))
	for i, claim := range c.GroupsClaim {
		groupClaimSelectors[i] = strings.Split(claim, ".")
	}

	// Track whether we're using the CSV string adapter (vs custom adapter like SQL)
	usingCSVAdapter := c.Adapter == nil
	isDefaultPolicy := false
	isPolicyExtended := false
	csvPolicy := ""

	// CSV policy building - only when using the default string adapter
	// When a custom adapter (e.g., SQL) is provided, skip CSV-specific logic
	if usingCSVAdapter {
		csvPolicy, isDefaultPolicy, isPolicyExtended = buildCSVPolicy(c)
		c.Adapter = stringadapter.NewAdapter(csvPolicy)
	}

	logger.Debug("creating casbin enforcer",
		slog.Any("config", c),
		slog.Bool("isDefaultModel", isDefaultModel),
		slog.Bool("isBuiltinPolicy", isDefaultPolicy),
		slog.Bool("isPolicyExtended", isPolicyExtended),
		slog.Bool("usingCSVAdapter", usingCSVAdapter),
	)

	m, err := casbinModel.NewModelFromString(c.Model)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin model: %w", err)
	}

	e, err := casbin.NewEnforcer(m, c.Adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}

	// Explicitly load the policy from the adapter
	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load casbin policy: %w", err)
	}

	// CSV validation - only for CSV/string adapters
	// Skip validation for custom adapters (e.g., SQL) which have their own validation
	if usingCSVAdapter {
		if err := validateCSVPolicy(csvPolicy); err != nil {
			return nil, err
		}
	}

	return &Enforcer{
		Enforcer:            e,
		Config:              c,
		Policy:              csvPolicy, // Empty string if using non-CSV adapter
		isDefaultPolicy:     isDefaultPolicy,
		isDefaultModel:      isDefaultModel,
		logger:              logger,
		groupClaimSelectors: groupClaimSelectors,
	}, nil
}

// Enforce checks if the given token and userInfo are allowed to perform the action on the resource.
// It extracts roles from both the token and userInfo, then checks against the Casbin policy.
func (e *Enforcer) Enforce(token jwt.Token, userInfo []byte, resource, action string) bool {
	// Fail-safe: deny if resource or action is empty
	if resource == "" || action == "" {
		e.logger.Debug("permission denied: empty resource or action", slog.String("resource", resource), slog.String("action", action))
		return false
	}

	// extract the role claim from the token and userInfo
	s := e.BuildSubjectFromTokenAndUserInfo(token, userInfo)

	// Assign the default role if no roles are found
	if len(s) == 0 {
		s = append(s, rolePrefix+defaultRole)
	}

	for _, info := range s {
		allowed, err := e.Enforcer.Enforce(info, resource, action)
		if err != nil {
			e.logger.Error("enforce by role error", slog.String("subject info", info), slog.String("resource", resource), slog.String("action", action), slog.String("error", err.Error()))
		}
		if allowed {
			e.logger.Debug("allowed by policy", slog.String("subject info", info), slog.String("resource", resource), slog.String("action", action))
			return true
		}
	}
	e.logger.Debug("permission denied by policy", slog.Any("subject.info", s), slog.String("resource", resource), slog.String("action", action))
	return false
}

// BuildSubjectFromTokenAndUserInfo combines roles from both token and userInfo.
// It extracts roles from both sources and adds the username claim if present.
// This method implements authz.V1Enforcer interface.
func (e *Enforcer) BuildSubjectFromTokenAndUserInfo(t jwt.Token, userInfo []byte) []string {
	var subject string
	info := casbinSubject{}

	e.logger.Debug("building subject from token and userInfo", slog.Any("token", t), slog.Any("userInfo", userInfo))
	roles := e.extractRolesFromToken(t)
	roles = append(roles, e.extractRolesFromUserInfo(userInfo)...)

	for _, r := range roles {
		if r != "" {
			info = append(info, r)
		}
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
	e.logger.Debug("built subject info", slog.Any("info", info))
	return info
}

const (
	// defaultRolesCapacity is the default capacity for roles slice in extractRolesFromToken
	defaultRolesCapacity = 4
)

// extractRolesFromToken extracts roles from a jwt.Token based on the configured claim path
func (e *Enforcer) extractRolesFromToken(token jwt.Token) []string {
	roles := make([]string, 0, defaultRolesCapacity) // preallocate for common case
	for _, selectors := range e.groupClaimSelectors {
		if len(selectors) == 0 {
			continue
		}
		claim, exists := token.Get(selectors[0])
		if !exists {
			continue // skip missing claim, don't log on hot path
		}
		if len(selectors) > 1 {
			claimMap, ok := claim.(map[string]interface{})
			if !ok {
				continue // skip invalid type
			}
			claim = util.Dotnotation(claimMap, strings.Join(selectors[1:], "."))
			if claim == nil {
				continue
			}
		}
		// Inline extractRolesFromClaim for efficiency
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
		}
	}
	return roles
}

// extractRolesFromUserInfo extracts roles from a userInfo JSON ([]byte) based on the configured claim path
func (e *Enforcer) extractRolesFromUserInfo(userInfo []byte) []string {
	roles := make([]string, 0, defaultRolesCapacity)
	if userInfo == nil || len(userInfo) == 0 {
		return roles
	}
	var userInfoMap map[string]interface{}
	if err := json.Unmarshal(userInfo, &userInfoMap); err != nil {
		return roles // skip logging on hot path
	}
	for _, selectors := range e.groupClaimSelectors {
		if len(selectors) == 0 {
			continue
		}
		claim := util.Dotnotation(userInfoMap, strings.Join(selectors, "."))
		if claim == nil {
			continue
		}
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
		}
	}
	return roles
}
