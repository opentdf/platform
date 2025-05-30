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
	Policy              string
	logger              *logger.Logger
	isDefaultPolicy     bool
	isDefaultModel      bool
	groupClaimSelectors [][]string // precomputed selectors for GroupsClaim
}

type casbinSubject []string

type CasbinConfig struct {
	PolicyConfig
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

	// Precompute group claim selectors for efficiency
	groupClaimSelectors := make([][]string, len(c.GroupsClaim))
	for i, claim := range c.GroupsClaim {
		groupClaimSelectors[i] = strings.Split(claim, ".")
	}

	m, err := casbinModel.NewModelFromString(c.Model)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin model: %w", err)
	}

	e, err := casbin.NewEnforcer(m, c.Adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}
	// Explicitly load and validate the policy to catch malformed lines
	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load casbin policy: %w", err)
	}

	// Fail-safe: validate all policy lines for correct format
	policyLines := strings.Split(c.Csv, "\n")
	for i, line := range policyLines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue // skip empty/comment lines
		}
		fields := strings.Split(line, ",")
		for j := range fields {
			fields[j] = strings.TrimSpace(fields[j])
		}
		switch fields[0] {
		case "p":
			// Policy line: expect at least 5 fields: p, sub, obj, act, eft
			const expectedFields = 5
			sub, obj, act, eft := fields[1], fields[2], fields[3], fields[4]
			if len(fields) < expectedFields {
				return nil, fmt.Errorf("malformed casbin policy line %d: %q (expected at least 5 fields)", i+1, line)
			}
			if sub == "" || obj == "" || act == "" {
				return nil, fmt.Errorf("malformed casbin policy line %d: %q (resource and action fields must not be empty)", i+1, line)
			}
			if eft != "allow" && eft != "deny" {
				return nil, fmt.Errorf("malformed casbin policy line %d: %q (effect must be 'allow' or 'deny')", i+1, line)
			}
		case "g":
			const expectedFields = 3
			// Grouping line: expect at least 3 fields: g, user, role
			if len(fields) < expectedFields {
				return nil, fmt.Errorf("malformed casbin grouping line %d: %q (expected at least 3 fields)", i+1, line)
			}
		default:
			// Unknown line type, fail-safe: error
			return nil, fmt.Errorf("malformed casbin policy line %d: %q (unknown line type, must start with 'p' or 'g')", i+1, line)
		}
	}

	return &Enforcer{
		Enforcer:            e,
		Config:              c,
		Policy:              c.Csv,
		isDefaultPolicy:     isDefaultPolicy,
		isDefaultModel:      isDefaultModel,
		logger:              logger,
		groupClaimSelectors: groupClaimSelectors,
	}, nil
}

// casbinEnforce is a helper function to enforce the policy with casbin
func (e *Enforcer) Enforce(token jwt.Token, userInfo []byte, resource, action string) bool {
	// Fail-safe: deny if resource or action is empty
	if resource == "" || action == "" {
		e.logger.Debug("permission denied: empty resource or action", slog.String("resource", resource), slog.String("action", action))
		return false
	}

	// extract the role claim from the token and userInfo
	s := e.buildSubjectFromTokenAndUserInfo(token, userInfo)

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

// buildSubjectFromTokenAndUserInfo combines roles from both token and userInfo
func (e *Enforcer) buildSubjectFromTokenAndUserInfo(t jwt.Token, userInfo []byte) casbinSubject {
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
	if userInfo == nil {
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
