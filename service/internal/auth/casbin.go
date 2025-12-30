package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"

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
	// If adapter instance is not provided, use the default string adapter
	if c.AdapterInstance == nil {
		isDefaultAdapter = true
		c.AdapterInstance = stringadapter.NewAdapter(c.Csv)
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

	e, err := casbin.NewEnforcer(m, c.AdapterInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to create casbin enforcer: %w", err)
	}
	enforcer := &Enforcer{
		Enforcer:        e,
		Config:          c,
		Policy:          c.Csv,
		isDefaultPolicy: isDefaultPolicy,
		isDefaultModel:  isDefaultModel,
		logger:          logger,
	}

	// If using SQL policy storage, seed the store if empty
	if c.Adapter == "sql" {
		if err := enforcer.useSQLPolicy(m); err != nil {
			return nil, err
		}
	}

	return enforcer, nil
}

// casbinEnforce is a helper function to enforce the policy with casbin
// TODO implement a common type so this can be used for both http and grpc
func (e *Enforcer) Enforce(token jwt.Token, resource, action string) (bool, error) {
	// extract the role claim from the token
	s := e.buildSubjectFromToken(token)
	s = append(s, rolePrefix+defaultRole)

	for _, info := range s {
		allowed, err := e.Enforcer.Enforce(info, resource, action)
		if err != nil {
			e.logger.Error("enforce by role error",
				slog.String("subject_info", info),
				slog.String("action", action),
				slog.String("resource", resource),
				slog.Any("error", err),
			)
		}
		if allowed {
			e.logger.Debug("allowed by policy",
				slog.String("subject_info", info),
				slog.String("action", action),
				slog.String("resource", resource),
			)
			return true, nil
		}
	}
	e.logger.Debug("permission denied by policy",
		slog.Any("subject_info", s),
		slog.String("action", action),
		slog.String("resource", resource),
	)
	return false, errors.New("permission denied")
}

func (e *Enforcer) buildSubjectFromToken(t jwt.Token) casbinSubject {
	var subject string
	info := casbinSubject{}

	e.logger.Debug("building subject from token")
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

func (e *Enforcer) extractRolesFromToken(t jwt.Token) []string {
	e.logger.Debug("extracting roles from token")
	roles := []string{}

	roleClaim := e.Config.GroupsClaim
	// roleMap := e.Config.RoleMap

	selectors := strings.Split(roleClaim, ".")
	claim, exists := t.Get(selectors[0])
	if !exists {
		e.logger.Warn("claim not found",
			slog.String("claim", roleClaim),
			slog.Any("claims", claim),
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
		claim = dotNotation(claimMap, strings.Join(selectors[1:], "."))
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

func (e *Enforcer) addSeed(entries [][]string, addFn func(...any) (bool, error), field string) {
	for _, entry := range entries {
		args := make([]any, len(entry))
		for i, v := range entry {
			args[i] = v
		}
		if _, err := addFn(args...); err != nil {
			e.logger.Warn(
				"failed to add seed entry",
				slog.Any(field, entry),
				slog.Any("error", err),
			)
		}
	}
}

// policyGetter defines the subset of casbin enforcer methods used to retrieve policies
type policyGetter interface {
	GetPolicy() ([][]string, error)
	GetGroupingPolicy() ([][]string, error)
}

// getPolicies returns both regular and grouping policies, or an error
func getPolicies(pg policyGetter) ([][]string, [][]string, error) {
	p, err := pg.GetPolicy()
	if err != nil {
		return nil, nil, err
	}
	g, err := pg.GetGroupingPolicy()
	if err != nil {
		return nil, nil, err
	}
	return p, g, nil
}

// hasAnyPolicies returns true if any policy or grouping policy exists
func hasAnyPolicies(p, g [][]string) bool {
	return len(p) > 0 || len(g) > 0
}

// useSQLPolicy loads existing policies from the configured adapter. If none are found,
// it seeds the SQL store with the combined CSV policy in e.Config.Csv and persists it.
func (e *Enforcer) useSQLPolicy(m casbinModel.Model) error {
	e.logger.Debug("checking SQL policy store for existing policies")
	if err := e.LoadPolicy(); err != nil {
		e.logger.Warn("failed loading existing policy from adapter; attempting seed", slog.Any("error", err))
	}
	ep, eg, err := getPolicies(e.Enforcer)
	if err != nil {
		return fmt.Errorf("failed to get existing policies: %w", err)
	}
	if hasAnyPolicies(ep, eg) {
		e.logger.Debug("SQL policy store already contains policies; skipping seed")
		return nil
	}

	seedAdapter := stringadapter.NewAdapter(e.Config.Csv)
	seedEnf, seedErr := casbin.NewEnforcer(m, seedAdapter)
	if seedErr != nil {
		return fmt.Errorf("failed to create seeding enforcer: %w", seedErr)
	}
	if loadErr := seedEnf.LoadPolicy(); loadErr != nil {
		return fmt.Errorf("failed to load seed policy: %w", loadErr)
	}

	sp, sg, getSeedErr := getPolicies(seedEnf)
	if getSeedErr != nil {
		return fmt.Errorf("failed to get seed policies: %w", getSeedErr)
	}
	e.addSeed(sp, e.AddPolicy, "policy")
	e.addSeed(sg, e.AddGroupingPolicy, "grouping")

	if saveErr := e.SavePolicy(); saveErr != nil {
		return fmt.Errorf("failed to persist seed policy to SQL adapter: %w", saveErr)
	}
	e.logger.Info("seeded SQL policy store with standard policy")
	return nil
}
