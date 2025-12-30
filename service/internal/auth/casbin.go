package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"gorm.io/gorm"

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
	// Adapter is the runtime Casbin adapter instance to use. For adapter="csv",
	// if not provided, a string adapter will be created from the CSV policy.
	// For adapter="sql", this must be provided by the caller (e.g., server wiring).
	Adapter persist.Adapter
}

// newCasbinEnforcer creates a new casbin enforcer
func NewCasbinEnforcer(c CasbinConfig, logger *logger.Logger) (*Enforcer, error) {
	// Normalize adapter selection
	adapterMode := strings.ToLower(strings.TrimSpace(c.PolicyConfig.Adapter))
	if adapterMode == "" {
		adapterMode = "csv"
	}

	// Set Casbin config defaults depending on adapter mode
	isDefaultModel := false
	isDefaultPolicy := false
	isPolicyExtended := false
	isDefaultAdapter := false

	if adapterMode == "sql" {
		// Disregard model/csv/extension from config; always use defaultModel.
		c.Model = defaultModel
		isDefaultModel = true

		// Require a runtime adapter instance for SQL
		if c.Adapter == nil {
			return nil, fmt.Errorf("sql adapter requires a runtime adapter instance; none provided")
		}
	} else {
		// CSV mode: honor model/csv/extension/roleMap; set defaults when missing
		if c.Model == "" {
			c.Model = defaultModel
			isDefaultModel = true
		}

		if c.Csv == "" {
			if c.Builtin != "" {
				c.Csv = c.Builtin
			} else {
				c.Csv = builtinPolicy
			}
			isDefaultPolicy = true
		}

		if c.Extension != "" {
			c.Csv = strings.Join([]string{c.Csv, c.Extension}, "\n")
			isPolicyExtended = true
		}

		// Append grouping policies derived from config (role map or defaults)
		groupingLines := groupingCSVLines(composeGroupingEntries(c.PolicyConfig))
		if len(groupingLines) > 0 {
			c.Csv = strings.Join([]string{c.Csv, strings.Join(groupingLines, "\n")}, "\n")
		}

		// If adapter is not provided, use the default string adapter from CSV
		if c.Adapter == nil {
			isDefaultAdapter = true
			c.Adapter = stringadapter.NewAdapter(c.Csv)
		}
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
	enforcer := &Enforcer{
		Enforcer:        e,
		Config:          c,
		Policy:          c.Csv,
		isDefaultPolicy: isDefaultPolicy,
		isDefaultModel:  isDefaultModel,
		logger:          logger,
	}

	// If using SQL policy storage, seed the store if empty
	if adapterMode == "sql" {
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

	// If a username claim exists and is valid, prefer enforcing by username only
	if claim, found := t.Get(e.Config.UserNameClaim); found {
		sub, ok := claim.(string)
		if ok {
			subject = sub
			info = append(info, subject)
			return info
		}
		e.logger.Warn("username claim not of type string",
			slog.String("claim", e.Config.UserNameClaim),
			slog.Any("claims", claim),
		)
		// fall through to role-based enforcement when username claim is invalid
	}

	// No valid username claim; enforce using roles extracted from the token
	roles := e.extractRolesFromToken(t)
	info = append(info, roles...)
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

	// Seed from the builtin policy, then add grouping policies derived from config
	seedAdapter := stringadapter.NewAdapter(builtinPolicy)
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
	// Add grouping policies derived from runtime config (role map or defaults)
	derivedGrouping := composeGroupingEntries(e.Config.PolicyConfig)
	if len(derivedGrouping) == 0 {
		// fall back to any grouping policies present in the builtin seed
		e.addSeed(sg, e.AddGroupingPolicy, "grouping")
	} else {
		e.addSeed(derivedGrouping, e.AddGroupingPolicy, "grouping")
	}

	if saveErr := e.SavePolicy(); saveErr != nil {
		return fmt.Errorf("failed to persist seed policy to SQL adapter: %w", saveErr)
	}
	e.logger.Info("seeded SQL policy store with standard policy")
	return nil
}

// composeGroupingEntries returns grouping policies derived from PolicyConfig.RoleMap only.
// - If RoleMap is provided, it maps each external role to its internal role: g, <mapped>, role:<key>
// - If RoleMap is nil or empty, it returns no entries; callers should rely on builtin policy defaults.
func composeGroupingEntries(c PolicyConfig) [][]string {
	entries := [][]string{}
	if c.RoleMap == nil {
		return entries
	}
	for k, v := range c.RoleMap {
		entries = append(entries, []string{v, "role:" + k})
	}
	return entries
}

// groupingCSVLines converts grouping entries to CSV lines suitable for the string adapter
func groupingCSVLines(entries [][]string) []string {
	lines := []string{}
	for _, e := range entries {
		if len(e) != 2 {
			continue
		}
		lines = append(lines, strings.Join([]string{"g", e[0], e[1]}, ", "))
	}
	return lines
}

// ConfigureSQLCasbinAdapter initializes a GORM-backed Casbin adapter using the platform DB settings,
// auto-migrates the casbin_rule table (respecting search_path schema), and returns the adapter.
// It intentionally keeps the DB client open for the adapter's lifetime.
func ConfigureSQLCasbinAdapterWithGorm(gormDB *gorm.DB, logger *logger.Logger) (persist.Adapter, error) {
	if err := gormDB.AutoMigrate(&gormadapter.CasbinRule{}); err != nil {
		logger.Error("failed to auto-migrate casbin_rule table", slog.Any("error", err))
		return nil, fmt.Errorf("failed to auto-migrate casbin_rule table: %w", err)
	}
	casbinAdapter, err := gormadapter.NewAdapterByDB(gormDB)
	if err != nil {
		logger.Error("failed to initialize gorm casbin adapter", slog.Any("error", err))
		return nil, fmt.Errorf("failed to initialize gorm casbin adapter: %w", err)
	}
	logger.Info("SQL-backed Casbin adapter configured")
	return casbinAdapter, nil
}
