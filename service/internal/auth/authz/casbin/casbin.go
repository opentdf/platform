// Package casbin provides a Casbin-based authorization implementation.
package casbin

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/util"
)

//go:embed model.conf
var modelV2 string

//go:embed policy.csv
var builtinPolicyV2 string

const (
	// rolePrefix is the prefix for role subjects in casbin policies.
	rolePrefix = "role:"
	// defaultRole is the role assigned when no roles are found.
	defaultRole = "unknown"
	// defaultSubjectsCapacity is the default capacity for subjects/roles slices.
	defaultSubjectsCapacity = 4
	// dimensionMatchArgCount is the expected argument count for dimensionMatch function.
	dimensionMatchArgCount = 2
	// kvPairParts is the expected number of parts when splitting key=value pairs.
	kvPairParts = 2
)

func init() {
	// Register the Casbin authorizer factory
	authz.RegisterFactory("casbin", NewAuthorizer)
}

// Authorizer implements authz.Authorizer using Casbin.
// It supports both v1 (path-based) and v2 (RPC+dimensions) authorization models.
type Authorizer struct {
	// version indicates which model is active ("v1" or "v2")
	version string

	// v1Enforcer handles legacy path-based authorization
	// Used when version == "v1"
	v1Enforcer authz.V1Enforcer

	// v2Enforcer handles RPC+dimensions authorization
	// Used when version == "v2"
	v2Enforcer *casbin.Enforcer

	logger *logger.Logger

	// baseConfig holds common configuration extracted from adapter config
	baseConfig authz.BaseAdapterConfig

	// groupClaimSelectors are precomputed selectors for extracting roles from JWT claims
	// Used in v2-only mode when v1Enforcer is nil
	groupClaimSelectors [][]string
}

// NewAuthorizer creates a new Casbin Authorizer based on configuration.
// It maps the external Config to the appropriate internal adapter config
// (CasbinV1Config or CasbinV2Config) for cleaner separation of concerns.
func NewAuthorizer(cfg authz.Config) (authz.Authorizer, error) {
	log, ok := cfg.Logger.(*logger.Logger)
	if !ok || log == nil {
		return nil, errors.New("logger is required for CasbinAuthorizer")
	}

	// Map external config to internal adapter config
	adapterCfg := authz.AdapterConfigFromExternal(cfg)

	switch typedCfg := adapterCfg.(type) {
	case authz.CasbinV1Config:
		return newCasbinV1Authorizer(typedCfg, log)
	case authz.CasbinV2Config:
		return newCasbinV2Authorizer(typedCfg, log)
	default:
		return nil, fmt.Errorf("unsupported adapter config type: %T", adapterCfg)
	}
}

// newCasbinV1Authorizer creates a v1 (path-based) Casbin authorizer.
func newCasbinV1Authorizer(cfg authz.CasbinV1Config, log *logger.Logger) (*Authorizer, error) {
	if cfg.Enforcer == nil {
		return nil, errors.New("v1 enforcer is required for v1 authorization mode (use authz.WithV1Enforcer)")
	}

	authorizer := &Authorizer{
		version:    "v1",
		logger:     log,
		baseConfig: cfg.BaseAdapterConfig,
		v1Enforcer: cfg.Enforcer,
	}

	log.Info("casbin authorizer initialized",
		slog.String("version", authorizer.version),
		slog.Bool("supportsResourceAuth", authorizer.SupportsResourceAuthorization()),
	)

	return authorizer, nil
}

// newCasbinV2Authorizer creates a v2 (RPC+dimensions) Casbin authorizer.
func newCasbinV2Authorizer(cfg authz.CasbinV2Config, log *logger.Logger) (*Authorizer, error) {
	enforcer, err := createV2EnforcerFromConfig(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 casbin enforcer: %w", err)
	}

	// Precompute group claim selector for v2 role extraction
	// GroupsClaim is a dot-notation path like "realm_access.roles"
	var groupClaimSelectors [][]string
	if cfg.GroupsClaim != "" {
		groupClaimSelectors = [][]string{strings.Split(cfg.GroupsClaim, ".")}
	}

	authorizer := &Authorizer{
		version:             "v2",
		logger:              log,
		baseConfig:          cfg.BaseAdapterConfig,
		v2Enforcer:          enforcer,
		groupClaimSelectors: groupClaimSelectors,
	}

	log.Info("casbin authorizer initialized",
		slog.String("version", authorizer.version),
		slog.Bool("supportsResourceAuth", authorizer.SupportsResourceAuthorization()),
	)

	return authorizer, nil
}

// createV2EnforcerFromConfig creates a Casbin enforcer for the v2 model
// using the internal CasbinV2Config type.
//
// Adapter selection priority:
// 1. cfg.Adapter (custom adapter provided explicitly)
// 2. cfg.GormDB (SQL adapter with automatic migration and seeding)
// 3. CSV adapter (fallback using embedded policy + extensions)
func createV2EnforcerFromConfig(cfg authz.CasbinV2Config, log *logger.Logger) (*casbin.Enforcer, error) {
	// Use embedded v2 model or custom model from config
	modelStr := modelV2
	if cfg.Model != "" {
		modelStr = cfg.Model
	}

	m, err := casbinModel.NewModelFromString(modelStr)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 casbin model: %w", err)
	}

	// Build policy adapter with priority: custom > SQL > CSV
	var adapter persist.Adapter
	var usingSQLAdapter bool

	switch {
	case cfg.Adapter != nil:
		// 1. Use explicitly provided adapter
		adapter = cfg.Adapter
		log.Debug("v2 using custom adapter")
		break
	case cfg.GormDB != nil:
		// 2. Use SQL adapter with GORM
		sqlAdapter, err := CreateSQLAdapter(cfg.GormDB, cfg.Schema, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create SQL adapter: %w", err)
		}
		adapter = sqlAdapter
		usingSQLAdapter = true
		log.Info("v2 using SQL adapter", slog.String("schema", cfg.Schema))
		break
	default:
		// 3. Fallback to CSV adapter
		csvPolicy := buildV2PolicyFromConfig(cfg)
		adapter = stringadapter.NewAdapter(csvPolicy)
		log.Debug("v2 using CSV adapter", slog.String("policy", csvPolicy))
	}

	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 casbin enforcer: %w", err)
	}

	// Load policy from adapter
	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load v2 casbin policy: %w", err)
	}

	// Seed SQL adapter with default policies if empty
	if usingSQLAdapter {
		csvPolicy := buildV2PolicyFromConfig(cfg)
		if err := SeedPoliciesIfEmpty(e, csvPolicy, log); err != nil {
			return nil, fmt.Errorf("failed to seed SQL policy store: %w", err)
		}
	}

	// Register custom dimension matching function
	e.AddFunction("dimensionMatch", dimensionMatchFunc)

	return e, nil
}

// buildV2PolicyFromConfig constructs the CSV policy for v2 model
// using the internal CasbinV2Config type.
func buildV2PolicyFromConfig(cfg authz.CasbinV2Config) string {
	var policies []string

	if cfg.Csv != "" {
		// Custom policy overrides default
		policies = append(policies, cfg.Csv)
	} else {
		// Use embedded default v2 policy
		policies = append(policies, builtinPolicyV2)
	}

	// Add extension policy
	if cfg.Extension != "" {
		policies = append(policies, cfg.Extension)
	}

	return strings.Join(policies, "\n")
}

// Authorize implements authz.Authorizer.Authorize.
func (a *Authorizer) Authorize(ctx context.Context, req *authz.Request) (*authz.Decision, error) {
	switch a.version {
	case "v1":
		return a.authorizeV1(ctx, req)
	case "v2":
		return a.authorizeV2(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported authorization version: %s", a.version)
	}
}

// Version implements authz.Authorizer.Version.
func (a *Authorizer) Version() string {
	return a.version
}

// SupportsResourceAuthorization implements authz.Authorizer.SupportsResourceAuthorization.
func (a *Authorizer) SupportsResourceAuthorization() bool {
	return a.version == "v2"
}

// authorizeV1 performs legacy path-based authorization.
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
func (a *Authorizer) authorizeV1(_ context.Context, req *authz.Request) (*authz.Decision, error) {
	resource := req.RPC
	if strings.Contains(req.RPC, ".") {
		// gRPC-style path (contains '.'): strip leading slash for v1 policy compatibility
		// Example: /kas.AccessService/Rewrap -> kas.AccessService/Rewrap
		resource = strings.TrimPrefix(req.RPC, "/")
	}
	// HTTP paths (no '.') keep their leading slash
	// Example: /kas/v2/rewrap -> /kas/v2/rewrap

	allowed := a.v1Enforcer.Enforce(req.Token, req.UserInfo, resource, req.Action)

	return &authz.Decision{
		Allowed: allowed,
		Reason:  fmt.Sprintf("v1: %s %s", req.Action, resource),
		Mode:    authz.ModeV1,
	}, nil
}

// authorizeV2 performs RPC+dimensions authorization.
func (a *Authorizer) authorizeV2(_ context.Context, req *authz.Request) (*authz.Decision, error) {
	subjects := a.extractSubjects(req)

	// If no subjects found, use default role
	if len(subjects) == 0 {
		subjects = append(subjects, rolePrefix+defaultRole)
	}

	// Serialize dimensions to canonical string
	dims := serializeDimensions(req.ResourceContext)

	a.logger.Debug("v2 authorization check",
		slog.Any("subjects", subjects),
		slog.String("rpc", req.RPC),
		slog.String("dims", dims),
	)

	// Check each subject (role or username)
	// Track if any enforcement succeeded without error to distinguish
	// "all denied" from "all errored" (system failure)
	var (
		anyCheckedSuccessfully bool
		lastErr                error
	)

	for _, subject := range subjects {
		allowed, err := a.v2Enforcer.Enforce(subject, req.RPC, dims)
		if err != nil {
			a.logger.Error("v2 enforcement error",
				slog.String("subject", subject),
				slog.String("rpc", req.RPC),
				slog.String("dims", dims),
				slog.Any("error", err),
			)
			lastErr = err
			continue
		}

		anyCheckedSuccessfully = true

		if allowed {
			a.logger.Debug("v2 authorization allowed",
				slog.String("subject", subject),
				slog.String("rpc", req.RPC),
				slog.String("dims", dims),
			)
			return &authz.Decision{
				Allowed:       true,
				Reason:        fmt.Sprintf("v2: %s on %s with dims=%s", subject, req.RPC, dims),
				Mode:          authz.ModeV2,
				MatchedPolicy: subject,
			}, nil
		}
	}

	// If ALL subjects failed with errors (none checked successfully),
	// return a system error instead of a denial
	if !anyCheckedSuccessfully && lastErr != nil {
		return nil, fmt.Errorf("v2 authorization system error: %w", lastErr)
	}

	a.logger.Debug("v2 authorization denied",
		slog.Any("subjects", subjects),
		slog.String("rpc", req.RPC),
		slog.String("dims", dims),
	)

	return &authz.Decision{
		Allowed: false,
		Reason:  fmt.Sprintf("v2: denied %s with dims=%s", req.RPC, dims),
		Mode:    authz.ModeV2,
	}, nil
}

// extractSubjects extracts roles/username from JWT token and userInfo.
func (a *Authorizer) extractSubjects(req *authz.Request) []string {
	if a.v1Enforcer != nil {
		// Reuse v1 subject extraction logic
		return a.v1Enforcer.BuildSubjectFromTokenAndUserInfo(req.Token, req.UserInfo)
	}

	// For v2-only mode, implement subject extraction
	subjects := make([]string, 0, defaultSubjectsCapacity)

	// Extract roles from token claims
	if req.Token != nil {
		roles := a.extractRolesFromToken(req.Token)
		for _, role := range roles {
			if role != "" {
				subjects = append(subjects, rolePrefix+role)
			}
		}

		// Extract username claim
		if claim, found := req.Token.Get(a.baseConfig.UserNameClaim); found {
			if username, ok := claim.(string); ok && username != "" {
				subjects = append(subjects, username)
			}
		}
	}

	// Extract roles from userInfo
	if req.UserInfo != nil {
		roles := a.extractRolesFromUserInfo(req.UserInfo)
		for _, role := range roles {
			if role != "" {
				subjects = append(subjects, rolePrefix+role)
			}
		}
	}

	return subjects
}

// extractRolesFromToken extracts roles from a jwt.Token based on the configured claim path.
func (a *Authorizer) extractRolesFromToken(token jwt.Token) []string {
	roles := make([]string, 0, defaultSubjectsCapacity)
	for _, selectors := range a.groupClaimSelectors {
		if len(selectors) == 0 {
			continue
		}
		claim, exists := token.Get(selectors[0])
		if !exists {
			continue
		}
		if len(selectors) > 1 {
			claimMap, ok := claim.(map[string]any)
			if !ok {
				continue
			}
			claim = util.Dotnotation(claimMap, strings.Join(selectors[1:], "."))
			if claim == nil {
				continue
			}
		}
		// Extract roles from the claim value
		switch v := claim.(type) {
		case string:
			roles = append(roles, v)
		case []any:
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

// extractRolesFromUserInfo extracts roles from a userInfo JSON ([]byte) based on the configured claim path.
func (a *Authorizer) extractRolesFromUserInfo(userInfo []byte) []string {
	roles := make([]string, 0, defaultSubjectsCapacity)
	if len(userInfo) == 0 {
		return roles
	}
	var userInfoMap map[string]any
	if err := json.Unmarshal(userInfo, &userInfoMap); err != nil {
		return roles
	}
	for _, selectors := range a.groupClaimSelectors {
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
		case []any:
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

// serializeDimensions converts ResolverContext to canonical dimension string.
// Format: key1=value1&key2=value2 (keys sorted alphabetically)
// Returns "*" if no dimensions are present.
func serializeDimensions(ctx *authz.ResolverContext) string {
	if ctx == nil || len(ctx.Resources) == 0 {
		return "*"
	}

	// Collect all dimensions from all resources
	allDims := make(map[string]string)
	for _, resource := range ctx.Resources {
		if resource == nil {
			continue
		}
		for k, v := range *resource {
			allDims[k] = v
		}
	}

	if len(allDims) == 0 {
		return "*"
	}

	// Sort keys for canonical ordering
	keys := make([]string, 0, len(allDims))
	for k := range allDims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical string
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, allDims[k]))
	}

	return strings.Join(parts, "&")
}

// dimensionMatchFunc is the Casbin custom function for dimension matching.
// It compares request dimensions against policy dimensions.
//
// Policy format: "namespace=hr&attribute=*" (AND logic, * is wildcard)
// Request format: "namespace=hr&attribute=classification"
func dimensionMatchFunc(args ...any) (any, error) {
	if len(args) != dimensionMatchArgCount {
		return false, fmt.Errorf("dimensionMatch requires %d arguments, got %d", dimensionMatchArgCount, len(args))
	}

	reqDims, ok := args[0].(string)
	if !ok {
		return false, fmt.Errorf("request dimensions must be string, got %T", args[0])
	}

	policyDims, ok := args[1].(string)
	if !ok {
		return false, fmt.Errorf("policy dimensions must be string, got %T", args[1])
	}

	return dimensionMatch(reqDims, policyDims), nil
}

// dimensionMatch compares request dimensions against policy dimensions.
// Returns true if the request satisfies the policy.
//
// Rules:
// - Policy "*" matches any request dimensions
// - Each policy dimension must be satisfied by the request
// - Policy value "*" matches any value for that dimension
// - Request must have all dimensions specified in policy
func dimensionMatch(reqDims, policyDims string) bool {
	// Wildcard policy matches everything
	if policyDims == "*" {
		return true
	}

	// Parse request dimensions into map
	reqMap := parseDimensions(reqDims)

	// Empty policy with non-wildcard request: check if request also empty
	if policyDims == "" {
		return len(reqMap) == 0
	}

	// Each policy dimension must be satisfied
	for _, pair := range strings.Split(policyDims, "&") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		kv := strings.SplitN(pair, "=", kvPairParts)
		if len(kv) != kvPairParts {
			return false
		}
		key, policyVal := kv[0], kv[1]

		reqVal, exists := reqMap[key]
		if !exists {
			// Policy requires a dimension that request doesn't have
			return false
		}

		// Wildcard matches any value
		if policyVal != "*" && policyVal != reqVal {
			return false
		}
	}

	return true
}

// parseDimensions parses a dimension string into a map.
func parseDimensions(dims string) map[string]string {
	result := make(map[string]string)
	if dims == "*" || dims == "" {
		return result
	}

	for _, pair := range strings.Split(dims, "&") {
		kv := strings.SplitN(pair, "=", kvPairParts)
		if len(kv) == kvPairParts {
			result[kv[0]] = kv[1]
		}
	}
	return result
}
