package auth

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
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/util"
)

//go:embed casbin_model_v2.conf
var modelV2 string

//go:embed casbin_policy_v2.csv
var builtinPolicyV2 string

const (
	// defaultSubjectsCapacity is the default capacity for subjects/roles slices.
	defaultSubjectsCapacity = 4
	// dimensionMatchArgCount is the expected argument count for dimensionMatch function.
	dimensionMatchArgCount = 2
	// kvPairParts is the expected number of parts when splitting key=value pairs.
	kvPairParts = 2
)

func init() {
	// Register the Casbin authorizer factory
	RegisterAuthorizer("casbin", NewCasbinAuthorizer)
}

// CasbinAuthorizer implements Authorizer using Casbin.
// It supports both v1 (path-based) and v2 (RPC+dimensions) authorization models.
type CasbinAuthorizer struct {
	// version indicates which model is active ("v1" or "v2")
	version string

	// v1Enforcer handles legacy path-based authorization
	// Used when version == "v1"
	v1Enforcer *Enforcer

	// v2Enforcer handles RPC+dimensions authorization
	// Used when version == "v2"
	v2Enforcer *casbin.Enforcer

	logger *logger.Logger
	config PolicyConfig

	// groupClaimSelectors are precomputed selectors for extracting roles from JWT claims
	// Used in v2-only mode when v1Enforcer is nil
	groupClaimSelectors [][]string
}

// NewCasbinAuthorizer creates a new CasbinAuthorizer based on configuration.
func NewCasbinAuthorizer(cfg AuthorizerConfig) (Authorizer, error) {
	log, ok := cfg.Logger.(*logger.Logger)
	if !ok || log == nil {
		return nil, errors.New("logger is required for CasbinAuthorizer")
	}

	authorizer := &CasbinAuthorizer{
		version: cfg.Version,
		logger:  log,
		config:  cfg.PolicyConfig,
	}

	switch cfg.Version {
	case "v1", "":
		// v1: Use existing Enforcer for backwards compatibility
		enforcer, err := NewCasbinEnforcer(CasbinConfig{PolicyConfig: cfg.PolicyConfig}, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create v1 casbin enforcer: %w", err)
		}
		authorizer.v1Enforcer = enforcer
		authorizer.version = "v1"

	case "v2":
		// v2: Create new enforcer with RPC+dimensions model
		enforcer, err := createV2Enforcer(cfg, log)
		if err != nil {
			return nil, fmt.Errorf("failed to create v2 casbin enforcer: %w", err)
		}
		authorizer.v2Enforcer = enforcer

		// Precompute group claim selectors for v2-only role extraction
		groupClaimSelectors := make([][]string, len(cfg.GroupsClaim))
		for i, claim := range cfg.GroupsClaim {
			groupClaimSelectors[i] = strings.Split(claim, ".")
		}
		authorizer.groupClaimSelectors = groupClaimSelectors

	default:
		return nil, fmt.Errorf("unsupported authorization version: %s", cfg.Version)
	}

	log.Info("casbin authorizer initialized",
		slog.String("version", authorizer.version),
		slog.Bool("supportsResourceAuth", authorizer.SupportsResourceAuthorization()),
	)

	return authorizer, nil
}

// createV2Enforcer creates a Casbin enforcer for the v2 model.
func createV2Enforcer(cfg AuthorizerConfig, log *logger.Logger) (*casbin.Enforcer, error) {
	// Use embedded v2 model or custom model from config
	modelStr := modelV2
	if cfg.Model != "" {
		modelStr = cfg.Model
	}

	m, err := casbinModel.NewModelFromString(modelStr)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 casbin model: %w", err)
	}

	// Build policy adapter
	var adapter interface{}
	if cfg.Adapter != nil {
		adapter = cfg.Adapter
	} else {
		// Build CSV policy for v2
		csvPolicy := buildV2Policy(cfg.PolicyConfig)
		adapter = stringadapter.NewAdapter(csvPolicy)
		log.Debug("v2 policy loaded", slog.String("policy", csvPolicy))
	}

	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 casbin enforcer: %w", err)
	}

	// Load policy from adapter
	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load v2 casbin policy: %w", err)
	}

	// Register custom dimension matching function
	e.AddFunction("dimensionMatch", dimensionMatchFunc)

	return e, nil
}

// buildV2Policy constructs the CSV policy for v2 model.
// Uses embedded default policy unless overridden by configuration.
func buildV2Policy(cfg PolicyConfig) string {
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

// Authorize implements Authorizer.Authorize.
func (a *CasbinAuthorizer) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationDecision, error) {
	switch a.version {
	case "v1":
		return a.authorizeV1(ctx, req)
	case "v2":
		return a.authorizeV2(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported authorization version: %s", a.version)
	}
}

// Version implements Authorizer.Version.
func (a *CasbinAuthorizer) Version() string {
	return a.version
}

// SupportsResourceAuthorization implements Authorizer.SupportsResourceAuthorization.
func (a *CasbinAuthorizer) SupportsResourceAuthorization() bool {
	return a.version == "v2"
}

// authorizeV1 performs legacy path-based authorization.
func (a *CasbinAuthorizer) authorizeV1(_ context.Context, req *AuthorizationRequest) (*AuthorizationDecision, error) {
	// Use existing Enforcer logic
	// Resource format varies by origin:
	// - gRPC paths (contain '.') need leading slash stripped: /kas.AccessService/Rewrap -> kas.AccessService/Rewrap
	// - HTTP paths (no dots) keep leading slash: /attributes -> /attributes
	resource := req.RPC
	if strings.Contains(req.RPC, ".") {
		// gRPC-style path: strip leading slash for v1 policy compatibility
		resource = strings.TrimPrefix(req.RPC, "/")
	}

	allowed := a.v1Enforcer.Enforce(req.Token, req.UserInfo, resource, req.Action)

	return &AuthorizationDecision{
		Allowed: allowed,
		Reason:  fmt.Sprintf("v1: %s %s", req.Action, resource),
		Mode:    AuthzModeV1,
	}, nil
}

// authorizeV2 performs RPC+dimensions authorization.
func (a *CasbinAuthorizer) authorizeV2(_ context.Context, req *AuthorizationRequest) (*AuthorizationDecision, error) {
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
	for _, subject := range subjects {
		allowed, err := a.v2Enforcer.Enforce(subject, req.RPC, dims)
		if err != nil {
			a.logger.Error("v2 enforcement error",
				slog.String("subject", subject),
				slog.String("rpc", req.RPC),
				slog.String("dims", dims),
				slog.Any("error", err),
			)
			continue
		}

		if allowed {
			a.logger.Debug("v2 authorization allowed",
				slog.String("subject", subject),
				slog.String("rpc", req.RPC),
				slog.String("dims", dims),
			)
			return &AuthorizationDecision{
				Allowed:       true,
				Reason:        fmt.Sprintf("v2: %s on %s with dims=%s", subject, req.RPC, dims),
				Mode:          AuthzModeV2,
				MatchedPolicy: subject,
			}, nil
		}
	}

	a.logger.Debug("v2 authorization denied",
		slog.Any("subjects", subjects),
		slog.String("rpc", req.RPC),
		slog.String("dims", dims),
	)

	return &AuthorizationDecision{
		Allowed: false,
		Reason:  fmt.Sprintf("v2: denied %s with dims=%s", req.RPC, dims),
		Mode:    AuthzModeV2,
	}, nil
}

// extractSubjects extracts roles/username from JWT token and userInfo.
func (a *CasbinAuthorizer) extractSubjects(req *AuthorizationRequest) []string {
	if a.v1Enforcer != nil {
		// Reuse v1 subject extraction logic
		return a.v1Enforcer.buildSubjectFromTokenAndUserInfo(req.Token, req.UserInfo)
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
		if claim, found := req.Token.Get(a.config.UserNameClaim); found {
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
func (a *CasbinAuthorizer) extractRolesFromToken(token jwt.Token) []string {
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
			claimMap, ok := claim.(map[string]interface{})
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

// extractRolesFromUserInfo extracts roles from a userInfo JSON ([]byte) based on the configured claim path.
func (a *CasbinAuthorizer) extractRolesFromUserInfo(userInfo []byte) []string {
	roles := make([]string, 0, defaultSubjectsCapacity)
	if len(userInfo) == 0 {
		return roles
	}
	var userInfoMap map[string]interface{}
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

// serializeDimensions converts AuthzResolverContext to canonical dimension string.
// Format: key1=value1&key2=value2 (keys sorted alphabetically)
// Returns "*" if no dimensions are present.
func serializeDimensions(ctx *AuthzResolverContext) string {
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
func dimensionMatchFunc(args ...interface{}) (interface{}, error) {
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
