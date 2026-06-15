// Package casbin provides a Casbin-based authorization implementation.
package casbin

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"
)

//go:embed model.conf
var modelV2 string

//go:embed policy.csv
var builtinPolicyV2 string

const (
	// rolePrefix is the prefix for role subjects in casbin policies.
	rolePrefix = "role:"
	// disallowedDimensionKeyChars are separators used in dimension serialization.
	disallowedDimensionKeyChars = "=&"
	// defaultRole is the role assigned when no roles are found.
	defaultRole = "unknown"
	// dimensionMatchArgCount is the expected argument count for dimensionMatch function.
	dimensionMatchArgCount = 2
	// kvPairParts is the expected number of parts when splitting key=value pairs.
	kvPairParts = 2
)

var dimensionValueEscaper = strings.NewReplacer(
	"%", "%25",
	"&", "%26",
	"*", "%2A",
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

	subjectExtractor authz.SubjectExtractor
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
		v1Enforcer: cfg.Enforcer,
	}

	log.Info(
		"casbin authorizer initialized",
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

	roleProvider := cfg.RoleProvider
	if roleProvider == nil {
		roleProvider = authz.NewJWTClaimsRoleProvider(cfg.GroupsClaim, log)
	}

	authorizer := &Authorizer{
		version:    "v2",
		logger:     log,
		v2Enforcer: enforcer,
		subjectExtractor: authz.SubjectExtractor{
			UserNameClaim: cfg.UserNameClaim,
			ClientIDClaim: cfg.ClientIDClaim,
			RoleProvider:  roleProvider,
			UsePrefix:     true,
			Logger:        log,
		},
	}

	log.Info(
		"casbin authorizer initialized",
		slog.String("version", authorizer.version),
		slog.Bool("supportsResourceAuth", authorizer.SupportsResourceAuthorization()),
	)

	return authorizer, nil
}

// createV2EnforcerFromConfig creates a Casbin enforcer for the v2 model
// using the internal CasbinV2Config type.
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

	// Build policy adapter
	var adapter persist.Adapter
	if cfg.Adapter != nil {
		adapter = cfg.Adapter
	} else {
		// Build CSV policy for v2
		csvPolicy := buildV2PolicyFromConfig(cfg)
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
func (a *Authorizer) authorizeV1(ctx context.Context, req *authz.Request) (*authz.Decision, error) {
	resource := req.RPC
	if strings.Contains(req.RPC, ".") {
		// gRPC-style path (contains '.'): strip leading slash for v1 policy compatibility
		// Example: /kas.AccessService/Rewrap -> kas.AccessService/Rewrap
		resource = strings.TrimPrefix(req.RPC, "/")
	}
	// HTTP paths (no '.') keep their leading slash
	// Example: /kas/v2/rewrap -> /kas/v2/rewrap

	allowed, _, err := a.v1Enforcer.Enforce(ctx, req.Token, platformauthz.RoleRequest{
		Resource: resource,
		Action:   req.Action,
	})
	if err != nil {
		if !allowed {
			return &authz.Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("v1: denied %s %s", req.Action, resource),
				Mode:    authz.ModeV1,
			}, nil
		}
		return nil, fmt.Errorf("v1 authorization system error: %w", err)
	}

	return &authz.Decision{
		Allowed: allowed,
		Reason:  fmt.Sprintf("v1: %s %s", req.Action, resource),
		Mode:    authz.ModeV1,
	}, nil
}

// authorizeV2 performs RPC+dimensions authorization.
func (a *Authorizer) authorizeV2(ctx context.Context, req *authz.Request) (*authz.Decision, error) {
	subjects, _, err := a.subjectExtractor.BuildSubjectFromToken(ctx, req.Token, platformauthz.RoleRequest{})
	if err != nil {
		a.logger.Warn("role provider error", slog.Any("error", err))
		return &authz.Decision{
			Allowed: false,
			Reason:  "v2: denied due to role provider error",
			Mode:    authz.ModeV2,
		}, nil
	}

	// If no subjects found, use default role
	if len(subjects) == 0 {
		subjects = append(subjects, rolePrefix+defaultRole)
	}

	// Serialize dimensions to canonical string
	dims, err := serializeDimensions(req.ResourceContext)
	if err != nil {
		return nil, fmt.Errorf("v2 authorization invalid resource dimensions: %w", err)
	}

	a.logger.Debug(
		"v2 authorization check",
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
			a.logger.Error(
				"v2 enforcement error",
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
			a.logger.Debug(
				"v2 authorization allowed",
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

	a.logger.Debug(
		"v2 authorization denied",
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

// serializeDimensions converts ResolverContext to canonical dimension string.
// Format: key1=value1&key2=value2 (keys sorted alphabetically)
// Returns "*" if no dimensions are present.
func serializeDimensions(ctx *authz.ResolverContext) (string, error) {
	if ctx == nil || len(ctx.Resources) == 0 {
		return "*", nil
	}

	// Collect all dimensions from all resources
	allDims := make(map[string]string)
	for _, resource := range ctx.Resources {
		if resource == nil {
			continue
		}
		for k, v := range *resource {
			if !isValidDimensionKey(k) {
				return "", fmt.Errorf("invalid dimension key %q: keys must not contain any of %q", k, disallowedDimensionKeyChars)
			}
			if existing, exists := allDims[k]; exists && existing != v {
				return "", fmt.Errorf("conflicting values for dimension key %q: %q != %q", k, existing, v)
			}
			allDims[k] = v
		}
	}

	if len(allDims) == 0 {
		return "*", nil
	}

	// Sort keys for canonical ordering
	keys := make([]string, 0, len(allDims))
	for k := range allDims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical string, percent-encoding only the characters that conflict
	// with dimension parsing. '%' must be escaped first because it introduces an
	// escape sequence, and '&' must be escaped because it separates key-value
	// pairs. '*' is escaped because raw '*' is the policy wildcard. '=' can remain
	// readable because pair parsing splits on the first '='.
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, escapeDimensionValue(allDims[k])))
	}

	return strings.Join(parts, "&"), nil
}

func escapeDimensionValue(value string) string {
	return dimensionValueEscaper.Replace(value)
}

func unescapeDimensionValue(value string) (string, error) {
	return url.PathUnescape(value)
}

// isValidDimensionKey reports whether a dimension key can be safely serialized.
func isValidDimensionKey(key string) bool {
	if key == "" {
		return false
	}

	return !strings.ContainsAny(key, disallowedDimensionKeyChars)
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
	reqMap, ok := parseDimensions(reqDims)
	if !ok {
		return false
	}

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
		if !isValidDimensionKey(key) {
			return false
		}
		policyWildcard := policyVal == "*"
		if !policyWildcard {
			unescapedVal, err := unescapeDimensionValue(policyVal)
			if err != nil {
				return false
			}
			policyVal = unescapedVal
		}

		reqVal, exists := reqMap[key]
		if !exists {
			// Policy requires a dimension that request doesn't have
			return false
		}

		// Wildcard matches any value
		if !policyWildcard && policyVal != reqVal {
			return false
		}
	}

	return true
}

// parseDimensions parses a dimension string into a map.
func parseDimensions(dims string) (map[string]string, bool) {
	result := make(map[string]string)
	if dims == "*" || dims == "" {
		return result, true
	}

	for _, pair := range strings.Split(dims, "&") {
		if pair == "" {
			continue
		}

		kv := strings.SplitN(pair, "=", kvPairParts)
		if len(kv) != kvPairParts {
			return nil, false
		}
		if !isValidDimensionKey(kv[0]) {
			return nil, false
		}
		unescapedVal, err := unescapeDimensionValue(kv[1])
		if err != nil {
			return nil, false
		}
		result[kv[0]] = unescapedVal
	}
	return result, true
}
