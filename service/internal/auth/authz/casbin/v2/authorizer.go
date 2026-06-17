// Package v2 provides the resource/dimension-based Casbin authorization implementation.
package v2

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

var errLoggerRequired = errors.New("logger is required for v2 casbin authorizer")

// Authorizer implements v2 authz.Authorizer using Casbin.
type Authorizer struct {
	// issuer is the configured token issuer for role provider requests.
	issuer string

	// groupsClaim is the configured claim used for group extraction.
	groupsClaim string

	enforcer *casbin.Enforcer

	logger *logger.Logger

	subjectExtractor authz.SubjectExtractor
}

// NewAuthorizer creates a v2 (RPC+dimensions) Casbin authorizer.
func NewAuthorizer(cfg authz.CasbinV2Config, log *logger.Logger) (*Authorizer, error) {
	if log == nil {
		return nil, errLoggerRequired
	}

	enforcer, err := createV2EnforcerFromConfig(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to create v2 casbin enforcer: %w", err)
	}

	roleProvider := cfg.RoleProvider
	if roleProvider == nil {
		roleProvider = authz.NewJWTClaimsRoleProvider(cfg.GroupsClaim, log)
	}

	authorizer := &Authorizer{
		issuer:      cfg.Issuer,
		groupsClaim: cfg.GroupsClaim,
		logger:      log,
		enforcer:    enforcer,
		subjectExtractor: authz.SubjectExtractor{
			UserNameClaim: cfg.UserNameClaim,
			ClientIDClaim: cfg.ClientIDClaim,
			RoleProvider:  roleProvider,
			Logger:        log,
		},
	}

	log.Info(
		"casbin authorizer initialized",
		slog.String("version", authorizer.Version()),
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
	if req == nil {
		return nil, errors.New("authorization request is required")
	}
	if req.Token == nil {
		return nil, errors.New("authorization token is required")
	}

	return a.authorize(ctx, req)
}

// Version implements authz.Authorizer.Version.
func (a *Authorizer) Version() string {
	return string(authz.ModeV2)
}

// SupportsResourceAuthorization implements authz.Authorizer.SupportsResourceAuthorization.
func (a *Authorizer) SupportsResourceAuthorization() bool {
	return true
}

// authorize performs RPC+dimensions authorization.
func (a *Authorizer) authorize(ctx context.Context, req *authz.Request) (*authz.Decision, error) {
	roleReq := platformauthz.RoleRequest{
		Issuer:   a.issuer,
		Resource: req.RPC,
		Action:   req.Action,
	}
	subjects, _, err := a.subjectExtractor.BuildSubjectFromToken(ctx, req.Token, roleReq, true)
	if err != nil {
		return nil, fmt.Errorf("v2 authorization subject extraction error: %w", err)
	}

	// If no subjects found, use default role
	if len(subjects) == 0 {
		subjects = append(subjects, rolePrefix+defaultRole)
	}

	resourceDims, err := serializeDimensions(req.ResourceContext)
	if err != nil {
		return nil, fmt.Errorf("v2 authorization invalid resource dimensions: %w", err)
	}

	a.logger.Debug(
		"v2 authorization check",
		slog.Any("subjects", subjects),
		slog.String("rpc", req.RPC),
		slog.Any("resource_dims", resourceDims),
	)

	var matchedSubject string
	// Casbin BatchEnforce/BulkEnforce could be investigated for efficiency if
	// resource or subject counts grow.
	for _, dims := range resourceDims {
		allowed, allowedSubject, enforcementErr := a.authorizeResource(req.RPC, dims, subjects)
		if enforcementErr != nil {
			return nil, fmt.Errorf("v2 authorization system error: %w", enforcementErr)
		}
		if !allowed {
			return &authz.Decision{
				Allowed: false,
				Reason:  fmt.Sprintf("v2: denied %s with dims=%s", req.RPC, dims),
				Mode:    authz.ModeV2,
				Metadata: authz.DecisionMetadata{
					GroupsClaim: a.groupsClaim,
				},
			}, nil
		}
		if matchedSubject == "" {
			matchedSubject = allowedSubject
		}
	}

	return &authz.Decision{
		Allowed:       true,
		Reason:        fmt.Sprintf("v2: %s on %s", matchedSubject, req.RPC),
		Mode:          authz.ModeV2,
		MatchedPolicy: matchedSubject,
		Metadata: authz.DecisionMetadata{
			GroupsClaim: a.groupsClaim,
		},
	}, nil
}

func (a *Authorizer) authorizeResource(rpc, dims string, subjects []string) (bool, string, error) {
	var (
		anyCheckedSuccessfully bool
		lastErr                error
	)

	for _, subject := range subjects {
		allowed, err := a.enforcer.Enforce(subject, rpc, dims)
		if err != nil {
			a.logger.Error(
				"v2 enforcement error",
				slog.String("subject", subject),
				slog.String("rpc", rpc),
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
				slog.String("rpc", rpc),
				slog.String("dims", dims),
			)
			return true, subject, nil
		}
	}

	if !anyCheckedSuccessfully && lastErr != nil {
		return false, "", lastErr
	}

	a.logger.Debug(
		"v2 authorization denied",
		slog.Any("subjects", subjects),
		slog.String("rpc", rpc),
		slog.String("dims", dims),
	)
	return false, "", nil
}

// serializeDimensions converts ResolverContext resources to canonical dimension strings.
// Each non-empty resource is serialized independently so each resource's dimensions
// are evaluated with all-of semantics.
// Format: key1=value1&key2=value2 (keys sorted alphabetically)
// Returns ["*"] if no dimensions are present.
func serializeDimensions(ctx *authz.ResolverContext) ([]string, error) {
	if ctx == nil || len(ctx.Resources) == 0 {
		return []string{"*"}, nil
	}

	dims := make([]string, 0, len(ctx.Resources))
	for _, resource := range ctx.Resources {
		if resource == nil || len(*resource) == 0 {
			continue
		}

		serialized, err := serializeResource(resource)
		if err != nil {
			return nil, err
		}
		dims = append(dims, serialized)
	}

	if len(dims) == 0 {
		return []string{"*"}, nil
	}

	return dims, nil
}

func serializeResource(resource *authz.ResolverResource) (string, error) {
	keys := make([]string, 0, len(*resource))
	for k := range *resource {
		if !isValidDimensionKey(k) {
			return "", fmt.Errorf("invalid dimension key %q: keys must not contain any of %q", k, disallowedDimensionKeyChars)
		}
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
		parts = append(parts, fmt.Sprintf("%s=%s", k, escapeDimensionValue((*resource)[k])))
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
