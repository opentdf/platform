package v1

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	internalauthz "github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	platformauthz "github.com/opentdf/platform/service/pkg/authz"

	_ "embed"
)

var (
	rolePrefix  = "role:"
	defaultRole = "unknown"
)

type EnforcementResult = internalauthz.EnforcementResult

//go:embed casbin_policy.csv
var builtinPolicy string

//go:embed casbin_model.conf
var defaultModel string

// Enforcer is the Casbin enforcer with platform-specific configuration
type Enforcer struct {
	casbinEnforcer   *casbin.Enforcer
	Config           casbinConfig
	Policy           string
	logger           *logger.Logger
	subjectExtractor internalauthz.SubjectExtractor
}

type casbinSubject []string

type casbinConfig struct {
	internalauthz.PolicyConfig
	Adapter      persist.Adapter
	RoleProvider platformauthz.RoleProvider
}

// newCasbinEnforcer creates a new casbin enforcer
func newCasbinEnforcer(c casbinConfig, logger *logger.Logger) (*Enforcer, error) {
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

	//nolint:staticcheck // Preserve deprecated RoleMap behavior for v1 compatibility.
	if c.RoleMap != nil {
		//nolint:staticcheck // Preserve deprecated RoleMap behavior for v1 compatibility.
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
	//nolint:staticcheck // Preserve deprecated RoleMap behavior for v1 compatibility.
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

	logger.Debug(
		"creating casbin enforcer",
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

	if c.RoleProvider == nil {
		c.RoleProvider = internalauthz.NewJWTClaimsRoleProvider(c.GroupsClaim, logger)
	}
	subjectExtractor := internalauthz.SubjectExtractor{
		UserNameClaim: c.UserNameClaim,
		ClientIDClaim: c.ClientIDClaim,
		RoleProvider:  c.RoleProvider,
		Logger:        logger,
	}

	return &Enforcer{
		casbinEnforcer:   e,
		Config:           c,
		Policy:           c.Csv,
		logger:           logger,
		subjectExtractor: subjectExtractor,
	}, nil
}

// enforce checks the request against the v1 Casbin policy.
// TODO implement a common type so this can be used for both http and grpc
func (e *Enforcer) enforce(ctx context.Context, token jwt.Token, req platformauthz.RoleRequest) (EnforcementResult, error) {
	// extract the role claim from the token
	s, _, err := e.buildSubjectFromToken(ctx, token, req)
	result := EnforcementResult{GroupsClaim: e.Config.GroupsClaim}
	if err != nil {
		e.logger.Warn("role provider error", slog.Any("error", err))
		return result, err
	}
	s = append(s, rolePrefix+defaultRole)

	resource := req.Resource
	action := req.Action
	for _, info := range s {
		allowed, err := e.casbinEnforcer.Enforce(info, resource, action)
		if err != nil {
			e.logger.Error(
				"enforce by role error",
				slog.String("subject_info", info),
				slog.String("action", action),
				slog.String("resource", resource),
				slog.String("error", err.Error()),
			)
			return result, err
		}
		if allowed {
			e.logger.Debug(
				"allowed by policy",
				slog.String("subject_info", info),
				slog.String("action", action),
				slog.String("resource", resource),
			)
			result.Allowed = true
			return result, nil
		}
	}
	e.logger.Debug(
		"permission denied by policy",
		slog.Any("subject_info", s),
		slog.String("action", action),
		slog.String("resource", resource),
	)
	return result, nil
}

func (e *Enforcer) buildSubjectFromToken(ctx context.Context, t jwt.Token, req platformauthz.RoleRequest) (casbinSubject, []string, error) {
	subjects, roles, err := e.subjectExtractor.BuildSubjectFromToken(ctx, t, req, false)
	if err != nil {
		return nil, nil, err
	}
	return casbinSubject(subjects), roles, nil
}
