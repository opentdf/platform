package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinModel "github.com/casbin/casbin/v2/model"
	stringadapter "github.com/casbin/casbin/v2/persist/string-adapter"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/authz"

	_ "embed"
)

var (
	rolePrefix          = "role:"
	defaultRole         = "unknown"
	ErrPermissionDenied = errors.New("permission denied")
)

type EnforcementResult struct {
	Allowed     bool
	CasbinAuthz CasbinAuthzLog
}

type CasbinAuthzLog struct {
	ConfiguredGroupsClaim string
	SubjectGroups         []string
}

//go:embed casbin_policy.csv
var builtinPolicy string

//go:embed casbin_model.conf
var defaultModel string

// Enforcer is the Casbin enforcer with platform-specific configuration
type Enforcer struct {
	*casbin.Enforcer
	Config CasbinConfig
	Policy string
	logger *logger.Logger

	isDefaultPolicy bool
	isDefaultModel  bool
	roleProvider    authz.RoleProvider
}

type casbinSubject []string

type CasbinConfig struct {
	PolicyConfig
	RoleProvider authz.RoleProvider
}

// NewCasbinEnforcer creates a new casbin enforcer
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

	roleProvider := c.RoleProvider
	if roleProvider == nil {
		roleProvider = newJWTClaimsRoleProvider(c.GroupsClaim, logger)
	}

	return &Enforcer{
		Enforcer:        e,
		Config:          c,
		Policy:          c.Csv,
		isDefaultPolicy: isDefaultPolicy,
		isDefaultModel:  isDefaultModel,
		logger:          logger,
		roleProvider:    roleProvider,
	}, nil
}

// casbinEnforce is a helper function to enforce the policy with casbin
// TODO implement a common type so this can be used for both http and grpc
func (e *Enforcer) Enforce(ctx context.Context, token jwt.Token, req authz.RoleRequest) (EnforcementResult, error) {
	// extract the role claim from the token
	s, subjectGroups, err := e.buildSubjectFromToken(ctx, token, req)
	result := EnforcementResult{
		CasbinAuthz: CasbinAuthzLog{
			ConfiguredGroupsClaim: e.Config.GroupsClaim,
			SubjectGroups:         subjectGroups,
		},
	}
	if err != nil {
		e.logger.Warn("role provider error", slog.Any("error", err))
		return result, ErrPermissionDenied
	}
	s = append(s, rolePrefix+defaultRole)

	resource := req.Resource
	action := req.Action
	for _, info := range s {
		allowed, err := e.Enforcer.Enforce(info, resource, action)
		if err != nil {
			e.logger.Error(
				"enforce by role error",
				slog.String("subject_info", info),
				slog.String("action", action),
				slog.String("resource", resource),
				slog.String("error", err.Error()),
			)
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
	return result, ErrPermissionDenied
}

func (e *Enforcer) buildSubjectFromToken(ctx context.Context, t jwt.Token, req authz.RoleRequest) (casbinSubject, []string, error) {
	var subject string
	info := casbinSubject{}

	e.logger.Debug("building subject from token")
	roles, err := e.roleProvider.Roles(ctx, t, req)
	if err != nil {
		return nil, nil, err
	}

	if claim, found := t.Get(e.Config.UserNameClaim); found {
		sub, ok := claim.(string)
		subject = sub
		if !ok {
			e.logger.Warn(
				"username claim not of type string",
				slog.String("claim", e.Config.UserNameClaim),
				slog.Any("claims", claim),
			)
			subject = ""
		}
	}
	info = append(info, roles...)
	info = append(info, subject)
	return info, append([]string(nil), roles...), nil
}

type v1EnforcerAdapter struct {
	enforcer *Enforcer
}

func (a v1EnforcerAdapter) Enforce(token jwt.Token, userInfo []byte, resource, action string) bool {
	result, err := a.enforcer.Enforce(context.Background(), token, authz.RoleRequest{
		Resource: resource,
		Action:   action,
	})
	return err == nil && result.Allowed
}

func (a v1EnforcerAdapter) BuildSubjectFromTokenAndUserInfo(token jwt.Token, userInfo []byte) []string {
	subjects, _, err := a.enforcer.buildSubjectFromToken(context.Background(), token, authz.RoleRequest{})
	if err != nil {
		a.enforcer.logger.Warn("failed to extract subjects", slog.Any("error", err))
		return nil
	}
	return subjects
}
