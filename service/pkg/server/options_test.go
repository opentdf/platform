package server

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/authz"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithAuditPipeline(t *testing.T) {
	encoder := audit.EncoderFunc(func(context.Context, audit.Event) ([]audit.Emission, error) {
		return []audit.Emission{{Level: audit.LevelAudit, Message: "encoded"}}, nil
	})
	sink := audit.SinkFunc(func(context.Context, audit.Emission) error { return nil })

	cfg := WithAuditEncoder(encoder)(StartConfig{})
	cfg = WithAuditSink(sink)(cfg)

	require.NotNil(t, cfg.auditEncoder)
	require.NotNil(t, cfg.auditSink)
}

// noopInterceptor returns a connect.UnaryInterceptorFunc that passes through.
func noopInterceptor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			return next(ctx, req)
		}
	})
}

func TestWithConnectInterceptors(t *testing.T) {
	tests := []struct {
		name      string
		apply     func(*StartConfig)
		wantCount int
	}{
		{
			name: "single interceptor is appended",
			apply: func(c *StartConfig) {
				*c = WithConnectInterceptors(noopInterceptor())(*c)
			},
			wantCount: 1,
		},
		{
			name: "multiple interceptors are appended in order",
			apply: func(c *StartConfig) {
				*c = WithConnectInterceptors(noopInterceptor(), noopInterceptor(), noopInterceptor())(*c)
			},
			wantCount: 3,
		},
		{
			name: "calling twice accumulates interceptors",
			apply: func(c *StartConfig) {
				*c = WithConnectInterceptors(noopInterceptor())(*c)
				*c = WithConnectInterceptors(noopInterceptor(), noopInterceptor())(*c)
			},
			wantCount: 3,
		},
		{
			name: "empty call leaves slice nil",
			apply: func(c *StartConfig) {
				*c = WithConnectInterceptors()(*c)
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg StartConfig
			tt.apply(&cfg)

			if tt.wantCount == 0 {
				assert.Nil(t, cfg.extraConnectInterceptors)
			} else {
				require.Len(t, cfg.extraConnectInterceptors, tt.wantCount)
			}
			// Must not affect IPC interceptors
			assert.Nil(t, cfg.extraIPCInterceptors)
		})
	}
}

func TestWithExternalInterceptorFactories(t *testing.T) {
	factory := InterceptorFactory{
		Name: "test",
		Factory: func(InterceptorParams) (connect.Interceptor, error) {
			return noopInterceptor(), nil
		},
	}

	tests := []struct {
		name      string
		apply     func(*StartConfig)
		wantCount int
	}{
		{
			name: "single factory is appended",
			apply: func(c *StartConfig) {
				*c = WithExternalInterceptorFactories(factory)(*c)
			},
			wantCount: 1,
		},
		{
			name: "multiple factories are appended in order",
			apply: func(c *StartConfig) {
				*c = WithExternalInterceptorFactories(factory, factory, factory)(*c)
			},
			wantCount: 3,
		},
		{
			name: "calling twice accumulates factories",
			apply: func(c *StartConfig) {
				*c = WithExternalInterceptorFactories(factory)(*c)
				*c = WithExternalInterceptorFactories(factory, factory)(*c)
			},
			wantCount: 3,
		},
		{
			name: "empty call leaves slice nil",
			apply: func(c *StartConfig) {
				*c = WithExternalInterceptorFactories()(*c)
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg StartConfig
			tt.apply(&cfg)

			if tt.wantCount == 0 {
				assert.Nil(t, cfg.externalInterceptorFactories)
			} else {
				require.Len(t, cfg.externalInterceptorFactories, tt.wantCount)
			}
			assert.Nil(t, cfg.extraConnectInterceptors)
			assert.Nil(t, cfg.extraIPCInterceptors)
		})
	}
}

func TestExternalInterceptorFactoryReceivesNamedConfig(t *testing.T) {
	type auditConfig struct {
		Enabled bool     `mapstructure:"enabled"`
		Headers []string `mapstructure:"headers"`
	}

	factory := InterceptorFactory{
		Name: "audit_enrichment",
		Factory: func(params InterceptorParams) (connect.Interceptor, error) {
			var cfg auditConfig
			if err := mapstructure.Decode(params.Config, &cfg); err != nil {
				return nil, err
			}

			require.Equal(t, auditConfig{
				Enabled: true,
				Headers: []string{
					"x-request-id",
					"x-forwarded-for",
				},
			}, cfg)

			return noopInterceptor(), nil
		},
	}

	params := newInterceptorParams(factory, &config.Config{
		Interceptors: config.InterceptorsMap{
			"audit_enrichment": {
				"enabled": true,
				"headers": []string{
					"x-request-id",
					"x-forwarded-for",
				},
			},
		},
	}, nil, nil)

	interceptor, err := factory.Factory(params)
	require.NoError(t, err)
	require.NotNil(t, interceptor)
}

func TestValidateExternalInterceptorFactoryRequiresName(t *testing.T) {
	err := validateExternalInterceptorFactory(InterceptorFactory{})

	require.ErrorIs(t, err, ErrExternalInterceptorFactoryNameRequired)
}

func TestValidateExternalInterceptorFactoryRequiresFactoryFunc(t *testing.T) {
	err := validateExternalInterceptorFactory(InterceptorFactory{Name: "test"})

	require.ErrorIs(t, err, ErrExternalInterceptorFactoryFuncRequired)
}

func TestWithIPCInterceptors(t *testing.T) {
	tests := []struct {
		name      string
		apply     func(*StartConfig)
		wantCount int
	}{
		{
			name: "single interceptor is appended",
			apply: func(c *StartConfig) {
				*c = WithIPCInterceptors(noopInterceptor())(*c)
			},
			wantCount: 1,
		},
		{
			name: "multiple interceptors are appended in order",
			apply: func(c *StartConfig) {
				*c = WithIPCInterceptors(noopInterceptor(), noopInterceptor(), noopInterceptor())(*c)
			},
			wantCount: 3,
		},
		{
			name: "calling twice accumulates interceptors",
			apply: func(c *StartConfig) {
				*c = WithIPCInterceptors(noopInterceptor())(*c)
				*c = WithIPCInterceptors(noopInterceptor(), noopInterceptor())(*c)
			},
			wantCount: 3,
		},
		{
			name: "empty call leaves slice nil",
			apply: func(c *StartConfig) {
				*c = WithIPCInterceptors()(*c)
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg StartConfig
			tt.apply(&cfg)

			if tt.wantCount == 0 {
				assert.Nil(t, cfg.extraIPCInterceptors)
			} else {
				require.Len(t, cfg.extraIPCInterceptors, tt.wantCount)
			}
			// Must not affect Connect interceptors
			assert.Nil(t, cfg.extraConnectInterceptors)
		})
	}
}

func TestWithConnectAndIPCInterceptorsTogether(t *testing.T) {
	var cfg StartConfig
	cfg = WithConnectInterceptors(noopInterceptor(), noopInterceptor())(cfg)
	cfg = WithIPCInterceptors(noopInterceptor())(cfg)

	require.Len(t, cfg.extraConnectInterceptors, 2, "expected 2 connect interceptors")
	require.Len(t, cfg.extraIPCInterceptors, 1, "expected 1 IPC interceptor")

	// Verify slices are independent (not sharing backing array)
	assert.NotSame(
		t,
		&cfg.extraConnectInterceptors[0],
		&cfg.extraIPCInterceptors[0],
		"connect and IPC interceptor slices must be independent",
	)
}

type noopRoleProvider struct{}

func (noopRoleProvider) Roles(_ context.Context, _ jwt.Token, _ authz.RoleRequest) ([]string, error) {
	return nil, nil
}

func TestWithAuthZRoleProvider(t *testing.T) {
	var cfg StartConfig
	cfg = WithAuthZRoleProvider(noopRoleProvider{})(cfg)

	require.NotNil(t, cfg.authzRoleProvider)
	assert.Nil(t, cfg.authzRoleProviderFactories)
}

func TestWithAuthZRoleProviderFactory(t *testing.T) {
	var cfg StartConfig
	cfg = WithAuthZRoleProviderFactory("mock", func(_ context.Context, _ authz.ProviderConfig, _ *logger.Logger) (authz.RoleProvider, error) {
		return noopRoleProvider{}, nil
	})(cfg)

	require.NotNil(t, cfg.authzRoleProviderFactories)
	require.Contains(t, cfg.authzRoleProviderFactories, "mock")
}

const testAuditTypeBase = 1000

func TestWithAdditionalAuditTypeRegistrations(t *testing.T) {
	var cfg StartConfig

	objectTypesOne := make(map[audit.ObjectType]string)
	objectTypesOne[audit.ObjectType(testAuditTypeBase)] = "custom_object_1"

	actionTypes := make(map[audit.ActionType]string)
	actionTypes[audit.ActionType(testAuditTypeBase+1)] = "custom_action_1"

	cfg = WithAdditionalAuditTypeRegistrations(audit.TypeRegistrations{
		ObjectTypes: objectTypesOne,
		ActionTypes: actionTypes,
	})(cfg)

	objectTypesTwo := make(map[audit.ObjectType]string)
	objectTypesTwo[audit.ObjectType(testAuditTypeBase+2)] = "custom_object_2"

	actionResults := make(map[audit.ActionResult]string)
	actionResults[audit.ActionResult(testAuditTypeBase+3)] = "custom_result_1"

	cfg = WithAdditionalAuditTypeRegistrations(audit.TypeRegistrations{
		ObjectTypes:   objectTypesTwo,
		ActionResults: actionResults,
	})(cfg)

	require.Len(t, cfg.auditTypeRegistrations.ObjectTypes, 2)
	require.Len(t, cfg.auditTypeRegistrations.ActionTypes, 1)
	require.Len(t, cfg.auditTypeRegistrations.ActionResults, 1)
	require.Empty(t, cfg.auditTypeRegistrationConflicts)
	require.Len(t, objectTypesOne, 1)
	require.Len(t, objectTypesTwo, 1)
	require.Len(t, actionTypes, 1)
	require.Len(t, actionResults, 1)
	assert.Equal(t, "custom_object_1", cfg.auditTypeRegistrations.ObjectTypes[audit.ObjectType(testAuditTypeBase)])
	assert.Equal(t, "custom_object_2", cfg.auditTypeRegistrations.ObjectTypes[audit.ObjectType(testAuditTypeBase+2)])
	assert.Equal(t, "custom_action_1", cfg.auditTypeRegistrations.ActionTypes[audit.ActionType(testAuditTypeBase+1)])
	assert.Equal(t, "custom_result_1", cfg.auditTypeRegistrations.ActionResults[audit.ActionResult(testAuditTypeBase+3)])
	assert.Equal(t, "custom_object_1", objectTypesOne[audit.ObjectType(testAuditTypeBase)])
	assert.Equal(t, "custom_object_2", objectTypesTwo[audit.ObjectType(testAuditTypeBase+2)])
	assert.Equal(t, "custom_action_1", actionTypes[audit.ActionType(testAuditTypeBase+1)])
	assert.Equal(t, "custom_result_1", actionResults[audit.ActionResult(testAuditTypeBase+3)])
}

func TestWithAdditionalAuditTypeRegistrationsDetectsConflicts(t *testing.T) {
	const (
		conflictingObjectType   = audit.ObjectType(testAuditTypeBase)
		conflictingActionType   = audit.ActionType(testAuditTypeBase + 1)
		conflictingActionResult = audit.ActionResult(testAuditTypeBase + 2)
	)

	// Maps are built with make + assignment rather than literals so the exhaustive
	// linter does not require every enum key.
	registrations := func(suffix string) audit.TypeRegistrations {
		objectTypes := make(map[audit.ObjectType]string)
		objectTypes[conflictingObjectType] = "custom_object_" + suffix
		actionTypes := make(map[audit.ActionType]string)
		actionTypes[conflictingActionType] = "custom_action_" + suffix
		actionResults := make(map[audit.ActionResult]string)
		actionResults[conflictingActionResult] = "custom_result_" + suffix
		return audit.TypeRegistrations{
			ObjectTypes:   objectTypes,
			ActionTypes:   actionTypes,
			ActionResults: actionResults,
		}
	}

	var cfg StartConfig

	cfg = WithAdditionalAuditTypeRegistrations(registrations("1"))(cfg)
	cfg = WithAdditionalAuditTypeRegistrations(registrations("conflict"))(cfg)

	require.Len(t, cfg.auditTypeRegistrationConflicts, 3)
	conflictsByCategory := make(map[string]auditTypeRegistrationConflict, len(cfg.auditTypeRegistrationConflicts))
	for _, conflict := range cfg.auditTypeRegistrationConflicts {
		conflictsByCategory[conflict.Category] = conflict
	}

	for _, tc := range []struct {
		category     string
		key          int
		existingName string
		newName      string
	}{
		{category: "object_type", key: int(conflictingObjectType), existingName: "custom_object_1", newName: "custom_object_conflict"},
		{category: "action_type", key: int(conflictingActionType), existingName: "custom_action_1", newName: "custom_action_conflict"},
		{category: "action_result", key: int(conflictingActionResult), existingName: "custom_result_1", newName: "custom_result_conflict"},
	} {
		t.Run(tc.category, func(t *testing.T) {
			conflict, ok := conflictsByCategory[tc.category]
			require.True(t, ok, "expected a %s conflict", tc.category)
			assert.Equal(t, tc.key, conflict.Key)
			assert.Equal(t, tc.existingName, conflict.ExistingName)
			assert.Equal(t, tc.newName, conflict.NewName)
		})
	}

	// The first registration wins for every category.
	assert.Equal(t, "custom_object_1", cfg.auditTypeRegistrations.ObjectTypes[conflictingObjectType])
	assert.Equal(t, "custom_action_1", cfg.auditTypeRegistrations.ActionTypes[conflictingActionType])
	assert.Equal(t, "custom_result_1", cfg.auditTypeRegistrations.ActionResults[conflictingActionResult])
}

func TestFormatAuditTypeRegistrationConflictsIsDeterministic(t *testing.T) {
	conflicts := []auditTypeRegistrationConflict{
		{Category: "object_type", Key: 2, ExistingName: "object_two", NewName: "other_object_two"},
		{Category: "action_type", Key: 5, ExistingName: "action_five", NewName: "other_action_five"},
		{Category: "object_type", Key: 1, ExistingName: "object_one", NewName: "other_object_one"},
		{Category: "action_result", Key: 3, ExistingName: "result_three", NewName: "other_result_three"},
	}

	expected := `action_result 3: "result_three" vs "other_result_three"; ` +
		`action_type 5: "action_five" vs "other_action_five"; ` +
		`object_type 1: "object_one" vs "other_object_one"; ` +
		`object_type 2: "object_two" vs "other_object_two"`

	assert.Equal(t, expected, formatAuditTypeRegistrationConflicts(conflicts))

	// Input order must not change the message, and the input must not be reordered.
	shuffled := []auditTypeRegistrationConflict{conflicts[3], conflicts[0], conflicts[2], conflicts[1]}
	assert.Equal(t, expected, formatAuditTypeRegistrationConflicts(shuffled))
	assert.Equal(t, "object_type", conflicts[0].Category)
	assert.Equal(t, 2, conflicts[0].Key)
}

func TestFormatAuditTypeRegistrationConflictsEmpty(t *testing.T) {
	assert.Empty(t, formatAuditTypeRegistrationConflicts(nil))
}
