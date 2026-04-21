package migrations

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/charmbracelet/huh"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockMigrationHandler implements MigrationHandler for testing.
type MockMigrationHandler struct {
	Resources      []*policy.RegisteredResource
	ResourceValues map[string][]*policy.RegisteredResourceValue // keyed by resource ID
	Namespaces     []*policy.Namespace

	// Track calls
	CreatedResources      []createdResourceCall
	CreatedResourceValues []createdResourceValueCall
	DeletedResourceIDs    []string

	// Control behavior
	CreateResourceErr      error
	CreateResourceValueErr error
	DeleteResourceErr      error
}

type createdResourceCall struct {
	Namespace string
	Name      string
	Values    []string
	Metadata  *common.MetadataMutable
}

type createdResourceValueCall struct {
	ResourceID          string
	Value               string
	ActionAttributeVals []*registeredresources.ActionAttributeValue
	Metadata            *common.MetadataMutable
}

func (m *MockMigrationHandler) ListRegisteredResources(_ context.Context, limit, offset int32, _ string) (*registeredresources.ListRegisteredResourcesResponse, error) {
	start := int(offset)
	if start >= len(m.Resources) {
		return &registeredresources.ListRegisteredResourcesResponse{}, nil
	}
	end := start + int(limit)
	if end > len(m.Resources) {
		end = len(m.Resources)
	}
	return &registeredresources.ListRegisteredResourcesResponse{
		Resources: m.Resources[start:end],
	}, nil
}

func (m *MockMigrationHandler) ListRegisteredResourceValues(_ context.Context, resourceID string, limit, offset int32) (*registeredresources.ListRegisteredResourceValuesResponse, error) {
	values := m.ResourceValues[resourceID]
	start := int(offset)
	if start >= len(values) {
		return &registeredresources.ListRegisteredResourceValuesResponse{}, nil
	}
	end := start + int(limit)
	if end > len(values) {
		end = len(values)
	}
	return &registeredresources.ListRegisteredResourceValuesResponse{
		Values: values[start:end],
	}, nil
}

func (m *MockMigrationHandler) CreateRegisteredResource(_ context.Context, namespace, name string, values []string, metadata *common.MetadataMutable) (*policy.RegisteredResource, error) {
	m.CreatedResources = append(m.CreatedResources, createdResourceCall{
		Namespace: namespace,
		Name:      name,
		Values:    values,
		Metadata:  metadata,
	})
	if m.CreateResourceErr != nil {
		return nil, m.CreateResourceErr
	}

	// Build response with values
	rrValues := make([]*policy.RegisteredResourceValue, 0, len(values))
	for i, v := range values {
		rrValues = append(rrValues, &policy.RegisteredResourceValue{
			Id:    fmt.Sprintf("new-value-%d", i),
			Value: v,
		})
	}

	return &policy.RegisteredResource{
		Id:     "new-resource-id",
		Name:   name,
		Values: rrValues,
		Namespace: &policy.Namespace{
			Id:  "ns-id",
			Fqn: namespace,
		},
	}, nil
}

func (m *MockMigrationHandler) CreateRegisteredResourceValue(_ context.Context, resourceID string, value string, actionAttributeValues []*registeredresources.ActionAttributeValue, metadata *common.MetadataMutable) (*policy.RegisteredResourceValue, error) {
	m.CreatedResourceValues = append(m.CreatedResourceValues, createdResourceValueCall{
		ResourceID:          resourceID,
		Value:               value,
		ActionAttributeVals: actionAttributeValues,
		Metadata:            metadata,
	})
	if m.CreateResourceValueErr != nil {
		return nil, m.CreateResourceValueErr
	}
	return &policy.RegisteredResourceValue{
		Id:    "new-recreated-value-id",
		Value: value,
	}, nil
}

func (m *MockMigrationHandler) DeleteRegisteredResource(_ context.Context, id string) error {
	m.DeletedResourceIDs = append(m.DeletedResourceIDs, id)
	if m.DeleteResourceErr != nil {
		return m.DeleteResourceErr
	}
	return nil
}

func (m *MockMigrationHandler) ListNamespaces(_ context.Context, _ common.ActiveStateEnum, limit, offset int32) (*namespaces.ListNamespacesResponse, error) {
	start := int(offset)
	if start >= len(m.Namespaces) {
		return &namespaces.ListNamespacesResponse{}, nil
	}
	end := start + int(limit)
	if end > len(m.Namespaces) {
		end = len(m.Namespaces)
	}
	return &namespaces.ListNamespacesResponse{
		Namespaces: m.Namespaces[start:end],
	}, nil
}

// MockMigrationPrompter implements MigrationPrompter for testing.
type MockMigrationPrompter struct {
	ConfirmBackupResponse bool
	ConfirmBackupErr      error

	BatchNamespaceResponse string
	BatchNamespaceErr      error

	// ResourceNamespaceResponses are returned in order, one per call to SelectResourceNamespace.
	ResourceNamespaceResponses []string
	ResourceNamespaceErrs      []error
	resourceNamespaceCallIndex int

	// ConfirmResourceNamespaceResponses are returned in order, one per call.
	ConfirmResourceNamespaceResponses []string
	ConfirmResourceNamespaceErrs      []error
	confirmResourceNamespaceCallIndex int
}

func (m *MockMigrationPrompter) ConfirmBackup() (bool, error) {
	return m.ConfirmBackupResponse, m.ConfirmBackupErr
}

func (m *MockMigrationPrompter) SelectBatchNamespace(_ []*policy.Namespace) (string, error) {
	return m.BatchNamespaceResponse, m.BatchNamespaceErr
}

func (m *MockMigrationPrompter) SelectResourceNamespace(_ string, _ []*policy.Namespace) (string, error) {
	i := m.resourceNamespaceCallIndex
	m.resourceNamespaceCallIndex++

	var err error
	if i < len(m.ResourceNamespaceErrs) {
		err = m.ResourceNamespaceErrs[i]
	}
	if err != nil {
		return "", err
	}

	if i < len(m.ResourceNamespaceResponses) {
		return m.ResourceNamespaceResponses[i], nil
	}
	return "", errors.New("no more mock responses configured")
}

func (m *MockMigrationPrompter) ConfirmResourceNamespace(_ string, _ string) (string, error) {
	i := m.confirmResourceNamespaceCallIndex
	m.confirmResourceNamespaceCallIndex++

	var err error
	if i < len(m.ConfirmResourceNamespaceErrs) {
		err = m.ConfirmResourceNamespaceErrs[i]
	}
	if err != nil {
		return "", err
	}

	if i < len(m.ConfirmResourceNamespaceResponses) {
		return m.ConfirmResourceNamespaceResponses[i], nil
	}
	return "", errors.New("no more mock ConfirmResourceNamespace responses configured")
}

// Helper to build an AAV with a known namespace via the Attribute chain.
func aavWithNamespace(nsFQN string) *policy.RegisteredResourceValue_ActionAttributeValue {
	return &policy.RegisteredResourceValue_ActionAttributeValue{
		Action: &policy.Action{Id: "action-1"},
		AttributeValue: &policy.Value{
			Id: "av-1",
			Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{Fqn: nsFQN},
			},
		},
	}
}

// Helper to build an AAV with namespace derivable only from Value FQN.
func aavWithFQNOnly(valueFQN string) *policy.RegisteredResourceValue_ActionAttributeValue {
	return &policy.RegisteredResourceValue_ActionAttributeValue{
		Action:         &policy.Action{Id: "action-1"},
		AttributeValue: &policy.Value{Id: "av-1", Fqn: valueFQN},
	}
}

func TestExtractNamespaceFQNFromValue(t *testing.T) {
	t.Run("extracts from full Attribute->Namespace chain", func(t *testing.T) {
		val := &policy.Value{
			Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{Fqn: "https://example.com"},
			},
		}
		assert.Equal(t, "https://example.com", extractNamespaceFQNFromValue(val))
	})

	t.Run("extracts from Value FQN when Attribute is nil", func(t *testing.T) {
		val := &policy.Value{Fqn: "https://example.com/attr/color/value/red"}
		assert.Equal(t, "https://example.com", extractNamespaceFQNFromValue(val))
	})

	t.Run("returns empty when both are nil", func(t *testing.T) {
		val := &policy.Value{Id: "some-id"}
		assert.Empty(t, extractNamespaceFQNFromValue(val))
	})

	t.Run("returns empty when FQN has no /attr/ segment", func(t *testing.T) {
		val := &policy.Value{Fqn: "https://example.com/something/else"}
		assert.Empty(t, extractNamespaceFQNFromValue(val))
	})

	t.Run("prefers Attribute chain over FQN", func(t *testing.T) {
		val := &policy.Value{
			Fqn: "https://other.com/attr/color/value/red",
			Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{Fqn: "https://example.com"},
			},
		}
		assert.Equal(t, "https://example.com", extractNamespaceFQNFromValue(val))
	})
}

func TestDetectRequiredNamespace(t *testing.T) {
	t.Run("returns Deterministic when all AAVs share one namespace", func(t *testing.T) {
		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{Id: "r1"},
			Values: []*policy.RegisteredResourceValue{
				{Id: "v1", ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					aavWithNamespace("https://example.com"),
				}},
				{Id: "v2", ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					aavWithNamespace("https://example.com"),
				}},
			},
		}
		result := detectRequiredNamespace(plan)
		assert.Equal(t, "https://example.com", result.Deterministic)
		assert.False(t, result.NoAAVs)
		assert.False(t, result.Undetermined)
		assert.Empty(t, result.Conflicting)
	})

	t.Run("returns NoAAVs when resource has no action-attribute values", func(t *testing.T) {
		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{Id: "r1"},
			Values:   []*policy.RegisteredResourceValue{{Id: "v1"}},
		}
		result := detectRequiredNamespace(plan)
		assert.True(t, result.NoAAVs)
	})

	t.Run("returns NoAAVs when resource has no values", func(t *testing.T) {
		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{Id: "r1"},
		}
		result := detectRequiredNamespace(plan)
		assert.True(t, result.NoAAVs)
	})

	t.Run("returns Conflicting when AAVs reference multiple namespaces", func(t *testing.T) {
		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{Id: "r1"},
			Values: []*policy.RegisteredResourceValue{
				{Id: "v1", ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					aavWithNamespace("https://ns1.com"),
					aavWithNamespace("https://ns2.com"),
				}},
			},
		}
		result := detectRequiredNamespace(plan)
		assert.Len(t, result.Conflicting, 2)
		assert.Contains(t, result.Conflicting, "https://ns1.com")
		assert.Contains(t, result.Conflicting, "https://ns2.com")
	})

	t.Run("returns Undetermined when AAVs have nil attribute value namespace", func(t *testing.T) {
		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{Id: "r1"},
			Values: []*policy.RegisteredResourceValue{
				{Id: "v1", ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{Action: &policy.Action{Id: "a1"}, AttributeValue: &policy.Value{Id: "av1"}},
				}},
			},
		}
		result := detectRequiredNamespace(plan)
		assert.True(t, result.Undetermined)
	})

	t.Run("falls back to Value FQN parsing", func(t *testing.T) {
		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{Id: "r1"},
			Values: []*policy.RegisteredResourceValue{
				{Id: "v1", ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					aavWithFQNOnly("https://example.com/attr/color/value/red"),
				}},
			},
		}
		result := detectRequiredNamespace(plan)
		assert.Equal(t, "https://example.com", result.Deterministic)
	})
}

func TestFilterNamespacesByFQN(t *testing.T) {
	nsList := []*policy.Namespace{
		{Id: "ns-1", Fqn: "https://ns1.com"},
		{Id: "ns-2", Fqn: "https://ns2.com"},
		{Id: "ns-3", Fqn: "https://ns3.com"},
	}

	t.Run("filters to matching FQNs", func(t *testing.T) {
		filtered := filterNamespacesByFQN(nsList, []string{"https://ns1.com", "https://ns3.com"})
		assert.Len(t, filtered, 2)
		assert.Equal(t, "ns-1", filtered[0].GetId())
		assert.Equal(t, "ns-3", filtered[1].GetId())
	})

	t.Run("returns empty when no matches", func(t *testing.T) {
		filtered := filterNamespacesByFQN(nsList, []string{"https://other.com"})
		assert.Empty(t, filtered)
	})

	t.Run("returns empty for empty inputs", func(t *testing.T) {
		assert.Empty(t, filterNamespacesByFQN(nil, nil))
	})
}

func TestRunBatchRegisteredResourceMigration(t *testing.T) {
	styles := initMigrationDisplayStyles()
	nsList := []*policy.Namespace{{Id: "ns-1", Fqn: "https://example.com"}}

	t.Run("batch prompts for no-AAV resources", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			BatchNamespaceResponse: "https://example.com",
		}
		plan := []RegisteredResourceMigrationPlan{
			{Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"}},
			{Resource: &policy.RegisteredResource{Id: "r2", Name: "res2"}},
		}

		err := runBatchRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.NoError(t, err)
		assert.Len(t, handler.CreatedResources, 2)
		assert.Equal(t, "https://example.com", handler.CreatedResources[0].Namespace)
		assert.Equal(t, "https://example.com", handler.CreatedResources[1].Namespace)
		assert.Len(t, handler.DeletedResourceIDs, 2)
	})

	t.Run("auto-assigns deterministic namespaces", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{}
		plan := []RegisteredResourceMigrationPlan{
			{
				Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"},
				Values: []*policy.RegisteredResourceValue{{
					Id:                    "v1",
					ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{aavWithNamespace("https://example.com")},
				}},
			},
		}

		err := runBatchRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.NoError(t, err)
		require.Len(t, handler.CreatedResources, 1)
		assert.Equal(t, "https://example.com", handler.CreatedResources[0].Namespace)
	})

	t.Run("mixed: auto-assigns deterministic and batch-prompts for no-AAV", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			BatchNamespaceResponse: "https://example.com",
		}
		plan := []RegisteredResourceMigrationPlan{
			{
				Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"},
				Values: []*policy.RegisteredResourceValue{{
					Id:                    "v1",
					ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{aavWithNamespace("https://example.com")},
				}},
			},
			{Resource: &policy.RegisteredResource{Id: "r2", Name: "res2"}},
		}

		err := runBatchRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.NoError(t, err)
		assert.Len(t, handler.CreatedResources, 2)
	})

	t.Run("returns error when user aborts batch selection", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			BatchNamespaceErr: errors.New("migration aborted by user"),
		}
		plan := []RegisteredResourceMigrationPlan{
			{Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"}},
		}

		err := runBatchRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aborted")
		assert.Empty(t, handler.CreatedResources)
	})

	t.Run("reports partial failure", func(t *testing.T) {
		handler := &MockMigrationHandler{
			CreateResourceErr: errors.New("create failed"),
		}
		prompter := &MockMigrationPrompter{
			BatchNamespaceResponse: "https://example.com",
		}
		plan := []RegisteredResourceMigrationPlan{
			{Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"}},
			{Resource: &policy.RegisteredResource{Id: "r2", Name: "res2"}},
		}

		err := runBatchRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "2 of 2 resources failed")
	})
}

func TestRunInteractiveRegisteredResourceMigration(t *testing.T) {
	styles := initMigrationDisplayStyles()
	nsList := []*policy.Namespace{
		{Id: "ns-1", Fqn: "https://ns1.com"},
		{Id: "ns-2", Fqn: "https://ns2.com"},
		{Id: "ns-3", Fqn: "https://ns3.com"},
	}

	// buildNoAAVPlan creates resources with no AAVs (free namespace selection).
	buildNoAAVPlan := func(n int) []RegisteredResourceMigrationPlan {
		plan := make([]RegisteredResourceMigrationPlan, n)
		for i := range n {
			plan[i] = RegisteredResourceMigrationPlan{
				Resource: &policy.RegisteredResource{
					Id:   fmt.Sprintf("r%d", i+1),
					Name: fmt.Sprintf("res%d", i+1),
				},
			}
		}
		return plan
	}

	t.Run("no-AAV resources use free namespace selection", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ResourceNamespaceResponses: []string{"https://ns1.com", "https://ns2.com", "https://ns3.com"},
		}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, buildNoAAVPlan(3), nsList)
		require.NoError(t, err)
		require.Len(t, handler.CreatedResources, 3)
		assert.Equal(t, "https://ns1.com", handler.CreatedResources[0].Namespace)
		assert.Equal(t, "https://ns2.com", handler.CreatedResources[1].Namespace)
		assert.Equal(t, "https://ns3.com", handler.CreatedResources[2].Namespace)
		assert.Len(t, handler.DeletedResourceIDs, 3)
	})

	t.Run("auto-detected namespace confirmed", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ConfirmResourceNamespaceResponses: []string{"https://ns1.com"},
		}
		plan := []RegisteredResourceMigrationPlan{{
			Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"},
			Values: []*policy.RegisteredResourceValue{{
				Id:                    "v1",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{aavWithNamespace("https://ns1.com")},
			}},
		}}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.NoError(t, err)
		require.Len(t, handler.CreatedResources, 1)
		assert.Equal(t, "https://ns1.com", handler.CreatedResources[0].Namespace)
	})

	t.Run("user skips auto-detected namespace", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ConfirmResourceNamespaceResponses: []string{optSkipResource},
		}
		plan := []RegisteredResourceMigrationPlan{{
			Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"},
			Values: []*policy.RegisteredResourceValue{{
				Id:                    "v1",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{aavWithNamespace("https://ns1.com")},
			}},
		}}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.NoError(t, err)
		assert.Empty(t, handler.CreatedResources)
	})

	t.Run("conflict shows filtered namespace selection", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ResourceNamespaceResponses: []string{"https://ns1.com"},
		}
		plan := []RegisteredResourceMigrationPlan{{
			Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"},
			Values: []*policy.RegisteredResourceValue{{
				Id: "v1",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					aavWithNamespace("https://ns1.com"),
					aavWithNamespace("https://ns2.com"),
				},
			}},
		}}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.NoError(t, err)
		require.Len(t, handler.CreatedResources, 1)
		assert.Equal(t, "https://ns1.com", handler.CreatedResources[0].Namespace)
	})

	t.Run("undetermined namespace falls back to full selection", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ResourceNamespaceResponses: []string{"https://ns2.com"},
		}
		plan := []RegisteredResourceMigrationPlan{{
			Resource: &policy.RegisteredResource{Id: "r1", Name: "res1"},
			Values: []*policy.RegisteredResourceValue{{
				Id: "v1",
				ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
					{Action: &policy.Action{Id: "a1"}, AttributeValue: &policy.Value{Id: "av1"}},
				},
			}},
		}}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, plan, nsList)
		require.NoError(t, err)
		require.Len(t, handler.CreatedResources, 1)
		assert.Equal(t, "https://ns2.com", handler.CreatedResources[0].Namespace)
	})

	t.Run("skips resources when skip is selected", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ResourceNamespaceResponses: []string{"https://ns1.com", optSkipResource, "https://ns3.com"},
		}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, buildNoAAVPlan(3), nsList)
		require.NoError(t, err)
		assert.Len(t, handler.CreatedResources, 2)
		assert.Equal(t, "https://ns1.com", handler.CreatedResources[0].Namespace)
		assert.Equal(t, "https://ns3.com", handler.CreatedResources[1].Namespace)
	})

	t.Run("aborts migration when abort is selected", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ResourceNamespaceResponses: []string{"https://ns1.com", optAbortAll},
		}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, buildNoAAVPlan(3), nsList)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aborted")
		assert.Len(t, handler.CreatedResources, 1)
	})

	t.Run("aborts on huh.ErrUserAborted", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ResourceNamespaceResponses: []string{"https://ns1.com"},
			ResourceNamespaceErrs:      []error{nil, huh.ErrUserAborted},
		}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, buildNoAAVPlan(3), nsList)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aborted")
		assert.Len(t, handler.CreatedResources, 1)
	})

	t.Run("skips resource on prompt error and continues", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{
			ResourceNamespaceResponses: []string{"https://ns1.com", "", "https://ns3.com"},
			ResourceNamespaceErrs:      []error{nil, errors.New("terminal glitch"), nil},
		}

		err := runInteractiveRegisteredResourceMigration(context.Background(), handler, prompter, styles, buildNoAAVPlan(3), nsList)
		require.NoError(t, err)
		assert.Len(t, handler.CreatedResources, 2)
	})
}

func TestMigrateRegisteredResources(t *testing.T) {
	t.Run("interactive commit - full flow with auto-detected namespace", func(t *testing.T) {
		handler := &MockMigrationHandler{
			Resources: []*policy.RegisteredResource{{Id: "r1", Name: "res1"}},
			ResourceValues: map[string][]*policy.RegisteredResourceValue{
				"r1": {{
					Id: "v1", Value: "val1",
					ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
						aavWithNamespace("https://example.com"),
					},
				}},
			},
			Namespaces: []*policy.Namespace{{Id: "ns-1", Fqn: "https://example.com"}},
		}
		prompter := &MockMigrationPrompter{
			ConfirmBackupResponse:             true,
			ConfirmResourceNamespaceResponses: []string{"https://example.com"},
		}

		err := MigrateRegisteredResources(context.Background(), handler, prompter, true, true)
		require.NoError(t, err)
		assert.Len(t, handler.CreatedResources, 1)
		assert.Equal(t, "https://example.com", handler.CreatedResources[0].Namespace)
		assert.Len(t, handler.DeletedResourceIDs, 1)
	})

	t.Run("interactive commit - no-AAV resource uses free selection", func(t *testing.T) {
		handler := &MockMigrationHandler{
			Resources:  []*policy.RegisteredResource{{Id: "r1", Name: "res1"}},
			Namespaces: []*policy.Namespace{{Id: "ns-1", Fqn: "https://example.com"}},
		}
		prompter := &MockMigrationPrompter{
			ConfirmBackupResponse:      true,
			ResourceNamespaceResponses: []string{"https://example.com"},
		}

		err := MigrateRegisteredResources(context.Background(), handler, prompter, true, true)
		require.NoError(t, err)
		assert.Len(t, handler.CreatedResources, 1)
	})

	t.Run("batch commit - full flow", func(t *testing.T) {
		handler := &MockMigrationHandler{
			Resources:  []*policy.RegisteredResource{{Id: "r1", Name: "res1"}},
			Namespaces: []*policy.Namespace{{Id: "ns-1", Fqn: "https://example.com"}},
		}
		prompter := &MockMigrationPrompter{
			ConfirmBackupResponse:  true,
			BatchNamespaceResponse: "https://example.com",
		}

		err := MigrateRegisteredResources(context.Background(), handler, prompter, true, false)
		require.NoError(t, err)
		assert.Len(t, handler.CreatedResources, 1)
	})

	t.Run("backup not confirmed - returns error", func(t *testing.T) {
		handler := &MockMigrationHandler{
			Resources:  []*policy.RegisteredResource{{Id: "r1", Name: "res1"}},
			Namespaces: []*policy.Namespace{{Id: "ns-1", Fqn: "https://example.com"}},
		}
		prompter := &MockMigrationPrompter{
			ConfirmBackupResponse: false,
		}

		err := MigrateRegisteredResources(context.Background(), handler, prompter, true, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not confirm backup")
		assert.Empty(t, handler.CreatedResources)
	})

	t.Run("backup aborted - returns error", func(t *testing.T) {
		handler := &MockMigrationHandler{
			Resources:  []*policy.RegisteredResource{{Id: "r1", Name: "res1"}},
			Namespaces: []*policy.Namespace{{Id: "ns-1", Fqn: "https://example.com"}},
		}
		prompter := &MockMigrationPrompter{
			ConfirmBackupErr: errors.New("user aborted backup form"),
		}

		err := MigrateRegisteredResources(context.Background(), handler, prompter, true, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "aborted")
		assert.Empty(t, handler.CreatedResources)
	})

	t.Run("preview mode does not prompt", func(t *testing.T) {
		handler := &MockMigrationHandler{
			Resources:  []*policy.RegisteredResource{{Id: "r1", Name: "res1"}},
			Namespaces: []*policy.Namespace{{Id: "ns-1", Fqn: "https://example.com"}},
		}
		// Prompter has no responses configured - would error if called
		prompter := &MockMigrationPrompter{}

		err := MigrateRegisteredResources(context.Background(), handler, prompter, false, false)
		require.NoError(t, err)
		assert.Empty(t, handler.CreatedResources)
	})

	t.Run("no resources - returns early", func(t *testing.T) {
		handler := &MockMigrationHandler{}
		prompter := &MockMigrationPrompter{}

		err := MigrateRegisteredResources(context.Background(), handler, prompter, true, true)
		require.NoError(t, err)
	})

	t.Run("no namespaces - returns error", func(t *testing.T) {
		handler := &MockMigrationHandler{
			Resources: []*policy.RegisteredResource{{Id: "r1", Name: "res1"}},
		}
		prompter := &MockMigrationPrompter{}

		err := MigrateRegisteredResources(context.Background(), handler, prompter, true, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no namespaces available")
	})
}

func TestBuildRegisteredResourcePlan(t *testing.T) {
	t.Run("builds plan with resources lacking namespaces", func(t *testing.T) {
		mock := &MockMigrationHandler{
			Resources: []*policy.RegisteredResource{
				{Id: "res-1", Name: "resource-one"},
				{Id: "res-2", Name: "resource-two", Namespace: &policy.Namespace{Id: "ns-1", Fqn: "https://example.com"}},
				{Id: "res-3", Name: "resource-three"},
			},
			ResourceValues: map[string][]*policy.RegisteredResourceValue{
				"res-1": {
					{Id: "val-1", Value: "value-one"},
					{Id: "val-2", Value: "value-two"},
				},
				"res-3": {
					{Id: "val-3", Value: "value-three"},
				},
			},
		}

		plan, err := buildRegisteredResourcePlan(context.Background(), mock)
		require.NoError(t, err)

		// Should only include resources without namespaces (res-1 and res-3)
		assert.Len(t, plan, 2)
		assert.Equal(t, "res-1", plan[0].Resource.GetId())
		assert.Equal(t, "resource-one", plan[0].Resource.GetName())
		assert.Len(t, plan[0].Values, 2)
		assert.Equal(t, "res-3", plan[1].Resource.GetId())
		assert.Len(t, plan[1].Values, 1)
	})

	t.Run("returns empty plan when no resources exist", func(t *testing.T) {
		mock := &MockMigrationHandler{}

		plan, err := buildRegisteredResourcePlan(context.Background(), mock)
		require.NoError(t, err)
		assert.Empty(t, plan)
	})

	t.Run("returns empty plan when all resources have namespaces", func(t *testing.T) {
		mock := &MockMigrationHandler{
			Resources: []*policy.RegisteredResource{
				{Id: "res-1", Name: "resource-one", Namespace: &policy.Namespace{Id: "ns-1"}},
				{Id: "res-2", Name: "resource-two", Namespace: &policy.Namespace{Id: "ns-2"}},
			},
		}

		plan, err := buildRegisteredResourcePlan(context.Background(), mock)
		require.NoError(t, err)
		assert.Empty(t, plan)
	})
}

func TestCommitRegisteredResourceMigration(t *testing.T) {
	t.Run("creates resource with correct namespace and name", func(t *testing.T) {
		mock := &MockMigrationHandler{}

		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{
				Id:   "old-id",
				Name: "my-resource",
				Metadata: &common.Metadata{
					Labels: map[string]string{"env": "prod"},
				},
			},
			Values: []*policy.RegisteredResourceValue{
				{Id: "old-val-1", Value: "val-a"},
				{Id: "old-val-2", Value: "val-b"},
			},
			TargetNamespace: "https://example.com",
			Commit:          true,
		}

		err := commitRegisteredResourceMigration(context.Background(), mock, plan)
		require.NoError(t, err)

		// Verify resource was created without values (values are created individually)
		require.Len(t, mock.CreatedResources, 1)
		assert.Equal(t, "https://example.com", mock.CreatedResources[0].Namespace)
		assert.Equal(t, "my-resource", mock.CreatedResources[0].Name)
		assert.Nil(t, mock.CreatedResources[0].Values)
		assert.Equal(t, map[string]string{"env": "prod"}, mock.CreatedResources[0].Metadata.GetLabels())

		// Verify values were created individually
		require.Len(t, mock.CreatedResourceValues, 2)
		assert.Equal(t, "new-resource-id", mock.CreatedResourceValues[0].ResourceID)
		assert.Equal(t, "val-a", mock.CreatedResourceValues[0].Value)
		assert.Equal(t, "val-b", mock.CreatedResourceValues[1].Value)

		// Verify old resource was deleted
		assert.Contains(t, mock.DeletedResourceIDs, "old-id")
	})

	t.Run("re-creates values with action-attribute mappings", func(t *testing.T) {
		mock := &MockMigrationHandler{}

		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{
				Id:   "old-id",
				Name: "my-resource",
			},
			Values: []*policy.RegisteredResourceValue{
				{
					Id:    "old-val-1",
					Value: "val-a",
					ActionAttributeValues: []*policy.RegisteredResourceValue_ActionAttributeValue{
						{
							Id:             "aav-1",
							Action:         &policy.Action{Id: "action-1"},
							AttributeValue: &policy.Value{Id: "attr-val-1"},
						},
					},
				},
			},
			TargetNamespace: "https://example.com",
			Commit:          true,
		}

		err := commitRegisteredResourceMigration(context.Background(), mock, plan)
		require.NoError(t, err)

		// Should have re-created the value with AAVs
		require.Len(t, mock.CreatedResourceValues, 1)
		assert.Equal(t, "new-resource-id", mock.CreatedResourceValues[0].ResourceID)
		assert.Equal(t, "val-a", mock.CreatedResourceValues[0].Value)
		require.Len(t, mock.CreatedResourceValues[0].ActionAttributeVals, 1)
	})

	t.Run("returns error when create fails", func(t *testing.T) {
		mock := &MockMigrationHandler{
			CreateResourceErr: errors.New("create failed"),
		}

		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{
				Id:   "old-id",
				Name: "my-resource",
			},
			TargetNamespace: "https://example.com",
			Commit:          true,
		}

		err := commitRegisteredResourceMigration(context.Background(), mock, plan)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create failed")

		// Old resource should NOT have been deleted
		assert.Empty(t, mock.DeletedResourceIDs)
	})

	t.Run("returns error when delete fails", func(t *testing.T) {
		mock := &MockMigrationHandler{
			DeleteResourceErr: errors.New("delete failed"),
		}

		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{
				Id:   "old-id",
				Name: "my-resource",
			},
			Values: []*policy.RegisteredResourceValue{
				{Id: "old-val-1", Value: "val-a"},
			},
			TargetNamespace: "https://example.com",
			Commit:          true,
		}

		err := commitRegisteredResourceMigration(context.Background(), mock, plan)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete failed")
	})

	t.Run("returns error when plan not ready", func(t *testing.T) {
		mock := &MockMigrationHandler{}

		plan := RegisteredResourceMigrationPlan{
			Resource: &policy.RegisteredResource{Id: "old-id"},
			Commit:   false,
		}

		err := commitRegisteredResourceMigration(context.Background(), mock, plan)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not ready for commit")
	})
}

func TestBuildNamespaceOptions(t *testing.T) {
	t.Run("builds options from namespaces with FQN", func(t *testing.T) {
		nsList := []*policy.Namespace{
			{Id: "ns-1", Name: "example", Fqn: "https://example.com"},
			{Id: "ns-2", Name: "other", Fqn: "https://other.org"},
		}

		opts := buildNamespaceOptions(nsList)
		assert.Len(t, opts, 2)
	})

	t.Run("returns empty options for empty namespace list", func(t *testing.T) {
		opts := buildNamespaceOptions(nil)
		assert.Empty(t, opts)
	})
}

func TestConvertActionAttributeValues(t *testing.T) {
	t.Run("converts action-attribute values correctly", func(t *testing.T) {
		aavs := []*policy.RegisteredResourceValue_ActionAttributeValue{
			{
				Id:             "aav-1",
				Action:         &policy.Action{Id: "action-1"},
				AttributeValue: &policy.Value{Id: "attr-val-1"},
			},
			{
				Id:             "aav-2",
				Action:         &policy.Action{Id: "action-2"},
				AttributeValue: &policy.Value{Id: "attr-val-2"},
			},
		}

		result := convertActionAttributeValues(aavs)
		require.Len(t, result, 2)
		assert.Equal(t, "action-1", result[0].GetActionId())
		assert.Equal(t, "attr-val-1", result[0].GetAttributeValueId())
		assert.Equal(t, "action-2", result[1].GetActionId())
		assert.Equal(t, "attr-val-2", result[1].GetAttributeValueId())
	})

	t.Run("handles empty input", func(t *testing.T) {
		result := convertActionAttributeValues(nil)
		assert.Empty(t, result)
	})
}
