package authorization

import (
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/policy/filestore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/structpb"
)

// Verifies GetEntitlements works end-to-end with a file-backed policy store —
// no Postgres, no policy service. ERS is still consumed via SDK (mocked).
func Test_GetEntitlements_FileStore(t *testing.T) {
	const policyYAML = `
namespaces:
  - name: www.example.org
attributes:
  - namespace: www.example.org
    name: foo
    rule: anyOf
    values:
      - value: value1
      - value: value2
subject_mappings:
  - attribute_value_fqn: https://www.example.org/attr/foo/value/value1
    inline_condition_set:
      subject_sets:
        - condition_groups:
            - boolean_operator: AND
              conditions:
                - subject_external_selector_value: .A
                  operator: IN
                  subject_external_values: [B]
    actions:
      - name: read
        standard: TRANSMIT
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(policyYAML), 0o600))
	store, err := filestore.NewStoreFromFile(path)
	require.NoError(t, err)

	userStruct, err := structpb.NewStruct(map[string]interface{}{"A": "B"})
	require.NoError(t, err)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId:      "e1",
				AdditionalProps: []*structpb.Struct{userStruct},
			},
		},
	}

	prepared, err := rego.New(
		rego.SetRegoVersion(ast.RegoV0),
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`),
	).PrepareForEval(t.Context())
	require.NoError(t, err)

	as := AuthorizationService{
		logger: logger.CreateTestLogger(),
		// Deliberately omit Attributes / SubjectMapping clients: the file
		// store must satisfy every policy lookup, so any SDK call here
		// would nil-panic and fail the test.
		sdk: &otdf.SDK{
			EntityResoution: &myERSClient{},
		},
		eval:        prepared,
		policyStore: store,
		Tracer:      noop.NewTracerProvider().Tracer(""),
	}

	resp, err := as.GetEntitlements(t.Context(), &connect.Request[authorization.GetEntitlementsRequest]{
		Msg: &authorization.GetEntitlementsRequest{
			Entities: []*authorization.Entity{{
				Id:         "e1",
				EntityType: &authorization.Entity_ClientId{ClientId: "testclient"},
				Category:   authorization.Entity_CATEGORY_ENVIRONMENT,
			}},
			Scope: &authorization.ResourceAttribute{
				AttributeValueFqns: []string{"https://www.example.org/attr/foo/value/value1"},
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Msg.GetEntitlements(), 1)
	assert.Equal(t, "e1", resp.Msg.GetEntitlements()[0].GetEntityId())
	assert.Equal(t, []string{"https://www.example.org/attr/foo/value/value1"},
		resp.Msg.GetEntitlements()[0].GetAttributeValueFqns())
}

// Verifies GetDecisions works against the file-backed store with no policy
// service available.
func Test_GetDecisions_FileStore(t *testing.T) {
	const policyYAML = `
namespaces:
  - name: www.example.org
attributes:
  - namespace: www.example.org
    name: foo
    rule: allOf
    values:
      - value: value1
subject_mappings:
  - attribute_value_fqn: https://www.example.org/attr/foo/value/value1
    inline_condition_set:
      subject_sets:
        - condition_groups:
            - boolean_operator: AND
              conditions:
                - subject_external_selector_value: .A
                  operator: IN
                  subject_external_values: [B]
    actions:
      - name: read
        standard: TRANSMIT
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(policyYAML), 0o600))
	store, err := filestore.NewStoreFromFile(path)
	require.NoError(t, err)

	userStruct, err := structpb.NewStruct(map[string]interface{}{"A": "B"})
	require.NoError(t, err)
	resolveEntitiesResp = entityresolution.ResolveEntitiesResponse{
		EntityRepresentations: []*entityresolution.EntityRepresentation{
			{
				OriginalId:      "e1",
				AdditionalProps: []*structpb.Struct{userStruct},
			},
		},
	}

	prepared, err := rego.New(
		rego.SetRegoVersion(ast.RegoV0),
		rego.Query("data.example.p"),
		rego.Module("example.rego",
			`package example
			p = {"e1":["https://www.example.org/attr/foo/value/value1"]} { true }`),
	).PrepareForEval(t.Context())
	require.NoError(t, err)

	as := AuthorizationService{
		logger: logger.CreateTestLogger(),
		sdk: &otdf.SDK{
			EntityResoution: &myERSClient{},
		},
		eval:        prepared,
		policyStore: store,
		Tracer:      noop.NewTracerProvider().Tracer(""),
	}

	ctx := audit.ContextWithActorID(t.Context(), "test-actor")
	resp, err := as.GetDecisions(ctx, &connect.Request[authorization.GetDecisionsRequest]{
		Msg: &authorization.GetDecisionsRequest{
			DecisionRequests: []*authorization.DecisionRequest{{
				EntityChains: []*authorization.EntityChain{{
					Id: "ec1",
					Entities: []*authorization.Entity{{
						Id:         "e1",
						EntityType: &authorization.Entity_ClientId{ClientId: "testclient"},
						Category:   authorization.Entity_CATEGORY_ENVIRONMENT,
					}},
				}},
				ResourceAttributes: []*authorization.ResourceAttribute{{
					AttributeValueFqns: []string{"https://www.example.org/attr/foo/value/value1"},
				}},
			}},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Msg.GetDecisionResponses(), 1)
	assert.Equal(t, authorization.DecisionResponse_DECISION_PERMIT, resp.Msg.GetDecisionResponses()[0].GetDecision())
}
