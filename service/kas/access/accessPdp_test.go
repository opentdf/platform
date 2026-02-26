package access

import (
	"context"
	"io"
	"log/slog"
	"testing"

	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/protocol/go/entity"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

type fakeAuthorizationV2 struct {
	decisionReq      *authzV2.GetDecisionRequest
	decisionMultiReq *authzV2.GetDecisionMultiResourceRequest
}

func (f *fakeAuthorizationV2) GetDecision(ctx context.Context, req *authzV2.GetDecisionRequest) (*authzV2.GetDecisionResponse, error) {
	f.decisionReq = req
	return &authzV2.GetDecisionResponse{
		Decision: &authzV2.ResourceDecision{
			EphemeralResourceId: req.GetResource().GetEphemeralId(),
			Decision:            authzV2.Decision_DECISION_PERMIT,
		},
	}, nil
}

func (f *fakeAuthorizationV2) GetDecisionMultiResource(ctx context.Context, req *authzV2.GetDecisionMultiResourceRequest) (*authzV2.GetDecisionMultiResourceResponse, error) {
	f.decisionMultiReq = req
	decisions := make([]*authzV2.ResourceDecision, 0, len(req.GetResources()))
	for _, resource := range req.GetResources() {
		decisions = append(decisions, &authzV2.ResourceDecision{
			EphemeralResourceId: resource.GetEphemeralId(),
			Decision:            authzV2.Decision_DECISION_PERMIT,
		})
	}
	return &authzV2.GetDecisionMultiResourceResponse{ResourceDecisions: decisions}, nil
}

func (f *fakeAuthorizationV2) GetDecisionBulk(ctx context.Context, req *authzV2.GetDecisionBulkRequest) (*authzV2.GetDecisionBulkResponse, error) {
	return &authzV2.GetDecisionBulkResponse{}, nil
}

func (f *fakeAuthorizationV2) GetEntitlements(ctx context.Context, req *authzV2.GetEntitlementsRequest) (*authzV2.GetEntitlementsResponse, error) {
	return &authzV2.GetEntitlementsResponse{}, nil
}

func TestCanAccessPopulatesResourceMetadata(t *testing.T) {
	fakeAuthz := &fakeAuthorizationV2{}
	sdk := &otdf.SDK{AuthorizationV2: fakeAuthz}

	baseLogger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditLogger := audit.CreateAuditLogger(*slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: audit.LevelAudit})))
	testLogger := &logger.Logger{Logger: baseLogger, Audit: auditLogger}

	policy := &Policy{
		Body: PolicyBody{
			DataAttributes: []Attribute{{URI: "https://example.com/attr/foo/value/bar"}},
		},
	}

	resourceMetadata := resourceMetadataFromKAOResults(map[string]kaoResult{
		"kao-1": {
			DecryptedMetadata: map[string]any{
				"resourceMetadata": map[string]any{
					"file_name": "report.csv",
					"byte_size": float64(123),
				},
			},
		},
	})

	provider := &Provider{
		SDK:    sdk,
		Logger: testLogger,
		Tracer: trace.NewNoopTracerProvider().Tracer("test"),
	}

	_, err := provider.canAccess(
		context.Background(),
		&entity.Token{Jwt: "token"},
		[]*Policy{policy},
		map[*Policy]map[string]string{policy: resourceMetadata},
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, fakeAuthz.decisionReq)
	require.Equal(t, map[string]string{
		"file_name": "report.csv",
		"byte_size": "123",
	}, fakeAuthz.decisionReq.GetResource().GetMetadata())
}

func TestCanAccessPopulatesResourceMetadataForMultiResource(t *testing.T) {
	fakeAuthz := &fakeAuthorizationV2{}
	sdk := &otdf.SDK{AuthorizationV2: fakeAuthz}

	baseLogger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
	auditLogger := audit.CreateAuditLogger(*slog.New(slog.NewJSONHandler(io.Discard, &slog.HandlerOptions{Level: audit.LevelAudit})))
	testLogger := &logger.Logger{Logger: baseLogger, Audit: auditLogger}

	policyOne := &Policy{
		Body: PolicyBody{
			DataAttributes: []Attribute{{URI: "https://example.com/attr/one/value/alpha"}},
		},
	}
	policyTwo := &Policy{
		Body: PolicyBody{
			DataAttributes: []Attribute{{URI: "https://example.com/attr/two/value/beta"}},
		},
	}

	resourceMetadataOne := map[string]string{
		"file_name": "one.csv",
		"byte_size": "111",
	}
	resourceMetadataTwo := map[string]string{
		"file_name": "two.csv",
		"byte_size": "222",
	}

	provider := &Provider{
		SDK:    sdk,
		Logger: testLogger,
		Tracer: trace.NewNoopTracerProvider().Tracer("test"),
	}

	_, err := provider.canAccess(
		context.Background(),
		&entity.Token{Jwt: "token"},
		[]*Policy{policyOne, policyTwo},
		map[*Policy]map[string]string{
			policyOne: resourceMetadataOne,
			policyTwo: resourceMetadataTwo,
		},
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, fakeAuthz.decisionMultiReq)
	require.Len(t, fakeAuthz.decisionMultiReq.GetResources(), 2)

	resourceMeta := map[string]map[string]string{}
	for _, resource := range fakeAuthz.decisionMultiReq.GetResources() {
		resourceMeta[resource.GetEphemeralId()] = resource.GetMetadata()
	}

	require.Contains(t, resourceMeta, "rewrap-0")
	require.Contains(t, resourceMeta, "rewrap-1")
	require.Equal(t, resourceMetadataOne, resourceMeta["rewrap-0"])
	require.Equal(t, resourceMetadataTwo, resourceMeta["rewrap-1"])
}
