package authorization

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"log/slog"
	"os"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/profiler"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/opentdf/platform/internal/entitlements"
	"github.com/opentdf/platform/internal/opa"
	"github.com/opentdf/platform/protocol/go/authorization"
	"google.golang.org/grpc"
)

type AuthorizationService struct {
	authorization.UnimplementedAuthorizationServiceServer
	eng *opa.Engine
	cc  *grpc.ClientConn
}

func NewAuthorizationServer(g *grpc.Server, cc *grpc.ClientConn, s *runtime.ServeMux, eng *opa.Engine) error {
	as := &AuthorizationService{
		eng: eng,
		cc:  cc,
	}
	authorization.RegisterAuthorizationServiceServer(g, as)
	err := authorization.RegisterAuthorizationServiceHandlerServer(context.Background(), s, as)
	if err != nil {
		return fmt.Errorf("failed to register authorization service handler: %w", err)
	}
	return nil
}

func (as AuthorizationService) GetDecisions(ctx context.Context, req *authorization.GetDecisionsRequest) (*authorization.GetDecisionsResponse, error) {
	slog.DebugContext(ctx, "getting decisions")

	// Temporary canned echo response with permit decision for all requested decision/entity/ra combos
	rsp := &authorization.GetDecisionsResponse{
		DecisionResponses: make([]*authorization.DecisionResponse, 0),
	}
	for _, dr := range req.DecisionRequests {
		for _, ra := range dr.ResourceAttributes {
			for _, ec := range dr.EntityChains {
				decision := &authorization.DecisionResponse{
					Decision:      authorization.DecisionResponse_DECISION_PERMIT,
					EntityChainId: ec.Id,
					Action: &authorization.Action{
						Value: &authorization.Action_Standard{
							Standard: authorization.Action_STANDARD_ACTION_TRANSMIT,
						},
					},
					ResourceAttributesId: "resourceAttributesId_stub" + ra.String(),
				}
				rsp.DecisionResponses = append(rsp.DecisionResponses, decision)
			}
		}
	}
	return rsp, nil
}

func (as AuthorizationService) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	slog.Debug("getting entitlements")
	// get subject mappings
	smc := subjectmapping.NewSubjectMappingServiceClient(as.cc)
	ins := subjectmapping.GetSubjectSetRequest{
		Id: "abc",
	}
	out, err := smc.GetSubjectSet(ctx, &ins)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		return nil, err
	}
	slog.InfoContext(ctx, out.String())
	// OPA
	in, err := entitlements.OpaInput(req.Entities[0], out.SubjectSet)
	if err != nil {
		return nil, err
	}
	slog.Debug("entitlements", "input", fmt.Sprintf("%+v", in))
	if err := json.NewEncoder(os.Stdout).Encode(in); err != nil {
		panic(err)
	}
	options := sdk.DecisionOptions{
		Now:                 time.Now(),
		Path:                "opentdf/entitlements/entitlements",
		Input:               in,
		NDBCache:            nil,
		StrictBuiltinErrors: false,
		Tracer:              nil,
		Metrics:             metrics.New(),
		Profiler:            profiler.New(),
		Instrument:          true,
		DecisionID:          fmt.Sprintf("%-v", req.String()),
	}
	decision, err := as.eng.Decision(ctx, options)
	if err != nil {
		return nil, err
	}
	slog.DebugContext(ctx, "opa", "result", fmt.Sprintf("%+v", decision.Result))
	var ee []*authorization.EntityEntitlements
	rsp := &authorization.GetEntitlementsResponse{}
	rsp.Entitlements = ee
	return rsp, nil
}
