package authorization

import (
	"context"
	"fmt"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/authorization"
	"google.golang.org/grpc"
	"log/slog"
)

type AuthorizationService struct {
	authorization.UnimplementedAuthorizationServiceServer
}

func NewAuthorizationServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) error {
	as := &AuthorizationService{}
	authorization.RegisterAuthorizationServiceServer(g, as)
	err := authorization.RegisterAuthorizationServiceHandlerServer(context.Background(), s, as)
	if err != nil {
		return fmt.Errorf("failed to register authorization service handler: %w", err)
	}
	return nil
}

func (as AuthorizationService) GetDecisions(ctx context.Context, req *authorization.GetDecisionsRequest) (*authorization.GetDecisionsResponse, error) {
	slog.Debug("getting decisions")

	//Temporary canned echo response with permit decision for all requested decision/entity/ra combos
	rsp := &authorization.GetDecisionsResponse{
		DecisionResponses: make([]*authorization.DecisionResponse, 0),
	}
	for _, dr := range req.DecisionRequests {
		for _, ra := range dr.ResourceAttributes {
			for _, ec := range dr.EntityChains {
				decision := &authorization.DecisionResponse{
					Decision:             authorization.DecisionResponse_DECISION_PERMIT,
					EntityChainId:        ec.Id,
					Action:               &authorization.Action{},
					ResourceAttributesId: ra.Id,
				}
				rsp.DecisionResponses = append(rsp.DecisionResponses, decision)
			}
		}
	}
	return rsp, nil
}

func (as AuthorizationService) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	slog.Debug("getting entitlements")

	rsp := &authorization.GetEntitlementsResponse{}

	var empty_entityEntitlements []*authorization.EntityEntitlements

	rsp.Entitlements = empty_entityEntitlements

	return rsp, nil
}
