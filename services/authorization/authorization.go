package authorization

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/sdk/authorization"
	"google.golang.org/grpc"
)

type AuthorizationService struct {
	authorization.UnimplementedAuthorizationServiceServer
}

func NewAuthorizationServer(g *grpc.Server, s *runtime.ServeMux) error {
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

	rsp := &authorization.GetDecisionsResponse{}

	var empty_decisionResponses []*authorization.DecisionResponse
	
	rsp.DecisionResponses = empty_decisionResponses

	return rsp, nil
}

func (as AuthorizationService) GetEntitlements(ctx context.Context, req *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	slog.Debug("getting entitlements")

	rsp := &authorization.GetEntitlementsResponse{}

	var empty_entityEntitlements []*authorization.EntityEntitlements
	
	rsp.Entitlements = empty_entityEntitlements

	return rsp, nil
}