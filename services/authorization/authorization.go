package authorization

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	auth "github.com/opentdf/opentdf-v2-poc/protocol/go/authorization"
	"google.golang.org/grpc"
)

type AuthorizationService struct {
	auth.UnimplementedAuthorizationServiceServer
}

func NewAuthorizationServer(g *grpc.Server, s *runtime.ServeMux) error {
	as := &AuthorizationService{}
	auth.RegisterAuthorizationServiceServer(g, as)
	err := auth.RegisterAuthorizationServiceHandlerServer(context.Background(), s, as)
	if err != nil {
		return fmt.Errorf("failed to register authorization service handler: %w", err)
	}
	return nil
}

func (as AuthorizationService) GetDecisions(ctx context.Context, req *auth.GetDecisionsRequest) (*auth.GetDecisionsResponse, error) {
	slog.Debug("getting decisions")

	rsp := &auth.GetDecisionsResponse{}

	var empty_decisionResponses []*auth.DecisionResponse

	rsp.DecisionResponses = empty_decisionResponses

	return rsp, nil
}

func (as AuthorizationService) GetEntitlements(ctx context.Context, req *auth.GetEntitlementsRequest) (*auth.GetEntitlementsResponse, error) {
	slog.Debug("getting entitlements")

	rsp := &auth.GetEntitlementsResponse{}

	var empty_entityEntitlements []*auth.EntityEntitlements

	rsp.Entitlements = empty_entityEntitlements

	return rsp, nil
}
