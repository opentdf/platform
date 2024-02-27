package authorization

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/authorization"
	attr "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/services"
	"google.golang.org/grpc"
)

type AuthorizationService struct {
	authorization.UnimplementedAuthorizationServiceServer
	cc *grpc.ClientConn
}

func NewAuthorizationServer(g *grpc.Server, cc *grpc.ClientConn, s *runtime.ServeMux) error {
	as := &AuthorizationService{
		cc: cc,
	}
	authorization.RegisterAuthorizationServiceServer(g, as)
	err := authorization.RegisterAuthorizationServiceHandlerServer(context.Background(), s, as)
	if err != nil {
		return fmt.Errorf("failed to register authorization service handler: %w", err)
	}
	return nil
}

func (as AuthorizationService) GetDecisions(ctx context.Context, req *authorization.GetDecisionsRequest) (*authorization.GetDecisionsResponse, error) {
	slog.Debug("getting decisions")

	attrClient := attr.NewAttributesServiceClient(as.cc)

	// Temporary canned echo response with permit decision for all requested decision/entity/ra combos
	rsp := &authorization.GetDecisionsResponse{
		DecisionResponses: make([]*authorization.DecisionResponse, 0),
	}
	for _, dr := range req.DecisionRequests {
		for _, ra := range dr.ResourceAttributes {
			slog.Debug("getting resource attributes", slog.String("FQNs", strings.Join(ra.AttributeFqns, ", ")))

			attrs, err := attrClient.GetAttributesByValueFqns(ctx, &attr.GetAttributesByValueFqnsRequest{
				Fqns: ra.AttributeFqns,
			})
			if err != nil {
				// TODO: should all decisions in a request fail if one FQN lookup fails?
				return nil, services.HandleError(err, services.ErrGetRetrievalFailed, slog.String("fqns", strings.Join(ra.AttributeFqns, ", ")))
			}
			for _, ec := range dr.EntityChains {
				fmt.Printf("\nTODO: make access decision here with these fully qualified attributes: %+v\n", attrs)
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

	rsp := &authorization.GetEntitlementsResponse{}

	var empty_entityEntitlements []*authorization.EntityEntitlements

	rsp.Entitlements = empty_entityEntitlements

	return rsp, nil
}
