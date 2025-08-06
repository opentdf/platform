package virtrusaas

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
)

type EntityResolutionServiceV2 struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	logger *logger.Logger
	trace.Tracer
}

func RegisterVirtruSaasERS(_ config.ServiceConfig, logger *logger.Logger) (EntityResolutionServiceV2, serviceregistry.HandlerServer) {
	svc := EntityResolutionServiceV2{logger: logger}
	return svc, nil
}

func (s EntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	resp, err := EntityResolution(ctx, req.Msg, s.logger)
	return connect.NewResponse(&resp), err
}

func (s EntityResolutionServiceV2) CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "CreateEntityChainsFromTokens")
	defer span.End()

	resp, err := CreateEntityChainsFromTokens(ctx, req.Msg, s.logger)
	return connect.NewResponse(&resp), err
}

func CreateEntityChainsFromTokens(
	_ context.Context,
	req *entityresolutionV2.CreateEntityChainsFromTokensRequest,
	logger *logger.Logger,
) (entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	logger.Info("VirtruSaas CreateEntityChainsFromTokens called", "tokens", len(req.GetTokens()))

	return entityresolutionV2.CreateEntityChainsFromTokensResponse{}, errors.New("not implemented") // Placeholder for actual implementation
}

func EntityResolution(_ context.Context,
	req *entityresolutionV2.ResolveEntitiesRequest, logger *logger.Logger,
) (entityresolutionV2.ResolveEntitiesResponse, error) {
	logger.Info("VirtruSaas EntityResolution called", "entities", req.GetEntities())

	return entityresolutionV2.ResolveEntitiesResponse{}, errors.New("not implemented") // Placeholder for actual implementation
}
