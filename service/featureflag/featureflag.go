package featureflag

import (
	"context"

	"connectrpc.com/connect"
	"github.com/open-feature/go-sdk/openfeature"
	"github.com/opentdf/platform/protocol/go/featureflag"
	"github.com/opentdf/platform/protocol/go/featureflag/featureflagconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"google.golang.org/protobuf/types/known/structpb"
)

type FeatureFlagService struct {
	ffClient *openfeature.Client
	logger   *logger.Logger
}

func NewRegistration() *serviceregistry.Service[featureflagconnect.FeatureFlagServiceHandler] {
	ffs := new(FeatureFlagService)
	return &serviceregistry.Service[featureflagconnect.FeatureFlagServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[featureflagconnect.FeatureFlagServiceHandler]{
			Namespace:      "featureflag",
			ServiceDesc:    &featureflag.FeatureFlagService_ServiceDesc,
			ConnectRPCFunc: featureflagconnect.NewFeatureFlagServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (featureflagconnect.FeatureFlagServiceHandler, serviceregistry.HandlerServer) {
				if srp.FFClient == nil {
					panic("feature flag client is not set for FeatureFlagService")
				}

				ffs.logger = srp.Logger
				ffs.ffClient = srp.FFClient
				return ffs, nil
			},
		},
	}
}

func (s *FeatureFlagService) ResolveAll(ctx context.Context, req *connect.Request[featureflag.ResolveAllRequest]) (*connect.Response[featureflag.ResolveAllResponse], error) {
	s.logger.Debug("resolving all feature flags")
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *FeatureFlagService) ResolveBoolean(ctx context.Context, req *connect.Request[featureflag.ResolveBooleanRequest]) (*connect.Response[featureflag.ResolveBooleanResponse], error) {
	s.logger.Debug("resolving boolean feature flag", "flag_key", req.Msg.GetFlagKey())

	booleanEvaluationDetails, err := s.ffClient.BooleanValueDetails(ctx, req.Msg.GetFlagKey(), false, openfeature.EvaluationContext{})

	if err != nil {
		s.logger.Error("error occurred when resolving feature flag", "flag_key", req.Msg.GetFlagKey(), "error", err)
	}

	response := &featureflag.ResolveBooleanResponse{
		Value:   booleanEvaluationDetails.Value,
		Reason:  string(booleanEvaluationDetails.Reason),
		Variant: booleanEvaluationDetails.Variant,
	}
	if booleanEvaluationDetails.FlagMetadata != nil {
		var err error
		response.Metadata, err = structpb.NewStruct(booleanEvaluationDetails.FlagMetadata)
		if err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(response), nil
}

func (s *FeatureFlagService) ResolveString(ctx context.Context, req *connect.Request[featureflag.ResolveStringRequest]) (*connect.Response[featureflag.ResolveStringResponse], error) {
	s.logger.Debug("resolving string feature flag", "flag_key", req.Msg.GetFlagKey())
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *FeatureFlagService) ResolveFloat(ctx context.Context, req *connect.Request[featureflag.ResolveFloatRequest]) (*connect.Response[featureflag.ResolveFloatResponse], error) {
	s.logger.Debug("resolving float feature flag", "flag_key", req.Msg.GetFlagKey())
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *FeatureFlagService) ResolveInt(ctx context.Context, req *connect.Request[featureflag.ResolveIntRequest]) (*connect.Response[featureflag.ResolveIntResponse], error) {
	s.logger.Debug("resolving int feature flag", "flag_key", req.Msg.GetFlagKey())
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (s *FeatureFlagService) ResolveObject(ctx context.Context, req *connect.Request[featureflag.ResolveObjectRequest]) (*connect.Response[featureflag.ResolveObjectResponse], error) {
	s.logger.Debug("resolving object feature flag", "flag_key", req.Msg.GetFlagKey())
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}
