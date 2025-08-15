package sdk

import (
	"context"

	"github.com/open-feature/go-sdk/openfeature"
	"github.com/opentdf/platform/protocol/go/featureflag"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"google.golang.org/protobuf/types/known/structpb"
)

type PlatformProvider struct {
	featureService sdkconnect.FeatureFlagServiceClient
}

func NewPlatformProvider(featureService sdkconnect.FeatureFlagServiceClient) *PlatformProvider {
	return &PlatformProvider{
		featureService: featureService,
	}
}

func (p *PlatformProvider) Metadata() openfeature.Metadata {
	return openfeature.Metadata{
		Name: "platform-provider",
	}
}

func (p *PlatformProvider) Hooks() []openfeature.Hook {
	return []openfeature.Hook{}
}

func (p *PlatformProvider) BooleanEvaluation(ctx context.Context, flagKey string, defaultValue bool, evalCtx openfeature.FlattenedContext) openfeature.BoolResolutionDetail {
	if p.featureService != nil {
		contextStruct, err := structpb.NewStruct(evalCtx)
		if err != nil {
			return openfeature.BoolResolutionDetail{
				Value: defaultValue,
				ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
					Reason:          openfeature.ErrorReason,
					ResolutionError: openfeature.NewGeneralResolutionError(err.Error()),
				},
			}
		}
		resp, err := p.featureService.ResolveBoolean(ctx, &featureflag.ResolveBooleanRequest{
			FlagKey: flagKey,
			Context: contextStruct,
		})
		if err != nil {
			return openfeature.BoolResolutionDetail{
				Value: defaultValue,
				ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
					Reason:          openfeature.ErrorReason,
					ResolutionError: openfeature.NewGeneralResolutionError(err.Error()),
				},
			}
		}
		return openfeature.BoolResolutionDetail{
			Value: resp.Value,
			ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
				Reason: openfeature.TargetingMatchReason,
			},
		}
	}
	return openfeature.BoolResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason: openfeature.DefaultReason,
		},
	}
}

func (p *PlatformProvider) StringEvaluation(ctx context.Context, flagKey string, defaultValue string, evalCtx openfeature.FlattenedContext) openfeature.StringResolutionDetail {
	// TODO: Implement the logic to evaluate a string feature flag.
	return openfeature.StringResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason: openfeature.DefaultReason,
		},
	}
}

func (p *PlatformProvider) FloatEvaluation(ctx context.Context, flagKey string, defaultValue float64, evalCtx openfeature.FlattenedContext) openfeature.FloatResolutionDetail {
	// TODO: Implement the logic to evaluate a float feature flag.
	return openfeature.FloatResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason: openfeature.DefaultReason,
		},
	}
}

func (p *PlatformProvider) IntEvaluation(ctx context.Context, flagKey string, defaultValue int64, evalCtx openfeature.FlattenedContext) openfeature.IntResolutionDetail {
	return openfeature.IntResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason: openfeature.DefaultReason,
		},
	}
}

func (p *PlatformProvider) ObjectEvaluation(ctx context.Context, flagKey string, defaultValue interface{}, evalCtx openfeature.FlattenedContext) openfeature.InterfaceResolutionDetail {
	// TODO: Implement the logic to evaluate an object feature flag.
	return openfeature.InterfaceResolutionDetail{
		Value: defaultValue,
		ProviderResolutionDetail: openfeature.ProviderResolutionDetail{
			Reason: openfeature.DefaultReason,
		},
	}
}
