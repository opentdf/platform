package entitlements

import (
	"context"
	"log/slog"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/profiler"
	"github.com/open-policy-agent/opa/sdk"
	acsev1 "github.com/opentdf/opentdf-v2-poc/gen/acse/v1"
	entitlmentsv1 "github.com/opentdf/opentdf-v2-poc/gen/entitlements/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/opa"
	"github.com/opentdf/opentdf-v2-poc/pkg/entitlements/providers"
	"google.golang.org/grpc"
)

type Config struct {
	Providers []providers.Config `yaml:"providers"`
}

type Entitlements struct {
	entitlmentsv1.UnimplementedEntitlementsServiceServer
	grpcConn  *grpc.ClientConn
	eng       *opa.Engine
	providers []providers.Provider
}

func NewEntitlementsServer(config Config, grpcServers []*grpc.Server, clientConn *grpc.ClientConn, s *runtime.ServeMux, eng *opa.Engine) error {
	as := &Entitlements{
		grpcConn: clientConn,
		eng:      eng,
	}
	p, err := providers.BuildProviders(config.Providers)
	if err != nil {
		return err
	}
	as.providers = append(as.providers, p...)

	// Register with each grpc server
	for _, g := range grpcServers {
		entitlmentsv1.RegisterEntitlementsServiceServer(g, as)
	}

	err = entitlmentsv1.RegisterEntitlementsServiceHandlerServer(context.Background(), s, as)
	if err != nil {
		return err
	}
	return nil
}

/*
This is a poc to work with subject encodings service.
There is most likely logic that needs to be moved from https://github.com/opentdf/backend/tree/main/containers/entitlement-pdp
*/
func (s Entitlements) GetEntitlements(ctx context.Context, req *entitlmentsv1.GetEntitlementsRequest) (*entitlmentsv1.GetEntitlementsResponse, error) {
	var (
		entitlements = &entitlmentsv1.GetEntitlementsResponse{
			Entitlements: make(map[string]*entitlmentsv1.Entitlements),
		}
		entityAttributes = make(map[string]string)
	)
	slog.Info("getting entitlements", slog.Any("entities", req.Entities))

	// Get the subject mappings. Currently this list doesn't get filtered
	acseClient := acsev1.NewSubjectEncodingServiceClient(s.grpcConn)
	mappings, err := acseClient.ListSubjectMappings(ctx, &acsev1.ListSubjectMappingsRequest{})
	if err != nil {
		return entitlements, err
	}

	// Get Entitlements for each entity.
	for _, e := range req.Entities {
		// Get the attributes for each entity from each provider. Think about this as if we had to aggregate data from multiple systems
		// that we wanted to feed into the entitlements policy.
		for _, p := range s.providers {
			attrs, err := p.GetAttributes(e.Id)
			if err != nil {
				slog.Error("error getting attributes", slog.String("error", err.Error()))
				return entitlements, err
			}
			for k, v := range attrs {
				if ok := entityAttributes[k]; ok != "" {
					continue
				}
				entityAttributes[k] = v
			}
		}

		slog.Debug("evaluating opa policy", slog.Any("entity_attributes", entityAttributes), slog.Any("mappings", mappings.SubjectMappings))

		// Get the entitlements for the entity.
		result, err := s.eng.Decision(ctx, sdk.DecisionOptions{
			Now:  time.Now(),
			Path: "opentdf/entitlement/generated_entitlements",
			Input: map[string]interface{}{
				"entity_attrs": entityAttributes,
				"mappings":     mappings.SubjectMappings,
			},
			NDBCache:            nil,
			StrictBuiltinErrors: false,
			Tracer:              nil,
			Metrics:             metrics.New(),
			Profiler:            profiler.New(),
			Instrument:          false,
		})
		if err != nil {
			slog.Error("error evaluating opa policy", slog.String("error", err.Error()))
			return entitlements, err
		}
		ent := &entitlmentsv1.Entitlements{
			Entitlements: make([]string, 0),
		}
		for _, e := range result.Result.([]interface{}) {
			ent.Entitlements = append(ent.Entitlements, e.(string))
		}
		entitlements.Entitlements[e.Id] = ent
	}

	return entitlements, nil
}
