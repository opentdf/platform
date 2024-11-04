package wellknownconfiguration

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	wellknown "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type WellKnownService struct {
	wellknown.UnimplementedWellKnownServiceServer
	logger *logger.Logger
}

var (
	wellKnownConfiguration = make(map[string]any)
	rwMutex                sync.RWMutex
)

func RegisterConfiguration(namespace string, config any) error {
	rwMutex.Lock()
	defer rwMutex.Unlock()
	if _, ok := wellKnownConfiguration[namespace]; ok {
		return fmt.Errorf("namespace %s configuration already registered", namespace)
	}
	wellKnownConfiguration[namespace] = config
	return nil
}

func NewRegistration() *serviceregistry.Service[WellKnownService] {
	return &serviceregistry.Service[WellKnownService]{
		ServiceOptions: serviceregistry.ServiceOptions[WellKnownService]{
			Namespace:   "wellknown",
			ServiceDesc: &wellknown.WellKnownService_ServiceDesc,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (*WellKnownService, serviceregistry.HandlerServer) {
				wk := &WellKnownService{logger: srp.Logger}
				return wk, func(ctx context.Context, mux *runtime.ServeMux) error {
					return wellknown.RegisterWellKnownServiceHandlerServer(ctx, mux, wk)
				}
			},
		},
	}
}

func (s WellKnownService) GetWellKnownConfiguration(_ context.Context, _ *wellknown.GetWellKnownConfigurationRequest) (*wellknown.GetWellKnownConfigurationResponse, error) {
	rwMutex.RLock()
	cfg, err := structpb.NewStruct(wellKnownConfiguration)
	rwMutex.RUnlock()
	if err != nil {
		s.logger.Error("failed to create struct for wellknown configuration", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to create struct for wellknown configuration")
	}

	return &wellknown.GetWellKnownConfigurationResponse{
		Configuration: cfg,
	}, nil
}
