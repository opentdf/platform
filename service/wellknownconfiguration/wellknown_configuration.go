package wellknownconfiguration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"connectrpc.com/connect"
	wellknown "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"google.golang.org/protobuf/types/known/structpb"
)

type WellKnownService struct {
	logger *logger.Logger
}

var (
	wellKnownConfiguration = make(map[string]any)
	rwMutex                sync.RWMutex
	baseKeyWellKnown       = "base_key"
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

func UpdateConfigurationBaseKey(config any) {
	rwMutex.Lock()
	defer rwMutex.Unlock()
	wellKnownConfiguration[baseKeyWellKnown] = config
}

func NewRegistration() *serviceregistry.Service[wellknownconfigurationconnect.WellKnownServiceHandler] {
	return &serviceregistry.Service[wellknownconfigurationconnect.WellKnownServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[wellknownconfigurationconnect.WellKnownServiceHandler]{
			Namespace:       "wellknown",
			ServiceDesc:     &wellknown.WellKnownService_ServiceDesc,
			ConnectRPCFunc:  wellknownconfigurationconnect.NewWellKnownServiceHandler,
			GRPCGatewayFunc: wellknown.RegisterWellKnownServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (wellknownconfigurationconnect.WellKnownServiceHandler, serviceregistry.HandlerServer) {
				wk := &WellKnownService{logger: srp.Logger}
				return wk, nil
			},
		},
	}
}

func (s WellKnownService) GetWellKnownConfiguration(ctx context.Context, _ *connect.Request[wellknown.GetWellKnownConfigurationRequest]) (*connect.Response[wellknown.GetWellKnownConfigurationResponse], error) {
	rwMutex.RLock()
	s.logger.TraceContext(ctx, "wellknown configuration contents", slog.Any("config", wellKnownConfiguration))
	cfg, err := structpb.NewStruct(wellKnownConfiguration)
	rwMutex.RUnlock()
	if err != nil {
		s.logger.Error("failed to create struct for wellknown configuration", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create struct for wellknown configuration"))
	}

	rsp := &wellknown.GetWellKnownConfigurationResponse{
		Configuration: cfg,
	}
	return connect.NewResponse(rsp), nil
}
