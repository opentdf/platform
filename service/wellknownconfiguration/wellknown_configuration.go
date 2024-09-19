package wellknownconfiguration

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"connectrpc.com/connect"
	wellknown "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect"
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

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "wellknown",
		ServiceDesc: &wellknown.WellKnownService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			ws := &WellKnownService{logger: srp.Logger}
			return ws, func(ctx context.Context, mux *http.ServeMux, server any) {
				// interceptor := srp.OTDF.AuthN.ConnectUnaryServerInterceptor()
				interceptors := connect.WithInterceptors()
				path, handler := wellknownconfigurationconnect.NewWellKnownServiceHandler(ws, interceptors)
				mux.Handle(path, handler)
			}
		},
	}
}

func (s WellKnownService) GetWellKnownConfiguration(_ context.Context, _ *connect.Request[wellknown.GetWellKnownConfigurationRequest]) (*connect.Response[wellknown.GetWellKnownConfigurationResponse], error) {
	println("GetWellKnownConfiguration: HERE")
	rwMutex.RLock()
	cfg, err := structpb.NewStruct(wellKnownConfiguration)
	rwMutex.RUnlock()
	if err != nil {
		s.logger.Error("failed to create struct for wellknown configuration", slog.String("error", err.Error()))
		return nil, status.Error(codes.Internal, "failed to create struct for wellknown configuration")
	}
	rsp := &wellknown.GetWellKnownConfigurationResponse{
		Configuration: cfg,
	}
	return &connect.Response[wellknown.GetWellKnownConfigurationResponse]{Msg: rsp}, nil
}
