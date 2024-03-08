package kas

import (
	"context"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/pkg/serviceregistry"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/services/kas/access"
)

type KasService struct {
	kaspb.UnimplementedAccessServiceServer
	db *db.Client
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "policy",
		ServiceDesc: &kaspb.AccessService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			return &KasService{db: srp.DBClient}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				return kaspb.RegisterAccessServiceHandlerServer(ctx, mux, server.(kaspb.AccessServiceServer))
			}
		},
	}
}

func (s KasService) Info(ctx context.Context, req *kaspb.InfoRequest) (*kaspb.InfoResponse, error) {
	return &kaspb.InfoResponse{
		Version: "1.0.0",
	}, nil
}

func (s KasService) PublicKey(ctx context.Context, req *kaspb.PublicKeyRequest) (*kaspb.PublicKeyResponse, error) {
	provider := access.Provider{}
	resp, err := provider.PublicKey(ctx, &kaspb.PublicKeyRequest{})
	if err != nil {
		return nil, err
	}
	return &kaspb.PublicKeyResponse{
		PublicKey: resp.PublicKey,
	}, nil
}

func (s KasService) Rewrap(ctx context.Context, req *kaspb.RewrapRequest) (*kaspb.RewrapResponse, error) {
	provider := access.Provider{}
	resp, err := provider.Rewrap(ctx, &kaspb.RewrapRequest{})
	if err != nil {
		return nil, err
	}
	return &kaspb.RewrapResponse{
		EntityWrappedKey: resp.EntityWrappedKey,
	}, nil
}
func MakeAccessService() *KasService {
	return &KasService{}
}
