package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/server"
	"github.com/opentdf/platform/pkg/serviceregistry"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/services/kas/access"
)

type KasService struct {
	kaspb.UnimplementedAccessServiceServer
	o *server.OpenTDFServer
	p *access.Provider
}

func (s *KasService) initProvider() error {
	if s.p != nil {
		slog.Info("KAS already initialized")
		return nil
	}
	if s.o.HSM == nil {
		slog.Error("hsm not enabled")
		return fmt.Errorf("hsm not enabled")
	}
	kasURLString := "https://" + s.o.HTTPServer.Addr
	kasURI, err := url.Parse(kasURLString)
	if err != nil {
		return fmt.Errorf("invalid kas address [%s] %w", kasURLString, err)
	}

	s.p = &access.Provider{
		URI:          *kasURI,
		AttributeSvc: nil,
		Session:      *s.o.HSM,
		OIDCVerifier: nil,
	}

	// TODO: Add Authorization or Attribute service??
	// TODO: Add OIDC Verifier

	return nil
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "kas",
		ServiceDesc: &kaspb.AccessService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			k := KasService{o: srp.OTDF}
			err := k.initProvider()
			if err != nil {
				panic(err)
			}
			return &k, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				kas, ok := server.(kaspb.AccessServiceServer)
				if !ok {
					panic("invalid kas server object")
				}
				return kaspb.RegisterAccessServiceHandlerServer(ctx, mux, kas)
			}
		},
	}
}

func (s *KasService) Info(ctx context.Context, req *kaspb.InfoRequest) (*kaspb.InfoResponse, error) {
	return &kaspb.InfoResponse{
		Version: "1.0.0",
	}, nil
}

func (s *KasService) PublicKey(ctx context.Context, req *kaspb.PublicKeyRequest) (*kaspb.PublicKeyResponse, error) {
	resp, err := s.p.PublicKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return &kaspb.PublicKeyResponse{
		PublicKey: resp.PublicKey,
	}, nil
}

func (s KasService) Rewrap(ctx context.Context, req *kaspb.RewrapRequest) (*kaspb.RewrapResponse, error) {
	resp, err := s.p.Rewrap(ctx, req)
	if err != nil {
		return nil, err
	}
	return &kaspb.RewrapResponse{
		EntityWrappedKey: resp.EntityWrappedKey,
	}, nil
}
