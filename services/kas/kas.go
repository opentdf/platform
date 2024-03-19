package kas

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/pkg/serviceregistry"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/services/kas/access"
	"golang.org/x/oauth2"
)

func loadIdentityProvider() *oidc.IDTokenVerifier {
	oidcIssuerURL := "http://localhost:8888/auth/realms/opentdf"
	discoveryBaseURL := "http://localhost:8888/auth/realms/opentdf"
	ctx := context.Background()
	if discoveryBaseURL != "" {
		ctx = oidc.InsecureIssuerURLContext(ctx, oidcIssuerURL)
	} else {
		discoveryBaseURL = oidcIssuerURL
	}
	provider, err := oidc.NewProvider(ctx, discoveryBaseURL)
	if err != nil {
		slog.Error("OIDC_ISSUER_URL provider fail", "err", err, "OIDC_ISSUER_URL", oidcIssuerURL, "OIDC_DISCOVERY_BASE_URL", os.Getenv("OIDC_DISCOVERY_BASE_URL"))
		panic(err)
	}
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "",
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID},
	}
	slog.Debug("oauth configuring", "oauth2Config", oauth2Config)
	oidcConfig := oidc.Config{
		ClientID:                   "",
		SupportedSigningAlgs:       nil,
		SkipClientIDCheck:          true,
		SkipExpiryCheck:            false,
		SkipIssuerCheck:            false,
		Now:                        nil,
		InsecureSkipSignatureCheck: false,
	}
	return provider.Verifier(&oidcConfig)
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		Namespace:   "kas",
		ServiceDesc: &kaspb.AccessService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			hsm := srp.OTDF.HSM
			if hsm == nil {
				slog.Error("hsm not enabled")
				panic(fmt.Errorf("hsm not enabled"))
			}
			kasURLString := "https://" + srp.OTDF.HTTPServer.Addr
			kasURI, err := url.Parse(kasURLString)
			if err != nil {
				panic(fmt.Errorf("invalid kas address [%s] %w", kasURLString, err))
			}

			p := access.Provider{
				URI:          *kasURI,
				AttributeSvc: nil,
				Session:      *hsm,
				OIDCVerifier: loadIdentityProvider(),
			}
			return &p, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				kas, ok := server.(*access.Provider)
				if !ok {
					panic("invalid kas server object")
				}
				return kaspb.RegisterAccessServiceHandlerServer(ctx, mux, kas)
			}
		},
	}
}
