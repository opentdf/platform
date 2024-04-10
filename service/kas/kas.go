package kas

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/service/kas/access"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"golang.org/x/oauth2"
	"log/slog"
	"net/url"
)

func loadIdentityProvider(cfg serviceregistry.ServiceConfig) *oidc.IDTokenVerifier {
	ctx := context.Background()
	if cfg.ExtraProps == nil || cfg.ExtraProps["issuer"] == nil {
		panic(errors.New("services.kas.issuer is required"))
	}
	oidcIssuerURL, ok := cfg.ExtraProps["issuer"].(string)
	if !ok {
		panic(errors.New("services.kas.issuer must be a string"))
	}
	if cfg.ExtraProps == nil || cfg.ExtraProps["discovery"] == nil {
		panic(errors.New("services.kas.discovery is required"))
	}
	discoveryBaseURL, ok := cfg.ExtraProps["discovery"].(string)
	if !ok {
		panic(errors.New("services.kas.discovery must be a string"))
	}
	if discoveryBaseURL != "" {
		ctx = oidc.InsecureIssuerURLContext(ctx, oidcIssuerURL)
	} else {
		discoveryBaseURL = oidcIssuerURL
	}
	provider, err := oidc.NewProvider(ctx, discoveryBaseURL)
	if err != nil {
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
			// FIXME msg="mismatched key access url" keyAccessURL=http://localhost:9000 kasURL=https://:9000
			kasURLString := "https://" + srp.OTDF.HTTPServer.Addr
			kasURI, err := url.Parse(kasURLString)
			if err != nil {
				panic(fmt.Errorf("invalid kas address [%s] %w", kasURLString, err))
			}

			p := access.Provider{
				URI:            *kasURI,
				AttributeSvc:   nil,
				CryptoProvider: srp.OTDF.CryptoProvider,
				OIDCVerifier:   loadIdentityProvider(srp.Config),
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
