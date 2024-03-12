package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"google.golang.org/grpc/reflection"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"plugin"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/miekg/pkcs11"
	"github.com/opentdf/platform/services/kas/access"
	"github.com/opentdf/platform/services/kas/p11"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	hostname = "localhost"
)

func loadIdentityProvider() oidc.IDTokenVerifier {
	oidcIssuerURL := os.Getenv("OIDC_ISSUER_URL")
	discoveryBaseURL := os.Getenv("OIDC_DISCOVERY_BASE_URL")
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
	return *provider.Verifier(&oidcConfig)
}

type hsmContext struct {
	pin string
	ctx *pkcs11.Ctx
}

type hsmSession struct {
	c       *hsmContext
	session pkcs11.SessionHandle
}

func newHSMContext() (*hsmContext, error) {
	pin := os.Getenv("PKCS11_PIN")
	pkcs11ModulePath := os.Getenv("PKCS11_MODULE_PATH")
	slog.Debug("loading pkcs11 module", "pkcs11ModulePath", pkcs11ModulePath)
	ctx := pkcs11.New(pkcs11ModulePath)
	if err := ctx.Initialize(); err != nil {
		return nil, errors.Join(access.ErrHSM, err)
	}

	hc := new(hsmContext)
	hc.pin = pin
	hc.ctx = ctx
	return hc, nil
}

func destroyHSMContext(hc *hsmContext) {
	if hc == nil {
		slog.Error("destroyHSMContext error, input param is nil")
		return
	}

	defer hc.ctx.Destroy()
	err := hc.ctx.Finalize()
	if err != nil {
		slog.Error("pkcs11 error finalizing module", "err", err)
	}
}

func newHSMSession(hc *hsmContext) (*hsmSession, error) {
	if hc == nil {
		slog.Error("destroyHSMContext error, input param is nil")
		return nil, errors.Join(access.ErrHSM)
	}
	slot, err := strconv.ParseInt(os.Getenv("PKCS11_SLOT_INDEX"), 10, 32)
	if err != nil {
		slog.Error("pkcs11 PKCS11_SLOT_INDEX parse error", "err", err, "PKCS11_SLOT_INDEX", os.Getenv("PKCS11_SLOT_INDEX"))
		return nil, errors.Join(access.ErrHSM, err)
	}

	slots, err := hc.ctx.GetSlotList(true)
	if err != nil {
		slog.Error("pkcs11 error getting slots", "err", err)
		return nil, errors.Join(access.ErrHSM, err)
	}
	if int(slot) >= len(slots) || slot < 0 {
		slog.Error("pkcs11 PKCS11_SLOT_INDEX is invalid", "slot_index", slot, "slots", slots)
		return nil, errors.Join(access.ErrHSM, err)
	}

	session, err := hc.ctx.OpenSession(slots[slot], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		slog.Error("pkcs11 error opening session", "slot_index", slot, "slots", slots)
		return nil, errors.Join(access.ErrHSM, err)
	}

	hs := new(hsmSession)
	hs.c = hc
	hs.session = session
	return hs, nil
}

func destroyHSMSession(hs *hsmSession) {
	if hs == nil {
		slog.Error("destroyHSMSession err, input param is nil")
		return
	}
	err := hs.c.ctx.CloseSession(hs.session)
	if err != nil {
		slog.Error("pkcs11 error closing session", "err", err)
	}
}

func inferLogger(loglevel, format string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(loglevel) {
	case "info":
		level = slog.LevelInfo
	case "warning":
		level = slog.LevelWarn
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "debug":
		level = slog.LevelDebug
	}
	if strings.ToLower(format) == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

type BackendMiddleware interface {
	AuditHook(f http.Handler) http.Handler
}

func loadAuditHook() func(f http.Handler) http.Handler {
	auditEnabled := os.Getenv("AUDIT_ENABLED")
	slog.Info("gokas-info", "AUDIT_ENABLED", auditEnabled)

	if auditEnabled != "true" {
		return func(f http.Handler) http.Handler {
			return f
		}
	}

	testDir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	pluginPath := filepath.Join(testDir, "..", "..", "plugins", "audit_hooks.so")

	slog.Info("Install plugin", "path", pluginPath)

	plug, err := plugin.Open(pluginPath)
	if err != nil {
		panic(err)
	}
	symMiddleware, err := plug.Lookup("Middleware")
	if err != nil {
		panic(err)
	}
	mid, _ := symMiddleware.(BackendMiddleware)

	return mid.AuditHook
}

func validatePort(port string) (int, error) {
	if port == "" {
		return 0, nil
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, errors.Join(access.ErrConfig, err)
	}
	if p < 0 || p > 65535 {
		return 0, access.ErrConfig
	}
	return p, nil
}

func main() {
	slog.SetDefault(inferLogger(os.Getenv("LOG_LEVEL"), os.Getenv("LOG_FORMAT")))

	// version and build information
	//stats := version.GetVersion()

	//slog.Info("gokas-info", "version", stats.Version, "version_long", stats.VersionLong, "build_time", stats.BuildTime)

	portGRPC, err := validatePort(os.Getenv("SERVER_GRPC_PORT"))
	if err != nil {
		slog.Error("Invalid port specified in SERVER_GRPC_PORT env variable", "err", err)
		panic(err)
	}

	portHTTP, err := validatePort(os.Getenv("SERVER_HTTP_PORT"))
	if err != nil {
		slog.Error("Invalid port specified in SERVER_HTTP_PORT env variable", "err", err)
		panic(err)
	}
	/*attrSvcURI, err := access.ResolveAttributeAuthority(os.Getenv("ATTR_AUTHORITY_HOST"))
	if err != nil {
		slog.Error("invalid attribute authority", "err", err)
		panic(err)
	}*/

	kasURLString := os.Getenv("KAS_URL")
	if len(kasURLString) == 0 {
		kasURLString = "https://" + hostname + ":" + strconv.Itoa(portHTTP)
	}
	kasURI, err := url.Parse(kasURLString)
	if err != nil {
		slog.Error("invalid KAS_URL", "err", err, "url", kasURLString)
		panic(err)
	}
	kas := access.Provider{
		URI:          *kasURI,
		AttributeSvc: nil,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRSA: rsa.PublicKey{},
		PrivateKeyEC: p11.Pkcs11PrivateKeyEC{},
		PublicKeyEC:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},
		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	oidcVerifier := loadIdentityProvider()
	kas.OIDCVerifier = &oidcVerifier

	// PKCS#11
	hc, err := newHSMContext()
	if err != nil {
		slog.Error("pkcs11 error initializing hsm", "err", err)
		panic(err)
	}
	defer destroyHSMContext(hc)

	info, err := hc.ctx.GetInfo()
	if err != nil {
		slog.Error("pkcs11 error querying module info", "err", err)
		panic(err)
	}
	slog.Info("pkcs11 module", "pkcs11info", info)

	hs, err := newHSMSession(hc)
	if err != nil {
		panic(err)
	}
	defer destroyHSMSession(hs)

	var keyID []byte

	err = hc.ctx.Login(hs.session, pkcs11.CKU_USER, hc.pin)
	if err != nil {
		slog.Error("pkcs11 error logging in as CKU USER", "err", err)
		panic(err)
	}
	defer func(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle) {
		err := ctx.Logout(sh)
		if err != nil {
			slog.Error("pkcs11 error logging out", "err", err)
		}
	}(hc.ctx, hs.session)

	info, err = hc.ctx.GetInfo()
	if err != nil {
		slog.Error("pkcs11 error querying module info", "err", err)
		panic(err)
	}
	slog.Info("pkcs11 module info after initialization", "pkcs11info", info)

	slog.Debug("Finding RSA key to wrap.")
	rsaLabel := os.Getenv("PKCS11_LABEL_PUBKEY_RSA") // development-rsa-kas
	keyHandle, err := findKey(hs, pkcs11.CKO_PRIVATE_KEY, keyID, rsaLabel)
	if err != nil {
		slog.Error("pkcs11 error finding key", "err", err)
		panic(err)
	}

	// set private key
	kas.PrivateKey = p11.NewPrivateKeyRSA(keyHandle)

	ecLabel := os.Getenv("PKCS11_LABEL_PUBKEY_EC") // development-rsa-kas
	keyHandleEC, err := findKey(hs, pkcs11.CKO_PRIVATE_KEY, keyID, ecLabel)
	if err != nil {
		slog.Error("pkcs11 error finding key", "err", err)
		panic(err)
	}

	kas.PrivateKeyEC = p11.NewPrivateKeyEC(keyHandleEC)

	// initialize p11.pkcs11session
	kas.Session = p11.NewSession(hs.c.ctx, hs.session)

	// RSA Cert
	slog.Debug("Finding RSA certificate", "rsaLabel", rsaLabel)
	certHandle, err := findKey(hs, pkcs11.CKO_CERTIFICATE, keyID, rsaLabel)
	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
	}
	if err != nil {
		slog.Error("pkcs11 error finding RSA cert", "err", err)
		panic(err)
	}
	attrs, err := hs.c.ctx.GetAttributeValue(hs.session, certHandle, certTemplate)
	if err != nil {
		slog.Error("pkcs11 error getting attribute from cert", "err", err)
		panic(err)
	}

	for _, a := range attrs {
		if a.Type == pkcs11.CKA_VALUE {
			certRsa, err := x509.ParseCertificate(a.Value)
			if err != nil {
				slog.Error("x509 parse error", "err", err)
				panic(err)
			}
			kas.Certificate = *certRsa
		}
	}

	// RSA Public key
	rsaPublicKey, ok := kas.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		slog.Error("public key RSA cert error")
		panic("public key RSA cert error")
	}
	kas.PublicKeyRSA = *rsaPublicKey

	// EC Cert
	certECHandle, err := findKey(hs, pkcs11.CKO_CERTIFICATE, keyID, ecLabel)
	if err != nil {
		slog.Error("public key EC cert error")
		panic("public key EC cert error")
	}
	certECTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
	}
	ecCertAttrs, err := hs.c.ctx.GetAttributeValue(hs.session, certECHandle, certECTemplate)
	if err != nil {
		slog.Error("public key EC cert error", "err", err)
		panic(err)
	}

	for _, a := range ecCertAttrs {
		if a.Type == pkcs11.CKA_VALUE {
			// exponent := big.NewInt(0)
			// exponent.SetBytes(a.Value)
			certEC, err := x509.ParseCertificate(a.Value)
			if err != nil {
				slog.Error("x509 parse error", "err", err)
				panic(err)
			}
			kas.CertificateEC = *certEC
		}
	}

	// EC Public Key
	ecPublicKey, ok := kas.CertificateEC.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		slog.Error("public key from cert fail for EC")
		panic("EC parse fail")
	}
	kas.PublicKeyEC = *ecPublicKey

	portGRPC = loadGRPC(portGRPC, &kas)

	if portHTTP == 0 {
		slog.Debug("gRPC only")
		return
	}

	conn, err := grpc.DialContext(
		context.Background(),
		fmt.Sprintf("0.0.0.0:%d", portGRPC),
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		slog.Error("Failed to dial internal gRPC server", "err", err)
		panic(err)
	}

	gwmux := runtime.NewServeMux()
	// Register Greeter
	err = kaspb.RegisterAccessServiceHandler(context.Background(), gwmux, conn)
	if err != nil {
		slog.Error("Failed to register gateway", "err", err)
		panic(err)
	}

	auditHook := loadAuditHook()
	gwServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", portHTTP),
		Handler: auditHook(gwmux),
	}

	slog.Info(fmt.Sprintf("Serving gRPC-Gateway on [http://0.0.0.0:%d] as [%v], connected to gRPC on [%d]", portHTTP, kas.URI, portGRPC))
	if err := gwServer.ListenAndServe(); err != nil {
		slog.Error("server failure", "err", err)
	}
}

func loadGRPC(port int, kas *access.Provider) int {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		slog.Error("gRPC listen failure", "err", err)
		panic(err)
	}

	s := grpc.NewServer()
	reflection.Register(s)
	healthcheck := health.NewServer()
	healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	healthgrpc.RegisterHealthServer(s, healthcheck)

	kaspb.RegisterAccessServiceServer(s, kas)
	slog.Info("Serving gRPC on [" + lis.Addr().String() + "] for server known as[" + kas.URI.String() + "]")

	go func() {
		// FIXME channel join
		if err := s.Serve(lis); err != nil {
			slog.Error("server failure", "err", err)
		}
	}()

	return lis.Addr().(*net.TCPAddr).Port
}

func findKey(hs *hsmSession, class uint, id []byte, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if len(id) > 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)))
	}

	// CloudHSM does not support CKO_PRIVATE_KEY set to false
	if class == pkcs11.CKO_PRIVATE_KEY {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true))
	}
	var handle pkcs11.ObjectHandle
	var err error
	if err = hs.c.ctx.FindObjectsInit(hs.session, template); err != nil {
		return handle, errors.Join(access.ErrHSM, err)
	}
	defer func() {
		finalErr := hs.c.ctx.FindObjectsFinal(hs.session)
		if err != nil {
			err = finalErr
			slog.Error("pcks11 FindObjectsFinal failure", "err", err)
		}
	}()

	var handles []pkcs11.ObjectHandle
	const maxHandles = 20
	handles, _, err = hs.c.ctx.FindObjects(hs.session, maxHandles)
	if err != nil {
		return handle, errors.Join(access.ErrHSM, err)
	}

	switch len(handles) {
	case 0:
		err = fmt.Errorf("key not found")
	case 1:
		handle = handles[0]
	default:
		err = fmt.Errorf("multiple key found")
	}

	return handle, err
}

type Error string

func (e Error) Error() string {
	return string(e)
}
