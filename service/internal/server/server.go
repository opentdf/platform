package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/textproto"
	"regexp"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/grpcreflect"
	"connectrpc.com/validate"
	"github.com/go-chi/cors"
	"github.com/opentdf/platform/sdk"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/internal/connectcompat"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/internal/server/realip"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/tracing"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

const (
	defaultWriteTimeout     time.Duration = 10 * time.Second
	defaultReadTimeout      time.Duration = 10 * time.Second
	shutdownTimeout         time.Duration = 5 * time.Second
	maxPprofDurationSeconds               = 30
	maxPprofFormBodyBytes   int64         = 1024
)

type Error string

func (e Error) Error() string {
	return string(e)
}

// Configurations for the server
type Config struct {
	Auth auth.Config `mapstructure:"auth" json:"auth"`

	Cache cache.Config `mapstructure:"cache" json:"cache"`

	GRPC GRPCConfig `mapstructure:"grpc" json:"grpc"`
	// To Deprecate: Use the WithKey[X]Provider StartOptions to register trust providers.
	CryptoProvider          security.Config                          `mapstructure:"cryptoProvider" json:"cryptoProvider"`
	TLS                     TLSConfig                                `mapstructure:"tls" json:"tls"`
	CORS                    CORSConfig                               `mapstructure:"cors" json:"cors"`
	WellKnownConfigRegister func(namespace string, config any) error `mapstructure:"-" json:"-"`

	// Programmatic interceptors injected at startup (not loaded from config).
	// The connect-go v1 interceptors cover only services registered with a v1
	// handler; registering a v2 service fails while any are set.
	ExtraConnectInterceptors []connect.Interceptor `mapstructure:"-" json:"-"`
	ExtraIPCInterceptors     []connect.Interceptor `mapstructure:"-" json:"-"`
	// ExtraConnectServerInterceptors and ExtraIPCServerInterceptors carry both
	// connect-go forms of each interceptor and run after the v1-only extras.
	ExtraConnectServerInterceptors []ExtraInterceptor `mapstructure:"-" json:"-"`
	ExtraIPCServerInterceptors     []ExtraInterceptor `mapstructure:"-" json:"-"`
	// Port to listen on
	Port           int    `mapstructure:"port" json:"port" default:"8080"`
	Host           string `mapstructure:"host,omitempty" json:"host"`
	PublicHostname string `mapstructure:"public_hostname,omitempty" json:"publicHostname"`
	// Http server config
	HTTPServerConfig HTTPServerConfig `mapstructure:"http" json:"http"`
	// Enable pprof
	EnablePprof bool `mapstructure:"enable_pprof" json:"enable_pprof" default:"false"`
	// Trace is for configuring open telemetry based tracing.
	Trace tracing.Config `mapstructure:"trace" json:"trace"`

	// AuthzResolverRegistry contains service-registered resolvers used by the auth interceptor.
	AuthzResolverRegistry *authz.ResolverRegistry `mapstructure:"-" json:"-"`
}

func (c Config) LogValue() slog.Value {
	group := []slog.Attr{
		slog.Any("auth_config", c.Auth),
		slog.Any("grpc", c.GRPC),
		slog.Any("tls", c.TLS),
		slog.Any("cors", c.CORS),
		slog.Int("port", c.Port),
		slog.String("host", c.Host),
		slog.Bool("enable_pprof", c.EnablePprof),
	}

	// CryptoProvider is deprecated in favor of the trust package.
	if !c.CryptoProvider.IsEmpty() {
		group = append(group, slog.Any("crypto_provider", c.CryptoProvider))
	}

	return slog.GroupValue(group...)
}

// GRPC Server specific configurations
type GRPCConfig struct {
	// Enable reflection for grpc server (default: true)
	ReflectionEnabled bool `mapstructure:"reflectionEnabled" json:"reflectionEnabled" default:"true"`

	// MaxRecvMsgSizeBytes caps each request message that external clients send to
	// Connect, gRPC, and gRPC-Web handlers, measured after decompression.
	MaxRecvMsgSizeBytes int `mapstructure:"maxRecvMsgSize" json:"maxRecvMsgSize" default:"4194304"` // 4MB = 4 * 1024 * 1024 = 4194304

	// MaxCallRecvMsgSizeBytes and MaxCallSendMsgSizeBytes configure the in-process client used for IPC.
	MaxCallRecvMsgSizeBytes int `mapstructure:"maxCallRecvMsgSize" json:"maxCallRecvMsgSize" default:"4194304"` // 4MB = 4 * 1024 * 1024 = 4194304
	MaxCallSendMsgSizeBytes int `mapstructure:"maxCallSendMsgSize" json:"maxCallSendMsgSize" default:"4194304"` // 4MB = 4 * 1024 * 1024 = 4194304
}

// TLS Configuration for the server
type TLSConfig struct {
	// Enable TLS for the server (default: false)
	Enabled bool `mapstructure:"enabled" json:"enabled" default:"false"`
	// Path to the certificate file
	Cert string `mapstructure:"cert" json:"cert"`
	// Path to the key file
	Key string `mapstructure:"key" json:"key"`
}

type HTTPServerConfig struct {
	ReadTimeout       time.Duration `mapstructure:"readTimeout" json:"readTimeout"`
	ReadHeaderTimeout time.Duration `mapstructure:"readHeaderTimeout" json:"readHeaderTimeout"`
	WriteTimeout      time.Duration `mapstructure:"writeTimeout" json:"writeTimeout"`
	IdleTimeout       time.Duration `mapstructure:"idleTimeout" json:"idleTimeout"`
	MaxHeaderBytes    int           `mapstructure:"maxHeaderBytes" json:"maxHeaderBytes"`
	TrustedProxies    []string      `mapstructure:"trustedProxies" json:"trustedProxies"`
}

// CORS Configuration for the server
type CORSConfig struct {
	// Enable CORS for the server (default: true)
	Enabled          bool     `mapstructure:"enabled" json:"enabled" default:"true"`
	AllowedOrigins   []string `mapstructure:"allowedorigins" json:"allowedorigins"`
	AllowedMethods   []string `mapstructure:"allowedmethods" json:"allowedmethods" default:"[\"GET\",\"POST\",\"PATCH\",\"DELETE\",\"OPTIONS\"]"`
	AllowedHeaders   []string `mapstructure:"allowedheaders" json:"allowedheaders" default:"[\"Accept\",\"Accept-Encoding\",\"Authorization\",\"Connect-Protocol-Version\",\"Content-Length\",\"Content-Type\",\"Dpop\",\"X-CSRF-Token\",\"X-Requested-With\",\"X-Rewrap-Additional-Context\"]"`
	ExposedHeaders   []string `mapstructure:"exposedheaders" json:"exposedheaders"`
	AllowCredentials bool     `mapstructure:"allowcredentials" json:"allowcredentials" default:"true"`
	MaxAge           int      `mapstructure:"maxage" json:"maxage" default:"3600"`
	Debug            bool     `mapstructure:"debug" json:"debug"`

	// Additive fields - appended to base lists at runtime without replacing defaults
	AdditionalMethods        []string `mapstructure:"additionalmethods" json:"additionalmethods"`
	AdditionalHeaders        []string `mapstructure:"additionalheaders" json:"additionalheaders"`
	AdditionalExposedHeaders []string `mapstructure:"additionalexposedheaders" json:"additionalexposedheaders"`
}

// mergeStringSlices combines base and additional slices, removing duplicates.
// The order is: base items first, then additional items (preserving order within each).
// Comparison is case-sensitive.
func mergeStringSlices(base, additional []string) []string {
	if len(additional) == 0 {
		return base
	}
	if len(base) == 0 {
		return additional
	}

	seen := make(map[string]struct{}, len(base)+len(additional))
	result := make([]string, 0, len(base)+len(additional))

	for _, v := range base {
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	for _, v := range additional {
		if _, exists := seen[v]; !exists {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

// mergeHeaderSlices combines base and additional HTTP header slices with case-insensitive
// deduplication. HTTP headers are case-insensitive per RFC 7230, so "Authorization" and
// "authorization" are treated as duplicates. The first occurrence's original casing is preserved.
func mergeHeaderSlices(base, additional []string) []string {
	if len(additional) == 0 {
		return base
	}
	if len(base) == 0 {
		return additional
	}

	// Use canonical header keys for case-insensitive comparison
	seen := make(map[string]struct{}, len(base)+len(additional))
	result := make([]string, 0, len(base)+len(additional))

	for _, v := range base {
		canonical := textproto.CanonicalMIMEHeaderKey(v)
		if _, exists := seen[canonical]; !exists {
			seen[canonical] = struct{}{}
			result = append(result, v) // Preserve original casing
		}
	}
	for _, v := range additional {
		canonical := textproto.CanonicalMIMEHeaderKey(v)
		if _, exists := seen[canonical]; !exists {
			seen[canonical] = struct{}{}
			result = append(result, v) // Preserve original casing
		}
	}
	return result
}

// EffectiveMethods returns AllowedMethods merged with AdditionalMethods.
func (c CORSConfig) EffectiveMethods() []string {
	return mergeStringSlices(c.AllowedMethods, c.AdditionalMethods)
}

// EffectiveHeaders returns AllowedHeaders merged with AdditionalHeaders.
// Uses case-insensitive deduplication since HTTP headers are case-insensitive per RFC 7230.
func (c CORSConfig) EffectiveHeaders() []string {
	return mergeHeaderSlices(c.AllowedHeaders, c.AdditionalHeaders)
}

// EffectiveExposedHeaders returns ExposedHeaders merged with AdditionalExposedHeaders.
// Uses case-insensitive deduplication since HTTP headers are case-insensitive per RFC 7230.
func (c CORSConfig) EffectiveExposedHeaders() []string {
	return mergeHeaderSlices(c.ExposedHeaders, c.AdditionalExposedHeaders)
}

type ConnectRPC struct {
	Mux *http.ServeMux
	// Interceptors are the handler options for services registered with a
	// connect-go v1 handler.
	Interceptors []connect.HandlerOption
	// ServerInterceptors wrap every service registered on a connect-go v2 server.
	ServerInterceptors []connectv2.ServerInterceptor
	// MountOptions apply to every connect-go v2 service; options a service
	// supplies follow them.
	MountOptions      []connecthttp.Option
	ServiceReflection []string

	// missingV1 and missingV2 name extra interceptors without a form for that
	// connect-go version.
	missingV1, missingV2 []string
}

type OpenTDFServer struct {
	AuthN               *auth.Authentication
	HTTPMux             *http.ServeMux
	HTTPServer          *http.Server
	ConnectRPCInProcess *inProcessServer
	ConnectRPC          *ConnectRPC
	CacheManager        *cache.Manager
	reflectionEnabled   bool
	maxRecvMsgSize      int

	// To Deprecate: Use the TrustKeyIndex and TrustKeyManager instead
	CryptoProvider *security.StandardCrypto
	Listener       net.Listener

	logger *logger.Logger

	PublicHostname string
}

/*
Still need to flush this out for internal communication. Would like to leverage grpc
as mechanism for internal communication. Hopefully making it easier to define service boundaries.
https://github.com/heroku/x/blob/master/grpc/grpcserver/inprocess.go
https://github.com/valyala/fasthttp/blob/master/fasthttputil/inmemory_listener.go
*/
type inProcessServer struct {
	srv                *memhttp.Server
	logger             *logger.Logger
	maxCallRecvMsgSize int
	maxCallSendMsgSize int
	*ConnectRPC
}

func NewOpenTDFServer(config Config, logger *logger.Logger, cacheManager *cache.Manager) (*OpenTDFServer, error) {
	var (
		authN *auth.Authentication
		err   error
	)

	// Add authN interceptor
	// TODO Remove this conditional once we move to the hardening phase (https://github.com/opentdf/platform/issues/381)
	if config.Auth.Enabled {
		authN, err = auth.NewAuthenticator(
			context.Background(),
			config.Auth,
			logger,
			config.WellKnownConfigRegister,
			auth.WithAuthzResolverRegistry(config.AuthzResolverRegistry),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create authentication interceptor: %w", err)
		}
		logger.Debug("authentication interceptor enabled")
	} else {
		logger.Warn("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP set `server.auth.dpop.enforce = false`")
	}

	ipcInts := connectRPCInterceptors{
		requestIP:   realip.ConnectTrustedRequestIPUnaryInterceptor(sdkAudit.RequestIPHeaderKey.String()),
		requestIPV2: realip.ConnectTrustedRequestIPInterceptorV2(sdkAudit.RequestIPHeaderKey.String()),
		extras:      append(v1OnlyExtras("WithIPCInterceptors", config.ExtraIPCInterceptors), config.ExtraIPCServerInterceptors...),
	}
	externalInts := connectRPCInterceptors{
		extras: append(v1OnlyExtras("WithConnectInterceptors", config.ExtraConnectInterceptors), config.ExtraConnectServerInterceptors...),
	}
	if config.Auth.Enabled && authN != nil {
		ipcInts.auth = []connect.Interceptor{authN.IPCUnaryServerInterceptor()}
		ipcInts.authV2 = []connectv2.ServerInterceptor{authN.IPCServerInterceptorV2()}
		externalInts.auth = []connect.Interceptor{
			authN.ConnectAuthNInterceptor(),
			authN.ConnectAuthZInterceptor(),
		}
		externalInts.authV2 = []connectv2.ServerInterceptor{
			authN.ConnectAuthNInterceptorV2(),
			authN.ConnectAuthZInterceptorV2(),
		}
	}

	connectRPCIpc, err := newConnectRPC(config, ipcInts, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect rpc ipc server: %w", err)
	}
	// connect-go v2 defaults to a 4 MiB read limit; in-process calls keep the
	// unlimited reads they have on v1.
	connectRPCIpc.MountOptions = []connecthttp.Option{connecthttp.WithReadMaxBytes(0)}

	externalInts.requestIP, err = realip.ConnectRealIPUnaryInterceptor(config.HTTPServerConfig.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("failed to configure trusted proxies: %w", err)
	}
	externalInts.requestIPV2, err = realip.ConnectRealIPInterceptorV2(config.HTTPServerConfig.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("failed to configure trusted proxies: %w", err)
	}
	connectRPC, err := newConnectRPC(config, externalInts, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect rpc server: %w", err)
	}
	// Prepend so options a service appends when registering its handler take precedence.
	connectRPC.Interceptors = append(externalConnectHandlerOptions(config), connectRPC.Interceptors...)
	connectRPC.Interceptors = append(externalConnectRequestGates(config, authN), connectRPC.Interceptors...)
	connectRPC.MountOptions = ReadLimitMountOptions(config.GRPC.MaxRecvMsgSizeBytes)

	httpMux := http.NewServeMux()

	// Create http server
	httpServer, err := newHTTPServer(config, connectRPC.Mux, httpMux, authN, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create http server: %w", err)
	}

	o := OpenTDFServer{
		AuthN:             authN,
		HTTPMux:           httpMux,
		HTTPServer:        httpServer,
		CacheManager:      cacheManager,
		ConnectRPC:        connectRPC,
		reflectionEnabled: config.GRPC.ReflectionEnabled,
		maxRecvMsgSize:    config.GRPC.MaxRecvMsgSizeBytes,
		ConnectRPCInProcess: &inProcessServer{
			logger:             logger.With("ipc_server", "true"),
			srv:                memhttp.New(connectRPCIpc.Mux),
			maxCallRecvMsgSize: config.GRPC.MaxCallRecvMsgSizeBytes,
			maxCallSendMsgSize: config.GRPC.MaxCallSendMsgSizeBytes,
			ConnectRPC:         connectRPCIpc,
		},
		logger:         logger,
		PublicHostname: config.PublicHostname,
	}

	if !config.CryptoProvider.IsEmpty() {
		// Create crypto provider
		logger.Info("creating crypto provider", slog.String("type", config.CryptoProvider.Type))
		o.CryptoProvider, err = security.NewCryptoProvider(config.CryptoProvider)
		if err != nil {
			return nil, fmt.Errorf("security.NewCryptoProvider: %w", err)
		}
	}

	return &o, nil
}

// newHTTPServer creates a new http server with the given Connect RPC and extra HTTP handlers.
func newHTTPServer(c Config, connectRPC http.Handler, extraHTTP http.Handler, a *auth.Authentication, l *logger.Logger) (*http.Server, error) {
	var (
		err error
		tc  *tls.Config
	)

	httpHandler := extraHTTP

	// Keep profiling behind the same authentication and authorization boundary as
	// the other HTTP handlers.
	if c.EnablePprof {
		httpHandler = pprofHandler(httpHandler)
		// Need to extend write timeout to collect pprof data.
		if c.HTTPServerConfig.WriteTimeout < maxPprofDurationSeconds*time.Second {
			c.HTTPServerConfig.WriteTimeout = maxPprofDurationSeconds * time.Second
		}
	}

	// Add authN interceptor to extra handlers.
	if c.Auth.Enabled {
		httpHandler = a.MuxHandler(httpHandler)
	} else {
		l.Error("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP set `server.auth.dpop.enforce = false`")
	}

	// CORS
	if c.CORS.Enabled {
		// Compute effective values by merging base and additional lists
		effectiveMethods := c.CORS.EffectiveMethods()
		effectiveHeaders := c.CORS.EffectiveHeaders()
		effectiveExposed := c.CORS.EffectiveExposedHeaders()

		// Log effective CORS config for operator visibility
		l.Info(
			"CORS middleware enabled",
			slog.Any("allowed_origins", c.CORS.AllowedOrigins),
			slog.Any("effective_methods", effectiveMethods),
			slog.Any("effective_headers", effectiveHeaders),
			slog.Any("effective_exposed_headers", effectiveExposed),
		)

		corsHandler := cors.New(cors.Options{
			AllowOriginFunc: func(_ *http.Request, origin string) bool {
				for _, allowedOrigin := range c.CORS.AllowedOrigins {
					if allowedOrigin == "*" {
						return true
					}
					if strings.EqualFold(origin, allowedOrigin) {
						return true
					}
				}
				return false
			},
			AllowedMethods:   effectiveMethods,
			AllowedHeaders:   effectiveHeaders,
			ExposedHeaders:   effectiveExposed,
			AllowCredentials: c.CORS.AllowCredentials,
			MaxAge:           c.CORS.MaxAge,
			Debug:            c.CORS.Debug,
		})

		// Apply CORS to connectRPC and extra handlers
		connectRPC = corsHandler.Handler(connectRPC)
		httpHandler = corsHandler.Handler(httpHandler)
	}

	var handler http.Handler
	if !c.TLS.Enabled {
		handler = h2c.NewHandler(routeConnectRPCRequests(connectRPC, httpHandler), &http2.Server{})
	} else {
		tc, err = loadTLSConfig(c.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls config: %w", err)
		}
		handler = routeConnectRPCRequests(connectRPC, httpHandler)
	}

	if c.HTTPServerConfig.ReadTimeout == 0 {
		c.HTTPServerConfig.ReadTimeout = defaultReadTimeout
	}
	if c.HTTPServerConfig.WriteTimeout == 0 {
		c.HTTPServerConfig.WriteTimeout = defaultWriteTimeout
	}

	return &http.Server{
		Addr:              fmt.Sprintf("%s:%d", c.Host, c.Port),
		WriteTimeout:      c.HTTPServerConfig.WriteTimeout,
		ReadTimeout:       c.HTTPServerConfig.ReadTimeout,
		ReadHeaderTimeout: c.HTTPServerConfig.ReadHeaderTimeout,
		IdleTimeout:       c.HTTPServerConfig.IdleTimeout,
		MaxHeaderBytes:    c.HTTPServerConfig.MaxHeaderBytes,
		Handler:           handler,
		TLSConfig:         tc,
	}, nil
}

var rpcPathRegex = regexp.MustCompile(`^/[\w\.]+\.[\w\.]+/[\w]+$`)

func routeConnectRPCRequests(connectRPC http.Handler, httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// contentType := r.Header.Get("Content-Type")
		if (r.Method == http.MethodPost || r.Method == http.MethodGet || r.Method == http.MethodOptions) && rpcPathRegex.MatchString(r.URL.Path) {
			// Request gates cannot read the HTTP method from Connect, so record it
			// for DPoP method binding in the authentication gate.
			connectRPC.ServeHTTP(w, r.WithContext(auth.ContextWithHTTPMethod(r.Context(), r.Method)))
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})
}

// pprofHandler routes profiling requests and bounds caller-controlled collection durations.
func pprofHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
			if supportsPprofDuration(r.URL.Path) && !validatePprofDuration(w, r) {
				return
			}

			switch r.URL.Path {
			case "/debug/pprof/cmdline":
				pprof.Cmdline(w, r)
			case "/debug/pprof/profile":
				pprof.Profile(w, r)
			case "/debug/pprof/symbol":
				pprof.Symbol(w, r)
			case "/debug/pprof/trace":
				pprof.Trace(w, r)
			default:
				pprof.Index(w, r)
			}
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func supportsPprofDuration(path string) bool {
	switch path {
	case "/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/symbol":
		return false
	default:
		return true
	}
}

func validatePprofDuration(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxPprofFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		writePprofFormError(w, err)
		return false
	}
	//nolint:gosec // MaxBytesReader bounds the complete request body above.
	if err := r.ParseMultipartForm(maxPprofFormBodyBytes); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		writePprofFormError(w, err)
		return false
	}

	seconds := r.FormValue("seconds")
	if seconds == "" {
		return true
	}

	duration, err := strconv.ParseFloat(seconds, 64)
	if err == nil && duration > maxPprofDurationSeconds {
		http.Error(w, fmt.Sprintf("pprof duration must not exceed %d seconds", maxPprofDurationSeconds), http.StatusBadRequest)
		return false
	}

	return true
}

func writePprofFormError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		http.Error(w, "pprof request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	http.Error(w, "invalid pprof form body", http.StatusBadRequest)
}

// connectRPCInterceptors are the per-server interceptors newConnectRPC
// installs in both connect-go forms.
type connectRPCInterceptors struct {
	auth        []connect.Interceptor
	authV2      []connectv2.ServerInterceptor
	requestIP   connect.Interceptor
	requestIPV2 connectv2.ServerInterceptor
	extras      []ExtraInterceptor
}

func newConnectRPC(c Config, ints connectRPCInterceptors, logger *logger.Logger) (*ConnectRPC, error) {
	interceptors := make([]connect.HandlerOption, 0)

	// OTel tracing and metrics for incoming Connect requests, before all other interceptors
	serverTraceInt, err := tracing.ConnectServerTraceInterceptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create server trace interceptor: %w", err)
	}
	interceptors = append(interceptors, connect.WithInterceptors(serverTraceInt))
	serverTraceIntV2, err := tracing.ConnectServerTraceInterceptorV2()
	if err != nil {
		return nil, fmt.Errorf("failed to create server trace interceptor: %w", err)
	}
	// connectcompat runs next so every error below it reaches clients the way
	// connect-go v1 sent it.
	serverInterceptors := []connectv2.ServerInterceptor{serverTraceIntV2, connectcompat.ServerInterceptor()}

	if c.Auth.Enabled {
		if len(ints.auth) == 0 || len(ints.authV2) == 0 {
			return nil, errors.New("authentication enabled but no interceptors provided")
		}
		interceptors = append(interceptors, connect.WithInterceptors(ints.auth...))
		serverInterceptors = append(serverInterceptors, ints.authV2...)
	} else {
		logger.Error("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP you can set `enforceDpop = false`")
	}

	// Add protovalidate interceptor
	validationInterceptor := validate.NewInterceptor()

	interceptors = append(interceptors, connect.WithInterceptors(ints.requestIP, validationInterceptor, audit.ContextServerInterceptor()))
	serverInterceptors = append(serverInterceptors, ints.requestIPV2, validateServerInterceptor(), audit.ContextServerInterceptorV2())

	rpc := &ConnectRPC{
		Interceptors:       interceptors,
		ServerInterceptors: serverInterceptors,
		Mux:                http.NewServeMux(),
	}
	// Add any additional interceptors provided programmatically AFTER the default ones, so they have access needed context
	rpc.AddExtraInterceptors(ints.extras...)
	return rpc, nil
}

// v1OnlyExtras wraps interceptors from an option that predates connect-go v2.
func v1OnlyExtras(option string, interceptors []connect.Interceptor) []ExtraInterceptor {
	extras := make([]ExtraInterceptor, 0, len(interceptors))
	for i, interceptor := range interceptors {
		extras = append(extras, ExtraInterceptor{Name: fmt.Sprintf("%s[%d]", option, i), V1: interceptor})
	}
	return extras
}

// externalConnectRequestGates returns the request gates for the external Connect
// server. The authentication gate rejects unauthenticated requests from their
// headers before Connect reads, decompresses, or unmarshals the request body.
// The in-process server keeps its own IPC interceptor.
func externalConnectRequestGates(c Config, authN *auth.Authentication) []connect.HandlerOption {
	if !c.Auth.Enabled || authN == nil {
		return nil
	}
	return []connect.HandlerOption{connect.WithRequestGate(authN.ConnectAuthNRequestGate())}
}

func (s OpenTDFServer) Start() error {
	s.registerReflectionHandlers()

	ln, err := s.openHTTPServerPort(context.Background())
	if err != nil {
		return err
	}
	s.Listener = ln

	// Start Http Server
	go s.startHTTPServer(ln)

	return nil
}

func (s OpenTDFServer) Stop() {
	s.logger.Info("shutting down http server")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := s.HTTPServer.Shutdown(ctx); err != nil {
		s.logger.Error("failed to shutdown http server", slog.String("error", err.Error()))
		return
	}
	// Close the listener
	if s.Listener != nil {
		s.Listener.Close()
	}

	s.logger.Info("shutting down in process grpc server")
	if err := s.ConnectRPCInProcess.srv.Shutdown(ctx); err != nil {
		s.logger.Error("failed to shutdown in process connect-rpc server", slog.String("error", err.Error()))
		return
	}

	s.logger.Info("shutdown complete")
}

func (s OpenTDFServer) registerReflectionHandlers() {
	if !s.reflectionEnabled {
		return
	}

	// Add reflection api to connect-rpc
	reflector := grpcreflect.NewStaticReflector(
		s.ConnectRPC.ServiceReflection...,
	)

	// Reflection handlers skip the shared interceptors but still need the read limit.
	readLimitOptions := readLimitHandlerOptions(s.maxRecvMsgSize)
	s.ConnectRPC.Mux.Handle(grpcreflect.NewHandlerV1(reflector, readLimitOptions...))
	s.ConnectRPC.Mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector, readLimitOptions...))
}

func (s inProcessServer) Conn() *sdk.ConnectRPCConnection {
	var clientInterceptors []connect.Interceptor

	// OTel tracing and metrics for outbound IPC Connect RPCs
	if clientTraceInt, err := tracing.ConnectClientTraceInterceptor(); err != nil {
		s.logger.Error("failed to create IPC client trace interceptor", slog.String("error", err.Error()))
	} else {
		clientInterceptors = append(clientInterceptors, clientTraceInt)
	}

	// Add audit interceptor
	clientInterceptors = append(clientInterceptors, sdkAudit.MetadataAddingConnectInterceptor())

	// Add IPC metadata transfer interceptor (transfers gRPC metadata to Connect headers)
	clientInterceptors = append(clientInterceptors, auth.IPCMetadataClientInterceptor(s.logger))

	conn := sdk.ConnectRPCConnection{
		Client:   s.srv.Client(),
		Endpoint: s.srv.Listener.Addr().String(),
		Options: []connect.ClientOption{
			connect.WithInterceptors(clientInterceptors...),
			connect.WithReadMaxBytes(s.maxCallRecvMsgSize),
			connect.WithSendMaxBytes(s.maxCallSendMsgSize),
		},
	}
	return &conn
}

func (s *inProcessServer) WithContextDialer() grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		conn, err := s.srv.Listener.DialContext(ctx, "tcp", "http://localhost:8080")
		if err != nil {
			return nil, fmt.Errorf("failed to dial in process grpc server: %w", err)
		}
		return conn, nil
	})
}

func (s OpenTDFServer) openHTTPServerPort(ctx context.Context) (net.Listener, error) {
	addr := s.HTTPServer.Addr
	if addr == "" {
		if s.HTTPServer.TLSConfig != nil {
			addr = ":https"
		} else {
			addr = ":http"
		}
	}
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return listener, nil
}

func (s OpenTDFServer) startHTTPServer(ln net.Listener) {
	var err error
	if s.HTTPServer.TLSConfig != nil {
		s.logger.Info("starting https server", slog.String("address", s.HTTPServer.Addr))
		err = s.HTTPServer.ServeTLS(ln, "", "")
	} else {
		s.logger.Info("starting http server", slog.String("address", s.HTTPServer.Addr))
		err = s.HTTPServer.Serve(ln)
	}

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("failed to serve http", slog.Any("error", err))
	}
}

func loadTLSConfig(config TLSConfig) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(config.Cert, config.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to load tls cert: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
