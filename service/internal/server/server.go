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
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"github.com/go-chi/cors"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/sdk"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/logger"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/opentdf/platform/service/pkg/oidc"
	"github.com/opentdf/platform/service/tracing"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	writeTimeout    time.Duration = 5 * time.Second
	readTimeout     time.Duration = 10 * time.Second
	shutdownTimeout time.Duration = 5 * time.Second
)

type Error string

func (e Error) Error() string {
	return string(e)
}

// Configurations for the server
type Config struct {
	Auth auth.Config `mapstructure:"auth" json:"auth"`

	Cache CacheConfig `mapstructure:"cache" json:"cache"`

	// OIDC Discovery configuration
	OIDCDiscovery *oidc.DiscoveryConfiguration

	GRPC GRPCConfig `mapstructure:"grpc" json:"grpc"`
	// To Deprecate: Use the WithKey[X]Provider StartOptions to register trust providers.
	CryptoProvider          security.Config                          `mapstructure:"cryptoProvider" json:"cryptoProvider"`
	TLS                     TLSConfig                                `mapstructure:"tls" json:"tls"`
	CORS                    CORSConfig                               `mapstructure:"cors" json:"cors"`
	WellKnownConfigRegister func(namespace string, config any) error `mapstructure:"-" json:"-"`
	// Port to listen on
	Port           int    `mapstructure:"port" json:"port" default:"8080"`
	Host           string `mapstructure:"host,omitempty" json:"host"`
	PublicHostname string `mapstructure:"public_hostname,omitempty" json:"publicHostname"`

	// Enable pprof
	EnablePprof bool `mapstructure:"enable_pprof" json:"enable_pprof" default:"false"`
	// Trace is for configuring open telemetry based tracing.
	Trace tracing.Config `mapstructure:"trace"`
}

func (c Config) LogValue() slog.Value {
	group := []slog.Attr{
		slog.Any("auth", c.Auth),
		slog.Any("grpc", c.GRPC),
		slog.Any("tls", c.TLS),
		slog.Any("cors", c.CORS),
		slog.Int("port", c.Port),
		slog.String("host", c.Host),
		slog.Bool("enablePprof", c.EnablePprof),
	}

	// CryptoProvider is deprecated in favor of the trust package.
	if !c.CryptoProvider.IsEmpty() {
		group = append(group, slog.Any("cryptoProvider", c.CryptoProvider))
	}

	return slog.GroupValue(group...)
}

type CacheRistrettoConfig struct {
	// MaxCost is the maximum cost of the cache (default: 100MB)
	MaxCost int64 `mapstructure:"maxCost" json:"maxCost" default:"100000000"`
}

type CacheConfig struct {
	Driver           string               `mapstructure:"driver" json:"driver" default:"ristretto"`
	RistrettoCache   CacheRistrettoConfig `mapstructure:"ristretto" json:"ristretto"`
	UserInfoCacheTTL time.Duration        `mapstructure:"userInfoCacheTTL" json:"userInfoCacheTTL" default:"5m"`
}

// GRPC Server specific configurations
type GRPCConfig struct {
	// Enable reflection for grpc server (default: true)
	ReflectionEnabled bool `mapstructure:"reflectionEnabled" json:"reflectionEnabled" default:"true"`

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

// CORS Configuration for the server
type CORSConfig struct {
	// Enable CORS for the server (default: true)
	Enabled          bool     `mapstructure:"enabled" json:"enabled" default:"true"`
	AllowedOrigins   []string `mapstructure:"allowedorigins" json:"allowedorigins"`
	AllowedMethods   []string `mapstructure:"allowedmethods" json:"allowedmethods" default:"[\"GET\",\"POST\",\"PATCH\",\"DELETE\",\"OPTIONS\"]"`
	AllowedHeaders   []string `mapstructure:"allowedheaders" json:"allowedheaders" default:"[\"Accept\",\"Content-Type\",\"Content-Length\",\"Accept-Encoding\",\"X-CSRF-Token\",\"Authorization\",\"X-Requested-With\",\"Dpop\"]"`
	ExposedHeaders   []string `mapstructure:"exposedheaders" json:"exposedheaders"`
	AllowCredentials bool     `mapstructure:"allowcredentials" json:"allowedcredentials" default:"true"`
	MaxAge           int      `mapstructure:"maxage" json:"maxage" default:"3600"`
	Debug            bool     `mapstructure:"debug" json:"debug"`
}

type ConnectRPC struct {
	Mux               *http.ServeMux
	Interceptors      []connect.HandlerOption
	ServiceReflection []string
}

type OpenTDFServer struct {
	AuthN               *auth.Authentication
	GRPCGatewayMux      *runtime.ServeMux
	HTTPServer          *http.Server
	ConnectRPCInProcess *inProcessServer
	ConnectRPC          *ConnectRPC
	CacheManager        *cache.Manager

	UserInfoCache *oidc.UserInfoCache

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
	maxCallRecvMsgSize int
	maxCallSendMsgSize int
	*ConnectRPC
}

// UserInfoCacheCost is the cost of the user info cache
const userInfoCacheCost = 10

func NewOpenTDFServer(ctx context.Context, config Config, logger *logger.Logger, cacheManager *cache.Manager) (*OpenTDFServer, error) {
	var err error
	svr := &OpenTDFServer{
		logger:         logger,
		CacheManager:   cacheManager,
		PublicHostname: config.PublicHostname,
	}

	// Create userinfo cache for enriched claims
	userInfoCache, err := cacheManager.NewCache("essential:"+oidc.UserInfoCacheService, logger, cache.Options{
		Expiration: config.Cache.UserInfoCacheTTL,
		Cost:       userInfoCacheCost,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo cache: %w", err)
	}
	svr.UserInfoCache, err = oidc.NewUserInfoCache(config.OIDCDiscovery, userInfoCache, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo cache: %w", err)
	}

	// Add authN interceptor
	svr.AuthN, err = auth.NewAuthenticator(
		ctx,
		&config.Auth,
		logger,
		config.WellKnownConfigRegister,
		config.OIDCDiscovery,
		svr.UserInfoCache,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication interceptor: %w", err)
	}

	// Setup IPC
	ipc, err := newConnectRPCIPC(config, svr.AuthN, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect rpc ipc server: %w", err)
	}
	svr.ConnectRPCInProcess = &inProcessServer{
		srv:                memhttp.New(ipc.Mux),
		maxCallRecvMsgSize: config.GRPC.MaxCallRecvMsgSizeBytes,
		maxCallSendMsgSize: config.GRPC.MaxCallSendMsgSizeBytes,
		ConnectRPC:         ipc,
	}

	// Setup Connect RPC
	svr.ConnectRPC, err = newConnectRPC(config, svr.AuthN, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect rpc server: %w", err)
	}

	// GRPC Gateway Mux
	svr.GRPCGatewayMux = runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(
			func(key string) (string, bool) {
				if k, ok := runtime.DefaultHeaderMatcher(key); ok {
					return k, true
				}
				if textproto.CanonicalMIMEHeaderKey(key) == "Dpop" {
					return "Dpop", true
				}
				return "", false
			},
		),
		runtime.WithMetadata(func(ctx context.Context, _ *http.Request) metadata.MD {
			md := make(map[string]string)
			if method, ok := runtime.RPCMethod(ctx); ok {
				md["method"] = method // /grpc.gateway.examples.internal.proto.examplepb.LoginService/Login
			}
			if pattern, ok := runtime.HTTPPathPattern(ctx); ok {
				md["pattern"] = pattern // /v1/example/login
			}
			md["Authorization"] = "Bearer " + ctxAuth.GetRawAccessTokenFromContext(ctx, nil)
			return metadata.New(md)
		}),
	)

	// Create http server
	svr.HTTPServer, err = newHTTPServer(config, svr.ConnectRPC.Mux, svr.GRPCGatewayMux, svr.AuthN, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create http server: %w", err)
	}

	// Create crypto provider
	if !config.CryptoProvider.IsEmpty() {
		svr.logger.Info("creating crypto provider", slog.String("type", config.CryptoProvider.Type))
		svr.CryptoProvider, err = security.NewCryptoProvider(config.CryptoProvider)
		if err != nil {
			return nil, fmt.Errorf("security.NewCryptoProvider: %w", err)
		}
	}

	return svr, nil
}

// Custom response writer to add deprecation header
type grpcGatewayResponseWriter struct {
	w           http.ResponseWriter
	code        int
	wroteHeader bool
}

func (rw *grpcGatewayResponseWriter) Header() http.Header {
	return rw.w.Header()
}

func (rw *grpcGatewayResponseWriter) WriteHeader(statusCode int) {
	gRPCGatewayDeprecationDate := fmt.Sprintf("@%d", time.Date(2025, time.March, 25, 0, 0, 0, 0, time.UTC).Unix())
	if !rw.wroteHeader {
		rw.w.Header().Set("Deprecation", gRPCGatewayDeprecationDate)
		rw.wroteHeader = true
		rw.w.WriteHeader(statusCode)
	}
	rw.code = statusCode
}

func (rw *grpcGatewayResponseWriter) Write(data []byte) (int, error) {
	// Ensure headers are written before any data
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.w.Write(data)
}

// newHTTPServer creates a new http server with the given handler and grpc server
func newHTTPServer(c Config, connectRPC http.Handler, originalGrpcGateway http.Handler, a *auth.Authentication, l *logger.Logger) (*http.Server, error) {
	var (
		err                  error
		tc                   *tls.Config
		writeTimeoutOverride = writeTimeout
	)

	// Adds deprecation header to any grpcGateway responses.
	var grpcGateway http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grpcRW := &grpcGatewayResponseWriter{w: w, code: http.StatusOK}
		originalGrpcGateway.ServeHTTP(grpcRW, r)
	})

	// Add authN interceptor to extra handlers
	if c.Auth.Enabled {
		grpcGateway = a.MuxHandler(grpcGateway)
	} else {
		l.Error("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP set `enforceDPoP = false`")
	}

	// Note: The grpc-gateway handlers are getting chained together in reverse. So the last handler is the first to be called.
	// CORS
	if c.CORS.Enabled {
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
			AllowedMethods:   c.CORS.AllowedMethods,
			AllowedHeaders:   c.CORS.AllowedHeaders,
			ExposedHeaders:   c.CORS.ExposedHeaders,
			AllowCredentials: c.CORS.AllowCredentials,
			MaxAge:           c.CORS.MaxAge,
			Debug:            c.CORS.Debug,
		})

		// Apply CORS to connectRPC and extra handlers
		connectRPC = corsHandler.Handler(connectRPC)
		grpcGateway = corsHandler.Handler(grpcGateway)
	}

	// Enable pprof
	if c.EnablePprof {
		grpcGateway = pprofHandler(grpcGateway)
		// Need to extend write timeout to collect pprof data.
		writeTimeoutOverride = 30 * time.Second //nolint:mnd // easier to read that we are overriding the default
	}

	var handler http.Handler
	if !c.TLS.Enabled {
		handler = h2c.NewHandler(routeConnectRPCRequests(connectRPC, grpcGateway), &http2.Server{})
	} else {
		tc, err = loadTLSConfig(c.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls config: %w", err)
		}
		handler = routeConnectRPCRequests(connectRPC, grpcGateway)
	}

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", c.Host, c.Port),
		WriteTimeout: writeTimeoutOverride,
		ReadTimeout:  readTimeout,
		Handler:      handler,
		TLSConfig:    tc,
	}, nil
}

var rpcPathRegex = regexp.MustCompile(`^/[\w\.]+\.[\w\.]+/[\w]+$`)

func routeConnectRPCRequests(connectRPC http.Handler, httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// contentType := r.Header.Get("Content-Type")
		if (r.Method == http.MethodPost || r.Method == http.MethodGet) && rpcPathRegex.MatchString(r.URL.Path) {
			connectRPC.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})
}

// ppprof handler
func pprofHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/debug/pprof/") {
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

func (s OpenTDFServer) Start() error {
	// Add reflection api to connect-rpc
	reflector := grpcreflect.NewStaticReflector(
		s.ConnectRPC.ServiceReflection...,
	)

	s.ConnectRPC.Mux.Handle(grpcreflect.NewHandlerV1(reflector))
	s.ConnectRPC.Mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	s.ConnectRPCInProcess.Mux.Handle(grpcreflect.NewHandlerV1(reflector))
	s.ConnectRPCInProcess.Mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	ln, err := s.openHTTPServerPort()
	if err != nil {
		return err
	}
	s.Listener = ln

	// Start Http Server
	go s.startHTTPServer(ln)

	return nil
}

func (s OpenTDFServer) Stop(ctx context.Context) {
	s.logger.Info("shutting down http server")
	ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
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

func (s inProcessServer) Conn() *sdk.ConnectRPCConnection {
	var clientInterceptors []connect.Interceptor

	// Add audit interceptor
	clientInterceptors = append(clientInterceptors, sdkAudit.MetadataAddingConnectInterceptor())

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

func (s inProcessServer) GrpcConn() *grpc.ClientConn {
	var clientInterceptors []grpc.UnaryClientInterceptor

	// Add audit interceptor
	clientInterceptors = append(clientInterceptors, sdkAudit.MetadataAddingClientInterceptor)

	defaultOptions := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(s.maxCallRecvMsgSize),
			grpc.MaxCallSendMsgSize(s.maxCallSendMsgSize),
		),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			conn, err := s.srv.Listener.DialContext(ctx, "tcp", "http://localhost:8080")
			if err != nil {
				return nil, fmt.Errorf("failed to dial in process grpc server: %w", err)
			}
			return conn, nil
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(clientInterceptors...),
	}

	conn, _ := grpc.NewClient("passthrough:///", defaultOptions...)
	return conn
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

func (s OpenTDFServer) openHTTPServerPort() (net.Listener, error) {
	addr := s.HTTPServer.Addr
	if addr == "" {
		if s.HTTPServer.TLSConfig != nil {
			addr = ":https"
		} else {
			addr = ":http"
		}
	}
	return net.Listen("tcp", addr)
}

func (s OpenTDFServer) startHTTPServer(ln net.Listener) {
	var err error
	if s.HTTPServer.TLSConfig != nil {
		s.logger.Info("starting https server", "address", s.HTTPServer.Addr)
		err = s.HTTPServer.ServeTLS(ln, "", "")
	} else {
		s.logger.Info("starting http server", "address", s.HTTPServer.Addr)
		err = s.HTTPServer.Serve(ln)
	}

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.logger.Error("failed to serve http", slog.String("error", err.Error()))
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
