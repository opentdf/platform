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
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"connectrpc.com/validate"
	"github.com/go-chi/cors"
	sdkAudit "github.com/opentdf/platform/sdk/audit"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	Auth                    auth.Config                              `mapstructure:"auth" json:"auth"`
	GRPC                    GRPCConfig                               `mapstructure:"grpc" json:"grpc"`
	CryptoProvider          security.Config                          `mapstructure:"cryptoProvider" json:"cryptoProvider"`
	TLS                     TLSConfig                                `mapstructure:"tls" json:"tls"`
	CORS                    CORSConfig                               `mapstructure:"cors" json:"cors"`
	WellKnownConfigRegister func(namespace string, config any) error `mapstructure:"-" json:"-"`
	// Port to listen on
	Port int    `mapstructure:"port" json:"port" default:"8080"`
	Host string `mapstructure:"host,omitempty" json:"host"`
	// Enable pprof
	EnablePprof bool `mapstructure:"enable_pprof" json:"enable_pprof" default:"false"`
}

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("auth", c.Auth),
		slog.Any("grpc", c.GRPC),
		slog.Any("cryptoProvider", c.CryptoProvider),
		slog.Any("tls", c.TLS),
		slog.Any("cors", c.CORS),
		slog.Int("port", c.Port),
		slog.String("host", c.Host),
		slog.Bool("enablePprof", c.EnablePprof),
	)
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
	AllowedMethods   []string `mapstructure:"allowedmethods" json:"allowedmethods"`
	AllowedHeaders   []string `mapstructure:"allowedheaders" json:"allowedheaders"`
	ExposedHeaders   []string `mapstructure:"exposedheaders" json:"exposedheaders"`
	AllowCredentials bool     `mapstructure:"allowcredentials" json:"allowedcredentials" default:"true"`
	MaxAge           int      `mapstructure:"maxage" json:"maxage" default:"3600"`
}

type ConnectRPC struct {
	Mux               *http.ServeMux
	Interceptors      []connect.HandlerOption
	ServiceReflection []string
}

type OpenTDFServer struct {
	AuthN               *auth.Authentication
	ExtraHandlerMux     *http.ServeMux
	HTTPServer          *http.Server
	ConnectRPCInProcess *inProcessServer
	ConnectRPC          *ConnectRPC
	CryptoProvider      security.CryptoProvider

	logger *logger.Logger
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

func NewOpenTDFServer(config Config, logger *logger.Logger) (*OpenTDFServer, error) {
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
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create authentication interceptor: %w", err)
		}
		logger.Debug("authentication interceptor enabled")
	} else {
		logger.Warn("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP set `enforceDPoP = false`")
	}

	connectRPCIpc, err := newConnectRPCIPC()
	if err != nil {
		return nil, fmt.Errorf("failed to create connect rpc ipc server: %w", err)
	}

	connectRPC, err := newConnectRPC(config, authN, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect rpc server: %w", err)
	}

	// Mux for addtional http handlers
	extraHandlerMux := http.NewServeMux()

	// Create http server
	httpServer, err := newHTTPServer(config, connectRPC.Mux, extraHandlerMux, authN, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create http server: %w", err)
	}

	o := OpenTDFServer{
		AuthN:           authN,
		ExtraHandlerMux: extraHandlerMux,
		HTTPServer:      httpServer,
		ConnectRPC:      connectRPC,
		ConnectRPCInProcess: &inProcessServer{
			srv:                memhttp.New(connectRPCIpc.Mux),
			maxCallRecvMsgSize: config.GRPC.MaxCallRecvMsgSizeBytes,
			maxCallSendMsgSize: config.GRPC.MaxCallSendMsgSizeBytes,
			ConnectRPC:         connectRPCIpc,
		},
		logger: logger,
	}

	// Create crypto provider
	logger.Info("creating crypto provider", slog.String("type", config.CryptoProvider.Type))
	o.CryptoProvider, err = security.NewCryptoProvider(config.CryptoProvider)
	if err != nil {
		return nil, fmt.Errorf("security.NewCryptoProvider: %w", err)
	}

	return &o, nil
}

// newHTTPServer creates a new http server with the given handler and grpc server
func newHTTPServer(c Config, connectRPC http.Handler, extraHandlers http.Handler, a *auth.Authentication, l *logger.Logger) (*http.Server, error) {
	var (
		err                  error
		tc                   *tls.Config
		writeTimeoutOverride = writeTimeout
	)

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
		})

		// Apply CORS to connectRPC and extra handlers
		connectRPC = corsHandler.Handler(connectRPC)
		extraHandlers = corsHandler.Handler(extraHandlers)
	}

	// Add authN interceptor to extra handlers
	if c.Auth.Enabled {
		extraHandlers = a.MuxHandler(extraHandlers)
	} else {
		l.Error("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP set `enforceDPoP = false`")
	}

	// Enable pprof
	if c.EnablePprof {
		extraHandlers = pprofHandler(extraHandlers)
		// Need to extend write timeout to collect pprof data.
		writeTimeoutOverride = 30 * time.Second //nolint:mnd // easier to read that we are overriding the default
	}

	var handler http.Handler
	if !c.TLS.Enabled {
		handler = h2c.NewHandler(routeConnectRPCRequests(connectRPC, extraHandlers), &http2.Server{})
	} else {
		tc, err = loadTLSConfig(c.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls config: %w", err)
		}
		handler = routeConnectRPCRequests(connectRPC, extraHandlers)
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
		contentType := r.Header.Get("Content-Type")
		if slices.Contains([]string{
			"application/grpc",
			"application/grpc+proto",
			"application/grpc+json",
			"application/grpc-web",
			"application/grpc-web+proto",
			"application/grpc-web+json",
			"application/proto",
			"application/json",
			"application/connect+proto",
			"application/connect+json",
		}, contentType) && r.Method == http.MethodPost && rpcPathRegex.MatchString(r.URL.Path) {
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

func newConnectRPCIPC() (*ConnectRPC, error) {
	interceptors := make([]connect.HandlerOption, 0)

	// Add protovalidate interceptor
	vaidationInterceptor, err := validate.NewInterceptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create validation interceptor: %w", err)
	}

	interceptors = append(interceptors, connect.WithInterceptors(vaidationInterceptor, audit.ContextServerInterceptor()))

	return &ConnectRPC{
		Interceptors: interceptors,
		Mux:          http.NewServeMux(),
	}, nil
}

func newConnectRPC(c Config, a *auth.Authentication, logger *logger.Logger) (*ConnectRPC, error) {
	interceptors := make([]connect.HandlerOption, 0)

	// Add protovalidate interceptor
	vaidationInterceptor, err := validate.NewInterceptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create validation interceptor: %w", err)
	}

	interceptors = append(interceptors, connect.WithInterceptors(vaidationInterceptor, audit.ContextServerInterceptor()))

	if c.Auth.Enabled {
		interceptors = append(interceptors, connect.WithInterceptors(a.ConnectUnaryServerInterceptor()))
	} else {
		logger.Error("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP you can set `enforceDpop = false`")
	}

	return &ConnectRPC{
		Interceptors: interceptors,
		Mux:          http.NewServeMux(),
	}, nil
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

	// Start Http Server
	ln, err := s.openHTTPServerPort()
	if err != nil {
		return err
	}
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

	s.logger.Info("shutting down in process grpc server")
	if err := s.ConnectRPCInProcess.srv.Shutdown(ctx); err != nil {
		s.logger.Error("failed to shutdown in process connect-rpc server", slog.String("error", err.Error()))
		return
	}

	s.logger.Info("shutdown complete")
}

func (s inProcessServer) Conn() *grpc.ClientConn {
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
