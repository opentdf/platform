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
	"golang.org/x/exp/slices"
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
	AuthN                  *auth.Authentication
	Mux                    *http.ServeMux
	HTTPServer             *http.Server
	ConnectInProcessServer *inProcessServer
	ConnectInProcessMux    *ConnectRPC
	ConnectMux             *ConnectRPC
	CryptoProvider         security.CryptoProvider

	logger *logger.Logger
}

/*
Based off of https://github.com/akshayjshah/memhttp
*/
type inProcessServer struct {
	srv *memhttp.Server

	maxCallRecvMsgSize int
	maxCallSendMsgSize int
}

func NewOpenTDFServer(config Config, logger *logger.Logger) (*OpenTDFServer, error) {
	var (
		authN *auth.Authentication
		err   error
	)

	interceptors := make([]connect.HandlerOption, 0)

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
		// Add authN interceptor
		interceptors = append(interceptors, connect.WithInterceptors(authN.ConnectUnaryServerInterceptor()))
		logger.Debug("authentication interceptor enabled")
	} else {
		logger.Warn("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP set `enforceDPoP = false`")
	}

	// Add protovalidate interceptor
	vaidationInterceptor, err := validate.NewInterceptor()
	if err != nil {
		return nil, fmt.Errorf("failed to create validation interceptor: %w", err)
	}

	interceptors = append(interceptors, connect.WithInterceptors(vaidationInterceptor))

	// Mux for in process connect server
	inProcessMux := http.NewServeMux()

	connectIPS := &inProcessServer{
		srv:                newConnectRPCInProcessServer(inProcessMux),
		maxCallRecvMsgSize: config.GRPC.MaxCallRecvMsgSizeBytes,
		maxCallSendMsgSize: config.GRPC.MaxCallSendMsgSizeBytes,
	}

	connectInProcessRPC := &ConnectRPC{
		Mux: inProcessMux,
	}

	// Mux for Connect RPC
	connectMux := http.NewServeMux()

	connectRPC := &ConnectRPC{
		Mux:          connectMux,
		Interceptors: interceptors,
	}

	// Mux for Extra HTTP Handlers
	httpMux := http.NewServeMux()

	httpServer, err := newHTTPServer(config, connectMux, httpMux, authN, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create http server: %w", err)
	}

	o := OpenTDFServer{
		AuthN:                  authN,
		HTTPServer:             httpServer,
		ConnectInProcessServer: connectIPS,
		ConnectInProcessMux:    connectInProcessRPC,
		ConnectMux:             connectRPC,
		Mux:                    httpMux,
		logger:                 logger,
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
func newHTTPServer(c Config, connectRPC http.Handler, httpHandler http.Handler, a *auth.Authentication, l *logger.Logger) (*http.Server, error) {
	var (
		err                  error
		tc                   *tls.Config
		writeTimeoutOverride = writeTimeout
	)

	// Add authN interceptor
	// This is needed because we are leveraging RegisterXServiceHandlerServer instead of RegisterXServiceHandlerFromEndpoint
	if c.Auth.Enabled {
		httpHandler = a.MuxHandler(httpHandler)
	} else {
		l.Error("disabling authentication. this is deprecated and will be removed. if you are using an IdP without DPoP set `enforceDPoP = false`")
	}

	// Combine connect and http mux
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if slices.Contains([]string{
			"application/grpc",
			"application/grpc+proto",
			"application/grpc+json",
			"application/grpc-web",
			"application/grpc-web+proto",
			"application/grpc-web+json",
			"application/proto",
			// "application/json",
			"application/connect+proto",
			"application/connect+json",
		}, contentType) && r.Method == http.MethodPost {
			connectRPC.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})

	// CORS
	if c.CORS.Enabled {
		h = cors.New(cors.Options{
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
		}).Handler(h)
	}

	// Enable pprof
	if c.EnablePprof {
		h = pprofHandler(h)
		// Need to extend write timeout to collect pprof data.
		writeTimeoutOverride = 30 * time.Second //nolint:mnd // easier to read that we are overriding the default
	}

	if !c.TLS.Enabled {
		h = h2c.NewHandler(h, &http2.Server{})
	} else {
		tc, err = loadTLSConfig(c.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls config: %w", err)
		}
	}

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", c.Host, c.Port),
		WriteTimeout: writeTimeoutOverride,
		ReadTimeout:  readTimeout,
		Handler:      h,
		TLSConfig:    tc,
	}, nil
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

func newConnectRPCInProcessServer(mux http.Handler) *memhttp.Server {
	// mux := http.NewServeMux()

	// var interceptors []grpc.UnaryServerInterceptor
	// var serverOptions []grpc.ServerOption

	// // Add audit to in process server
	// interceptors = append(interceptors, audit.ContextServerInterceptor)

	// // FIXME: this should probably use existing IP address instead of local?
	// // Add RealIP interceptor to in process server
	// // trustedPeers := []netip.Prefix{} // TODO: add this as a config option?
	// // headers := []string{realip.XForwardedFor, realip.XRealIp}
	// // interceptors = append(interceptors, realip.UnaryServerInterceptor(trustedPeers, headers))

	// // Add interceptors to server options
	// serverOptions = append(serverOptions, grpc.ChainUnaryInterceptor(interceptors...))
	// return grpc.NewServer(serverOptions...)
	return memhttp.New(mux)
}

func (s OpenTDFServer) Start() error {
	// Add reflection api to connect-rpc
	reflector := grpcreflect.NewStaticReflector(
		s.ConnectMux.ServiceReflection...,
	)
	s.ConnectMux.Mux.Handle(grpcreflect.NewHandlerV1(reflector))
	s.ConnectMux.Mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	s.ConnectInProcessMux.Mux.Handle(grpcreflect.NewHandlerV1(reflector))
	s.ConnectInProcessMux.Mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

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
	// TODO
	// s.GRPCInProcess.srv.GracefulStop()

	s.logger.Info("shutdown complete")
}

// func (s inProcessServer) GetGrpcServer() *http.Server {
// 	return s.srv
// }

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

	conn, err := grpc.NewClient("passthrough://", defaultOptions...)
	if err != nil {
		panic(err)
	}
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
