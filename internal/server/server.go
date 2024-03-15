package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/opentdf/platform/internal/security"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/bufbuild/protovalidate-go"
	"github.com/go-chi/cors"
	protovalidate_middleware "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/internal/auth"
	"github.com/valyala/fasthttp/fasthttputil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

const (
	writeTimeoutSeconds = 5
	readTimeoutSeconds  = 10
	shutdownTimeout     = 5
	maxAge              = 300
)

type Error string

func (e Error) Error() string {
	return string(e)
}

type Config struct {
	Auth                    auth.Config        `yaml:"auth"`
	GRPC                    GRPCConfig         `yaml:"grpc"`
	HSM                     security.HSMConfig `yaml:"hsm"`
	TLS                     TLSConfig          `yaml:"tls"`
	WellKnownConfigRegister func(namespace string, config any) error
	Port                    int    `yaml:"port" default:"9000"`
	Host                    string `yaml:"host,omitempty"`
}

type GRPCConfig struct {
	ReflectionEnabled bool `yaml:"reflectionEnabled" default:"true"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled" default:"false"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

type OpenTDFServer struct {
	Mux           *runtime.ServeMux
	HTTPServer    *http.Server
	GRPCServer    *grpc.Server
	GRPCInProcess *inProcessServer
	HSM           *security.HSMSession
}

/*
Still need to flush this out for internal communication. Would like to leverage grpc
as mechanism for internal communication. Hopefully making it easier to define service boundaries.
https://github.com/heroku/x/blob/master/grpc/grpcserver/inprocess.go
https://github.com/valyala/fasthttp/blob/master/fasthttputil/inmemory_listener.go
*/
type inProcessServer struct {
	ln  *fasthttputil.InmemoryListener
	srv *grpc.Server
}

func NewOpenTDFServer(config Config) (*OpenTDFServer, error) {
	var (
		gRPCOpts   []grpc.ServerOption
		httpServer *http.Server
		tlsConfig  *tls.Config
		err        error
	)

	// Enbale proto validation
	validator, _ := protovalidate.New()

	if config.TLS.Enabled {
		tlsConfig, err = loadTLSConfig(config.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls config: %w", err)
		}
	}

	// Add tls creds if tls is not nil
	if tlsConfig != nil {
		gRPCOpts = append(gRPCOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Build interceptor chain and handler chain
	var (
		interceptors []grpc.UnaryServerInterceptor
		handler      http.Handler
	)

	grpcInprocess := &inProcessServer{
		ln:  fasthttputil.NewInmemoryListener(),
		srv: grpc.NewServer(),
	}

	mux := runtime.NewServeMux(
		runtime.WithHealthzEndpoint(healthpb.NewHealthClient(grpcInprocess.Conn())),
	)

	handler = mux

	// Add authN interceptor
	if config.Auth.Enabled {
		authN, err := auth.NewAuthenticator(config.Auth.AuthNConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create authentication interceptor: %w", err)
		}

		interceptors = append(interceptors, authN.VerifyTokenInterceptor)
		handler = authN.VerifyTokenHandler(mux)

		// Try an register oidc issuer to wellknown service but don't return an error if it fails
		if err := config.WellKnownConfigRegister("platform_issuer", config.Auth.Issuer); err != nil {
			slog.Warn("failed to register platform issuer", slog.String("error", err.Error()))
		}
	}

	// Add proto validation interceptor
	interceptors = append(interceptors, protovalidate_middleware.UnaryServerInterceptor(validator))

	// Add CORS
	// TODO(#305) We need to make cors configurable
	handler = cors.New(cors.Options{
		AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"ACCEPT", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           maxAge,
	}).Handler(handler)

	gRPCOpts = append(gRPCOpts, grpc.ChainUnaryInterceptor(
		interceptors...,
	))

	grpcServer := grpc.NewServer(
		gRPCOpts...,
	)

	// Enable grpc reflection
	if config.GRPC.ReflectionEnabled {
		reflection.Register(grpcServer)
	}

	// Combine grpc and http server
	h2 := grpcHandlerFunc(grpcServer, handler)
	if !config.TLS.Enabled {
		h2 = h2c.NewHandler(h2, &http2.Server{})
	}

	httpServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		WriteTimeout: writeTimeoutSeconds * time.Second,
		ReadTimeout:  readTimeoutSeconds * time.Second,
		// We need to make cors configurable
		Handler:   h2,
		TLSConfig: tlsConfig,
	}

	o := OpenTDFServer{
		Mux:           mux,
		HTTPServer:    httpServer,
		GRPCServer:    grpcServer,
		GRPCInProcess: grpcInprocess,
	}

	if config.HSM.Enabled {
		o.HSM, err = security.New(&config.HSM)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize hsm: %w", err)
		}
	}

	return &o, nil
}

func grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("grpc handler func", slog.Int("proto_major", r.ProtoMajor), slog.String("content_type", r.Header.Get("Content-Type")))
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

func (s OpenTDFServer) Start() {
	// // Start Http Server
	go s.startHTTPServer()
	// Start In Process Grpc Server
	go s.startInProcessGrpcServer()

}

func (s OpenTDFServer) Stop() {

	slog.Info("shutting down http server")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout*time.Second)
	defer cancel()
	if err := s.HTTPServer.Shutdown(ctx); err != nil {
		slog.Error("failed to shutdown http server", slog.String("error", err.Error()))
		return
	}

	slog.Info("shutting down in process grpc server")
	s.GRPCInProcess.srv.GracefulStop()

	slog.Info("shutdown complete")
}

func (s inProcessServer) GetGrpcServer() *grpc.Server {
	return s.srv
}

func (s inProcessServer) Conn() *grpc.ClientConn {
	defaultOptions := []grpc.DialOption{
		grpc.WithContextDialer(func(_ context.Context, addr string) (net.Conn, error) {
			conn, err := s.ln.Dial()
			if err != nil {
				return nil, fmt.Errorf("failed to dial in process grpc server: %w", err)
			}
			return conn, nil
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	conn, _ := grpc.Dial("", defaultOptions...)
	return conn
}

func (s OpenTDFServer) startInProcessGrpcServer() {
	slog.Info("starting in process grpc server")
	if err := s.GRPCInProcess.srv.Serve(s.GRPCInProcess.ln); err != nil {
		slog.Error("failed to serve in process grpc", slog.String("error", err.Error()))
		panic(err)
	}
}

func (s OpenTDFServer) startHTTPServer() {
	var err error

	if s.HTTPServer.TLSConfig != nil {
		slog.Info("starting https server", "address", s.HTTPServer.Addr)
		err = s.HTTPServer.ListenAndServeTLS("", "")
	} else {
		slog.Info("starting http server", "address", s.HTTPServer.Addr)
		err = s.HTTPServer.ListenAndServe()
	}

	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("failed to serve http", slog.String("error", err.Error()))
		return
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
