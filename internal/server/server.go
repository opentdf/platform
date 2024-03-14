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
	HTTP                    HTTPConfig         `yaml:"http"`
	TLS                     TLSConfig          `yaml:"tls"`
	WellKnownConfigRegister func(namespace string, config any) error
}

type GRPCConfig struct {
	Port              int  `yaml:"port" default:"9000"`
	ReflectionEnabled bool `yaml:"reflectionEnabled" default:"true"`
}

type HTTPConfig struct {
	Enabled bool   `yaml:"enabled" default:"true"`
	Port    int    `yaml:"port" default:"8080"`
	Host    string `yaml:"host,omitempty"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled" default:"false"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

type OpenTDFServer struct {
	Mux               *runtime.ServeMux
	HTTPServer        *http.Server
	GRPCServer        *grpc.Server
	gRPCServerAddress string
	GRPCInProcess     *inProcessServer
	HSM               *security.HSMSession
	WrappedServer     *http.Server
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

	if config.HTTP.Enabled {
		httpServer = &http.Server{
			Addr:         fmt.Sprintf("%s:%d", config.HTTP.Host, config.HTTP.Port),
			WriteTimeout: writeTimeoutSeconds * time.Second,
			ReadTimeout:  readTimeoutSeconds * time.Second,
			// We need to make cors configurable
			Handler:   handler,
			TLSConfig: tlsConfig,
		}
	}

	server := &http.Server{
		Addr:         ":9005",
		WriteTimeout: writeTimeoutSeconds * time.Second,
		ReadTimeout:  readTimeoutSeconds * time.Second,
		Handler:      grpcHandlerFunc(grpcServer, handler),
		TLSConfig:    tlsConfig,
	}

	o := OpenTDFServer{
		Mux:               mux,
		HTTPServer:        httpServer,
		GRPCServer:        grpcServer,
		gRPCServerAddress: fmt.Sprintf(":%d", config.GRPC.Port),
		GRPCInProcess:     grpcInprocess,
		WrappedServer:     server,
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
		fmt.Println("http server", r.ProtoMajor, r.Header)
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

func (s OpenTDFServer) Start() {
	// // Start Grpc Server
	// go s.startGrpcServer()
	s.startHTTPServer()
	// Start In Process Grpc Server
	go s.startInProcessGrpcServer()

	// // Start Http Server
	// if s.HTTPServer != nil {
	// 	go s.startHTTPServer()
	// }
}

func (s OpenTDFServer) Stop() {
	if s.WrappedServer != nil {
		slog.Info("shutting down http server")
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout*time.Second)
		defer cancel()
		if err := s.WrappedServer.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown http server", slog.String("error", err.Error()))
			return
		}
	}

	// slog.Info("shutting down grpc server")
	// s.GRPCServer.GracefulStop()

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

func (s OpenTDFServer) startGrpcServer() {
	slog.Info("starting grpc server", "address", s.gRPCServerAddress)
	listener, err := net.Listen("tcp", s.gRPCServerAddress)
	if err != nil {
		slog.Error("failed to create listener", slog.String("error", err.Error()))
		panic(err)
	}
	if err := s.GRPCServer.Serve(listener); err != nil {
		slog.Error("failed to serve grpc", slog.String("error", err.Error()))
		panic(err)
	}
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

	// if s.WrappedServer.TLSConfig != nil {
	// 	slog.Info("starting https server", "address", s.WrappedServer.Addr)
	// 	err = s.WrappedServer.ListenAndServeTLS("", "")
	// } else {
	// 	slog.Info("starting http server", "address", s.WrappedServer.Addr)
	// 	err = s.WrappedServer.ListenAndServe()
	// }

	conn, err := net.Listen("tcp", fmt.Sprintf(":%d", 9005))
	if err != nil {
		panic(err)
	}

	err = s.WrappedServer.Serve(tls.NewListener(conn, s.WrappedServer.TLSConfig))
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
