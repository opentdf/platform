package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/bufbuild/protovalidate-go"
	"github.com/go-chi/cors"
	protovalidate_middleware "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
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

type Config struct {
	Grpc GrpcConfig `yaml:"grpc"`
	HTTP HTTPConfig `yaml:"http"`
	TLS  TLSConfig  `yaml:"tls"`
}

type GrpcConfig struct {
	Port              int  `yaml:"port" default:"9000"`
	ReflectionEnabled bool `yaml:"reflectionEnabled" default:"true"`
}

type HTTPConfig struct {
	Enabled bool `yaml:"enabled" default:"true"`
	Port    int  `yaml:"port" default:"8080"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled" default:"false"`
	Cert    string `yaml:"cert"`
	Key     string `yaml:"key"`
}

type OpenTDFServer struct {
	Mux               *runtime.ServeMux
	HTTPServer        *http.Server
	GrpcServer        *grpc.Server
	grpcServerAddress string
	GrpcInProcess     *inProcessServer
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
		grpcOpts   []grpc.ServerOption
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
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcOpts = append(grpcOpts, grpc.UnaryInterceptor(
		protovalidate_middleware.UnaryServerInterceptor(validator),
	))

	grpcServer := grpc.NewServer(
		grpcOpts...,
	)

	grpcInprocess := &inProcessServer{
		ln:  fasthttputil.NewInmemoryListener(),
		srv: grpc.NewServer(),
	}

	mux := runtime.NewServeMux(
		runtime.WithHealthzEndpoint(healthpb.NewHealthClient(grpcInprocess.Conn())),
	)

	// Enable grpc reflection
	if config.Grpc.ReflectionEnabled {
		reflection.Register(grpcServer)
	}

	if config.HTTP.Enabled {
		httpServer = &http.Server{
			Addr:         fmt.Sprintf(":%d", config.HTTP.Port),
			WriteTimeout: writeTimeoutSeconds * time.Second,
			ReadTimeout:  readTimeoutSeconds * time.Second,
			// We need to make cors configurable
			Handler: cors.New(cors.Options{
				AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
				AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"ACCEPT", "Authorization", "Content-Type", "X-CSRF-Token"},
				ExposedHeaders:   []string{"Link"},
				AllowCredentials: true,
				MaxAge:           maxAge,
			}).Handler(mux),
			TLSConfig: tlsConfig,
		}
	}

	return &OpenTDFServer{
		Mux:               mux,
		HTTPServer:        httpServer,
		GrpcServer:        grpcServer,
		grpcServerAddress: fmt.Sprintf(":%d", config.Grpc.Port),
		GrpcInProcess:     grpcInprocess,
	}, nil
}

func (s OpenTDFServer) Run() {
	// Start Grpc Server
	go s.startGrpcServer()

	// Start In Process Grpc Server
	go s.startInProcessGrpcServer()

	// Start Http Server
	if s.HTTPServer != nil {
		go s.startHTTPServer()
	}
}

func (s OpenTDFServer) Stop() {
	slog.Info("shutting down grpc server")
	s.GrpcServer.GracefulStop()

	slog.Info("shutting down in process grpc server")
	s.GrpcInProcess.srv.GracefulStop()

	slog.Info("shutting down http server")
	if s.HTTPServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout*time.Second)
		defer cancel()
		if err := s.HTTPServer.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown http server", slog.String("error", err.Error()))
			return
		}
	}
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
	slog.Info("starting grpc server", "address", s.grpcServerAddress)
	listener, err := net.Listen("tcp", s.grpcServerAddress)
	if err != nil {
		slog.Error("failed to create listener", slog.String("error", err.Error()))
		panic(err)
	}
	if err := s.GrpcServer.Serve(listener); err != nil {
		slog.Error("failed to serve grpc", slog.String("error", err.Error()))
		panic(err)
	}
}

func (s OpenTDFServer) startInProcessGrpcServer() {
	slog.Info("starting in process grpc server")
	if err := s.GrpcInProcess.srv.Serve(s.GrpcInProcess.ln); err != nil {
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
	}, nil
}
