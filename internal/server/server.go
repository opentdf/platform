package server

import (
	"context"
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
	"google.golang.org/grpc/credentials/insecure"
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
}

type GrpcConfig struct {
	Port              int  `yaml:"port" default:"9000"`
	ReflectionEnabled bool `yaml:"reflectionEnabled" default:"false"`
}

type HTTPConfig struct {
	Port int `yaml:"port" default:"8080"`
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

// TODO: make this configurable
func NewOpenTDFServer(config Config) *OpenTDFServer {
	// TODO: support ability to pass in grpc server options and interceptors
	validator, _ := protovalidate.New()

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(
			protovalidate_middleware.UnaryServerInterceptor(validator),
		),
	)

	// TODO: Support ability to configure mux
	mux := runtime.NewServeMux()

	// Enable grpc reflection
	if config.Grpc.ReflectionEnabled {
		reflection.Register(grpcServer)
	}

	return &OpenTDFServer{
		Mux: mux,
		HTTPServer: &http.Server{
			Addr:         fmt.Sprintf(":%d", config.HTTP.Port),
			WriteTimeout: writeTimeoutSeconds * time.Second,
			ReadTimeout:  readTimeoutSeconds * time.Second,
			// TOOO: cors should be configurable and not just allow all
			Handler: cors.New(cors.Options{
				AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
				AllowedMethods:   []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders:   []string{"ACCEPT", "Authorization", "Content-Type", "X-CSRF-Token"},
				ExposedHeaders:   []string{"Link"},
				AllowCredentials: true,
				MaxAge:           maxAge,
			}).Handler(mux),
		},
		GrpcServer:        grpcServer,
		grpcServerAddress: fmt.Sprintf(":%d", config.Grpc.Port),
		GrpcInProcess: &inProcessServer{
			ln:  fasthttputil.NewInmemoryListener(),
			srv: grpc.NewServer(),
		},
	}
}

func (s *OpenTDFServer) Run() {
	// Start Grpc Server
	go func() {
		slog.Info("starting grpc server")
		listener, err := net.Listen("tcp", s.grpcServerAddress)
		if err != nil {
			slog.Error("failed to start gRPC server", slog.String("error", err.Error()))
			return
		}
		if err := s.GrpcServer.Serve(listener); err != nil {
			slog.Error("failed to serve grpc", slog.String("error", err.Error()))
			return
		}
	}()

	// Start In Process Grpc Server
	go func() {
		slog.Info("starting in process grpc server")
		if err := s.GrpcInProcess.srv.Serve(s.GrpcInProcess.ln); err != nil {
			slog.Error("failed to serve in process grpc", slog.String("error", err.Error()))
			return
		}
	}()

	// Start Http Server
	go func() {
		slog.Info("starting http server")

		err := s.HTTPServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			slog.Error("failed to serve http", slog.String("error", err.Error()))
			return
		}
	}()
}

func (s *OpenTDFServer) Stop() {
	slog.Info("shutting down grpc server")
	s.GrpcServer.GracefulStop()

	slog.Info("shutting down in process grpc server")
	s.GrpcInProcess.srv.GracefulStop()

	slog.Info("shutting down http server")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout*time.Second)
	defer cancel()
	if err := s.HTTPServer.Shutdown(ctx); err != nil {
		slog.Error("failed to shutdown http server", slog.String("error", err.Error()))
		return
	}
	slog.Info("shutdown complete")
}

func (s inProcessServer) GetGrpcServer() *grpc.Server {
	return s.srv
}

func (s *inProcessServer) Conn() *grpc.ClientConn {
	defaultOptions := []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return s.ln.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	conn, _ := grpc.Dial("", defaultOptions...)
	return conn
}
