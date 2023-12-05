package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/valyala/fasthttp/fasthttputil"
	"google.golang.org/grpc"
)

const (
	writeTimeoutSeconds = 5
	readTimeoutSeconds  = 10
	shutdownTimeout     = 5
)

type OpenTDFServer struct {
	HttpServer        *http.Server
	GrpcServer        *grpc.Server
	grpcServerAddress string
	GrpcInProcess     *inProcessServer
}

/*
TODO: still need to flush this out for internal communication. Would like to leverage grpc as mechanism for internal communication. Hopefully making it easier to define service boundaries
https://github.com/heroku/x/blob/master/grpc/grpcserver/inprocess.go
https://github.com/valyala/fasthttp/blob/master/fasthttputil/inmemory_listener.go
*/
type inProcessServer struct {
	ln  *fasthttputil.InmemoryListener
	srv *grpc.Server
}

// TODO: make this configurable
func NewOpenTDFServer(grpcAddress string, httpAddress string) *OpenTDFServer {
	return &OpenTDFServer{
		HttpServer: &http.Server{
			Addr:         httpAddress,
			WriteTimeout: writeTimeoutSeconds * time.Second,
			ReadTimeout:  readTimeoutSeconds * time.Second,
		},
		GrpcServer:        grpc.NewServer(),
		grpcServerAddress: grpcAddress,
		GrpcInProcess: &inProcessServer{
			ln:  fasthttputil.NewInmemoryListener(),
			srv: &grpc.Server{},
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

	// Start Http Server
	go func() {
		slog.Info("starting http server")

		err := s.HttpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			slog.Error("failed to serve http", slog.String("error", err.Error()))
			return
		}
	}()
}

func (s *OpenTDFServer) Stop() {
	slog.Info("shutting down grpc server")
	s.GrpcServer.GracefulStop()
	slog.Info("shutting down http server")
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout*time.Second)
	defer cancel()
	if err := s.HttpServer.Shutdown(ctx); err != nil {
		slog.Error("failed to shutdown http server", slog.String("error", err.Error()))
		return
	}
	slog.Info("shutdown complete")
}
