package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/arkavo-org/opentdf-platform/service/internal/security"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/arkavo-org/opentdf-platform/service/internal/auth"
	"github.com/arkavo-org/opentdf-platform/service/internal/db"
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

type Error string

func (e Error) Error() string {
	return string(e)
}

type Config struct {
	Auth                    auth.Config     `yaml:"auth"`
	GRPC                    GRPCConfig      `yaml:"grpc"`
	CryptoProvider          security.Config `yaml:"cryptoProvider"`
	TLS                     TLSConfig       `yaml:"tls"`
	WellKnownConfigRegister func(namespace string, config any) error
	Port                    int    `yaml:"port" default:"8080"`
	Host                    string `yaml:"host,omitempty"`
}

type GRPCConfig struct {
	ReflectionEnabled bool `yaml:"reflectionEnabled" default:"true"`
}

type TLSConfig struct {
	Enabled bool   `yaml:"enabled" default:"false"`
	Cert    string `yaml:"cert"`
	CACert  string `yaml:"ca_cert" default:"../ca.crt"`
	Key     string `yaml:"key"`
}

type OpenTDFServer struct {
	Mux            *runtime.ServeMux
	HTTPServer     *http.Server
	GRPCServer     *grpc.Server
	GRPCInProcess  *inProcessServer
	CryptoProvider security.CryptoProvider
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

func NewOpenTDFServer(config Config, d *db.Client) (*OpenTDFServer, error) {
	var (
		authN *auth.Authentication
		err   error
	)

	// Add authN interceptor
	// TODO Remove this conditional once we move to the hardening phase (https://github.com/opentdf/platform/issues/381)
	if config.Auth.Enabled {
		slog.Info("authentication enabled")
		authN, err = auth.NewAuthenticator(config.Auth.AuthNConfig, d)
		if err != nil {
			return nil, fmt.Errorf("failed to create authentication interceptor: %w", err)
		}
	}

	// Try an register oidc issuer to wellknown service but don't return an error if it fails
	if err := config.WellKnownConfigRegister("platform_issuer", config.Auth.Issuer); err != nil {
		slog.Warn("failed to register platform issuer", slog.String("error", err.Error()))
	}

	// Create grpc server and in process grpc server
	grpcServer, err := newGrpcServer(config, authN)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc server: %w", err)
	}
	grpcIPCServer := &inProcessServer{
		ln:  fasthttputil.NewInmemoryListener(),
		srv: grpc.NewServer(),
	}

	// Create http server
	mux := runtime.NewServeMux(
		runtime.WithHealthzEndpoint(healthpb.NewHealthClient(grpcIPCServer.Conn())),
	)
	httpServer, err := newHttpServer(config, mux, authN, grpcServer)
	if err != nil {
		return nil, fmt.Errorf("failed to create http server: %w", err)
	}

	o := OpenTDFServer{
		Mux:           mux,
		HTTPServer:    httpServer,
		GRPCServer:    grpcServer,
		GRPCInProcess: grpcIPCServer,
	}

	if config.CryptoProvider.HSMConfig.Enabled {
		config.CryptoProvider.Type = "hsm"
		o.CryptoProvider, err = security.NewCryptoProvider(config.CryptoProvider)
		if err != nil {
			return nil, fmt.Errorf("HSM security.NewCryptoProvider: %w", err)
		}

		slog.Info("✅crypto provider: HSM")
	} else {
		config.CryptoProvider.Type = "standard"
		o.CryptoProvider, err = security.NewCryptoProvider(config.CryptoProvider)
		if err != nil {
			return nil, fmt.Errorf("standard security.NewCryptoProvider: %w", err)
		}

		slog.Info("✅ crypto provider: standard")
	}

	return &o, nil
}

// newHttpServer creates a new http server with the given handler and grpc server
func newHttpServer(c Config, h http.Handler, a *auth.Authentication, g *grpc.Server) (*http.Server, error) {
	var err error
	var tc *tls.Config

	// Add authN interceptor
	// TODO check if this is needed or if it is handled by gRPC
	if c.Auth.Enabled {
		h = a.MuxHandler(h)
	}

	// Add CORS // TODO We need to make cors configurable (https://github.com/opentdf/platform/issues/305)
	h = cors.New(cors.Options{
		AllowOriginFunc:  func(r *http.Request, origin string) bool { return true },
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowedHeaders:   []string{"ACCEPT", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           maxAge,
	}).Handler(h)

	// Add grpc handler
	h2 := httpGrpcHandlerFunc(h, g)

	if !c.TLS.Enabled {
		h2 = h2c.NewHandler(h2, &http2.Server{})
	} else {
		tc, err = loadTLSConfig(c.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls config: %w", err)
		}
	}

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", c.Host, c.Port),
		WriteTimeout: writeTimeoutSeconds * time.Second,
		ReadTimeout:  readTimeoutSeconds * time.Second,
		Handler:      h2,
		TLSConfig:    tc,
	}, nil
}

// httpGrpcHandlerFunc returns a http.Handler that delegates to the grpc server if the request is a grpc request
func httpGrpcHandlerFunc(h http.Handler, g *grpc.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("grpc handler func", slog.Int("proto_major", r.ProtoMajor), slog.String("content_type", r.Header.Get("Content-Type")))
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			g.ServeHTTP(w, r)
		} else {

			h.ServeHTTP(w, r)
		}
	})
}

// newGrpcServer creates a new grpc server with the given config and authN interceptor
func newGrpcServer(c Config, a *auth.Authentication) (*grpc.Server, error) {
	var i []grpc.UnaryServerInterceptor
	var o []grpc.ServerOption

	// Enbale proto validation
	validator, err := protovalidate.New()
	if err != nil {
		slog.Warn("failed to create proto validator", slog.String("error", err.Error()))
	}

	// Add authN interceptor
	if c.Auth.Enabled {
		i = append(i, a.UnaryServerInterceptor)
	}

	// Add tls creds if tls is not nil
	if c.TLS.Enabled {
		c, err := loadTLSConfig(c.TLS)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls config: %w", err)
		}
		o = append(o, grpc.Creds(credentials.NewTLS(c)))
	}

	// Add proto validation interceptor
	i = append(i, protovalidate_middleware.UnaryServerInterceptor(validator))

	o = append(o, grpc.ChainUnaryInterceptor(
		i...,
	))

	s := grpc.NewServer(o...)

	// Enable grpc reflection
	if c.GRPC.ReflectionEnabled {
		reflection.Register(s)
	}

	return s, nil
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
	// Load CA certificate
	caCert, err := os.ReadFile(config.CACert)
	if err != nil {
		log.Fatalf("failed to load CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	if ok := caPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatalf("failed to append CA cert to pool")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
