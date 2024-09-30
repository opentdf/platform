package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	keycloak "github.com/opentdf/platform/keycloak-ers/entityresolution"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/service/logger"
	logging "github.com/opentdf/platform/service/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gopkg.in/yaml.v2"
)

const (
	writeTimeout    time.Duration = 5 * time.Second
	readTimeout     time.Duration = 10 * time.Second
	shutdownTimeout time.Duration = 5 * time.Second
)

type Config struct {
	GRPC GRPCConfig `mapstructure:"grpc" json:"grpc" yaml:"grpc"`
	// Port to listen on
	Port int    `mapstructure:"port" json:"port" yaml:"port" default:"8181"`
	Host string `mapstructure:"host,omitempty" json:"host" yaml:"host"`
}

type GRPCConfig struct {
	// Enable reflection for grpc server (default: true)
	ReflectionEnabled bool `mapstructure:"reflectionEnabled" json:"reflectionEnabled" yaml:"reflectionEnabled" default:"true"`
}

type KeycloakERS struct {
	entityresolution.UnimplementedEntityResolutionServiceServer
	idpConfig keycloak.KeycloakConfig
	logger    *logger.Logger
}

func (s KeycloakERS) ResolveEntities(ctx context.Context, req *entityresolution.ResolveEntitiesRequest) (*entityresolution.ResolveEntitiesResponse, error) {
	resp, err := keycloak.EntityResolution(ctx, req, s.idpConfig, s.logger)
	return &resp, err
}

func (s KeycloakERS) CreateEntityChainFromJwt(ctx context.Context, req *entityresolution.CreateEntityChainFromJwtRequest) (*entityresolution.CreateEntityChainFromJwtResponse, error) {
	resp, err := keycloak.CreateEntityChainFromJwt(ctx, req, s.idpConfig, s.logger)
	return &resp, err
}

func Execute() {
	// listener, err := net.Listen("tcp", ":8181")
	// if err != nil {
	// 	log.Fatalf("Failed to listen: %v", err)
	// }

	// CONFIGS

	var inputIdpConfig keycloak.KeycloakConfig
	var serverConfig Config

	f, err := os.Open("config.yaml")
	if err != nil {
		panic(fmt.Errorf("error when opening YAML file: %s", err.Error()))
	}

	fileData, err := io.ReadAll(f)
	if err != nil {
		panic(fmt.Errorf("error reading YAML file: %s", err.Error()))
	}

	err = yaml.Unmarshal(fileData, &serverConfig)
	if err != nil {
		panic(fmt.Errorf("error unmarshaling yaml file %s", err.Error()))
	}

	err = yaml.Unmarshal(fileData, &inputIdpConfig)
	if err != nil {
		panic(fmt.Errorf("error unmarshaling yaml file %s", err.Error()))
	}

	// SERVER:
	s := grpc.NewServer()

	// Enable grpc reflection
	if serverConfig.GRPC.ReflectionEnabled {
		reflection.Register(s)
	}

	logger, err := logging.NewLogger(logging.Config{Level: "debug", Type: "text", Output: "stdout"})
	if err != nil {
		panic(fmt.Errorf("error creating logger %s", err.Error()))
	}

	logger.Debug("entity_resolution configuration", "config", inputIdpConfig)
	logger.Debug("entity_resolution configuration", "config", serverConfig)

	svr := KeycloakERS{idpConfig: inputIdpConfig, logger: logger}

	entityresolution.RegisterEntityResolutionServiceServer(s, &svr)

	// Create a gRPC-Gateway mux
	mux := runtime.NewServeMux()

	// Register gRPC Gateway handlers
	err = entityresolution.RegisterEntityResolutionServiceHandlerServer(context.Background(), mux, &svr)
	if err != nil {
		log.Fatalf("failed to register gateway: %v", err)
	}

	httphandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.TraceContext(r.Context(), "grpc handler func", slog.Int("proto_major", r.ProtoMajor), slog.String("content_type", r.Header.Get("Content-Type")))
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			s.ServeHTTP(w, r)
		} else {
			mux.ServeHTTP(w, r)
		}
	})

	h2 := h2c.NewHandler(httphandler, &http2.Server{})

	logger.Info("Serving gRPC and HTTP on " + fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port))
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", serverConfig.Host, serverConfig.Port), h2)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
