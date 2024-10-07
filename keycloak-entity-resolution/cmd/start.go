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

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	keycloak "github.com/opentdf/platform/keycloak-ers/entityresolution"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/opentdf/platform/protocol/go/entityresolution"
	logging "github.com/opentdf/platform/service/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"gopkg.in/yaml.v2"
)

type Config struct {
	GRPC GRPCConfig `mapstructure:"grpc" json:"grpc" yaml:"grpc"`
	// Port to listen on
	Port      int                     `mapstructure:"port" json:"port" yaml:"port" default:"8181"`
	Host      string                  `mapstructure:"host,omitempty" json:"host" yaml:"host"`
	ERSConfig keycloak.KeycloakConfig `mapstructure:"entityresolution" json:"entityresolution" yaml:"entityresolution"`
	Logger    logging.Config          `mapstructure:"logger" json:"logger" yaml:"logger"`
}

type GRPCConfig struct {
	// Enable reflection for grpc server (default: true)
	ReflectionEnabled bool `mapstructure:"reflectionEnabled" json:"reflectionEnabled" yaml:"reflectionEnabled" default:"true"`
}

type KeycloakERS struct {
	entityresolution.UnimplementedEntityResolutionServiceServer
	idpConfig keycloak.KeycloakConfig
	logger    *logging.Logger
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

	// CONFIGS
	var configData Config

	f, err := os.Open("config.yaml")
	if err != nil {
		panic(fmt.Errorf("error when opening YAML file: %s", err.Error()))
	}

	fileData, err := io.ReadAll(f)
	if err != nil {
		panic(fmt.Errorf("error reading YAML file: %s", err.Error()))
	}

	err = yaml.Unmarshal(fileData, &configData)
	if err != nil {
		panic(fmt.Errorf("error unmarshaling yaml file %s", err.Error()))
	}

	// SERVER
	s := grpc.NewServer()

	// Enable grpc reflection
	if configData.GRPC.ReflectionEnabled {
		reflection.Register(s)
	}

	logger, err := logging.NewLogger(configData.Logger)
	if err != nil {
		panic(fmt.Errorf("error creating logger %s", err.Error()))
	}

	logger.Debug("entity resolution configuration", "config", configData)

	svr := KeycloakERS{idpConfig: configData.ERSConfig, logger: logger}

	// Register gRPC service
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

	// START
	logger.Info("Serving gRPC and HTTP on " + fmt.Sprintf("%s:%d", configData.Host, configData.Port))
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", configData.Host, configData.Port), h2)
	if err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
