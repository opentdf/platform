/*
'Copyright 2023 Virtru Corporation'
*/
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/opentdf/opentdf-v2-poc/internal/config"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/internal/logger"
	"github.com/opentdf/opentdf-v2-poc/internal/opa"
	"github.com/opentdf/opentdf-v2-poc/internal/server"
	"github.com/opentdf/opentdf-v2-poc/services/resourcemapping"

	// "github.com/opentdf/opentdf-v2-poc/services/acre"
	"github.com/opentdf/opentdf-v2-poc/services/attributes"
	"github.com/opentdf/opentdf-v2-poc/services/kasregistry"
	"github.com/opentdf/opentdf-v2-poc/services/subjectmapping"

	"github.com/opentdf/opentdf-v2-poc/services/namespaces"
	// "github.com/opentdf/opentdf-v2-poc/services/keyaccessgrants"
	"github.com/spf13/cobra"
)

//nolint:gochecknoglobals // startCmd represents the start command.
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the opentdf service",
	RunE:  start,
}

func init() {
	startCmd.SilenceUsage = true
	rootCmd.AddCommand(startCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func start(_ *cobra.Command, _ []string) error {
	slog.Info("starting opentdf services")

	slog.Info("loading configuration")
	// Load the config
	conf, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	logger, err := logger.NewLogger(conf.Logger)
	if err != nil {
		return fmt.Errorf("could not start logger: %w", err)
	}
	slog.SetDefault(logger.Logger)

	ctx := context.Background()

	slog.Info("starting opa engine")
	// Start the opa engine
	eng, err := opa.NewEngine(conf.OPA)
	if err != nil {
		return fmt.Errorf("could not start opa engine: %w", err)
	}
	defer eng.Stop(ctx)

	// Lets make sure we can establish a new db client
	dbClient, err := createDatabaseClient(ctx, conf.DB)
	if err != nil {
		return fmt.Errorf("issue creating database client: %w", err)
	}
	defer dbClient.Close()

	// Create new server for grpc & http. Also will support in process grpc potentially too
	otdf, err := server.NewOpenTDFServer(conf.Server)
	if err != nil {
		slog.Error("issue creating opentdf server", slog.String("error", err.Error()))
		return fmt.Errorf("issue creating opentdf server: %w", err)
	}
	defer otdf.Stop()

	// Register the services
	err = RegisterServices(*conf, otdf, dbClient, eng)
	if err != nil {
		return fmt.Errorf("issue registering services: %w", err)
	}

	// Start the server
	slog.Info("starting opentdf")

	otdf.Run()

	waitForShutdownSignal()

	return nil
}

// waitForShutdownSignal blocks until a SIGINT or SIGTERM is received.
func waitForShutdownSignal() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

func createDatabaseClient(ctx context.Context, conf db.Config) (*db.Client, error) {
	slog.Info("creating database client")
	dbClient, err := db.NewClient(conf)
	if err != nil {
		//nolint:wrapcheck // we want to return the error as is. the start command will wrap it
		return nil, err
	}

	slog.Info("running database migrations")
	appliedMigrations, err := dbClient.RunMigrations(ctx)
	if err != nil {
		return nil, fmt.Errorf("issue running database migrations: %w", err)
	}

	slog.Info("database migrations complete", slog.Int("applied", appliedMigrations))
	return dbClient, nil
}

//nolint:revive // the opa engine will be used in the future
func RegisterServices(_ config.Config, otdf *server.OpenTDFServer, dbClient *db.Client, eng *opa.Engine) error {
	var err error
	slog.Info("registering resource mappings server")
	err = resourcemapping.NewResourceMappingServer(dbClient, otdf.GrpcServer, otdf.Mux)
	if err != nil {
		return fmt.Errorf("could not register resource mappings service: %w", err)
	}

	slog.Info("registering attributes server")
	err = attributes.NewAttributesServer(dbClient, otdf.GrpcServer, otdf.Mux)
	if err != nil {
		return fmt.Errorf("could not register attributes service: %w", err)
	}

	slog.Info("registering subject mappings service")
	err = subjectmapping.NewSubjectMappingServer(dbClient, otdf.GrpcServer, otdf.GrpcInProcess.GetGrpcServer(), otdf.Mux)
	if err != nil {
		return fmt.Errorf("could not register subject mappings service: %w", err)
	}

	slog.Info("registering key access server registry")
	err = kasregistry.NewKeyAccessServerRegistryServer(dbClient, otdf.GrpcServer, otdf.Mux)
	if err != nil {
		return fmt.Errorf("could not register key access grants service: %w", err)
	}

	slog.Info("registering namespaces server")
	err = namespaces.NewNamespacesServer(dbClient, otdf.GrpcServer, otdf.Mux)
	if err != nil {
		return fmt.Errorf("could not register namespaces service: %w", err)
	}

	return nil
}
