/*
'Copyright 2023 Virtru Corporation'
*/
package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/opentdf/opentdf-v2-poc/internal/config"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/internal/logger"
	"github.com/opentdf/opentdf-v2-poc/internal/opa"
	"github.com/opentdf/opentdf-v2-poc/internal/server"
	"github.com/opentdf/opentdf-v2-poc/pkg/acre"
	"github.com/opentdf/opentdf-v2-poc/pkg/acse"
	"github.com/opentdf/opentdf-v2-poc/pkg/attributes"
	"github.com/opentdf/opentdf-v2-poc/pkg/entitlements"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

// startCmd represents the start command
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

func start(cmd *cobra.Command, args []string) error {
	slog.Info("starting opentdf services")

	slog.Info("loading configuration")
	// Load the config
	conf, err := config.LoadConfig()
	if err != nil {
		slog.Error("could not load config", slog.String("error", err.Error()))
		return err
	}

	logger, err := logger.NewLogger(conf.Logger)
	if err != nil {
		slog.Error("could not start logger", slog.String("error", err.Error()))
		return err
	}
	slog.SetDefault(logger.Logger)

	slog.Info("starting opa engine")
	// Start the opa engine
	eng, err := opa.NewEngine(conf.OPA)
	if err != nil {
		slog.Error("could not start opa engine", slog.String("error", err.Error()))
		return err
	}
	defer eng.Stop(context.Background())

	// Lets make sure we can establish a new db client
	dbClient, err := createDatabaseClient(conf.DB)
	if err != nil {
		slog.Error("issue creating database client", slog.String("error", err.Error()))
		return err

	}

	// Create new server for grpc & http. Also will support in process grpc potentially too
	otdf := server.NewOpenTDFServer(conf.Server)
	defer otdf.Stop()

	// Register the services
	err = RegisterServices(*conf, otdf, dbClient, eng)
	if err != nil {
		slog.Error("issue registering services", slog.String("error", err.Error()))
		return err
	}

	// Start the server
	slog.Info("starting opentdf server", slog.Int("grpcPort", conf.Server.Grpc.Port), slog.Int("httpPort", conf.Server.Http.Port))
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

func createDatabaseClient(conf db.Config) (*db.Client, error) {
	slog.Info("creating database client")
	dbClient, err := db.NewClient(conf)
	if err != nil {
		return nil, err
	}

	slog.Info("running database migrations")
	appliedMigrations, err := dbClient.RunMigrations()
	if err != nil {
		return nil, err
	}

	slog.Info("database migrations complete", slog.Int("applied", appliedMigrations))
	return dbClient, nil
}

func RegisterServices(config config.Config, otdf *server.OpenTDFServer, dbClient *db.Client, eng *opa.Engine) error {
	var (
		err error
	)
	slog.Info("registering acre server")
	err = acre.NewResourceEncoding(dbClient, otdf.GrpcServer, otdf.Mux)
	if err != nil {
		return err
	}

	slog.Info("registering attributes server")
	err = attributes.NewAttributesServer(dbClient, otdf.GrpcServer, otdf.Mux)
	if err != nil {
		return err
	}

	slog.Info("registering acse server")
	err = acse.NewSubjectEncodingServer(dbClient, otdf.GrpcServer, otdf.GrpcInProcess.GetGrpcServer(), otdf.Mux)
	if err != nil {
		return err
	}

	slog.Info("registering entitlements service")
	err = entitlements.NewEntitlementsServer(config.OpenTDF.Entitlements, []*grpc.Server{otdf.GrpcServer}, otdf.GrpcInProcess.Conn(), otdf.Mux, eng)
	if err != nil {
		return err
	}
	return nil
}
