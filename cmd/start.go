/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
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
	"google.golang.org/grpc/reflection"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the opentdf service",
	Run:   start,
}

func init() {
	rootCmd.AddCommand(startCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// startCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func start(cmd *cobra.Command, args []string) {
	slog.Info("starting opentdf services")

	slog.Info("loading configuration")
	// Load the config
	conf, err := config.LoadConfig()
	if err != nil {
		slog.Error("could not load config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger, err := logger.NewLogger(conf.Logger)
	if err != nil {
		slog.Error("could not start logger", slog.String("error", err.Error()))
		os.Exit(1)
	}
	slog.SetDefault(logger.Logger)

	slog.Info("starting opa engine")
	// Start the opa engine
	eng, err := opa.NewEngine(conf.OPA)
	if err != nil {
		slog.Error("could not start opa engine", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer eng.Stop(context.Background())

	// Lets make sure we can establish a new db client
	dbClient, err := db.NewClient(conf.DB)
	if err != nil {
		slog.Error("could not establish database connection", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("running database migrations")
	appliedMigrations, err := dbClient.RunMigrations()
	if err != nil {
		slog.Error("issue running database migrations", slog.String("error", err.Error()))
		os.Exit(1)
	}
	slog.Info("database migrations complete", slog.Int("applied", appliedMigrations))

	slog.Info("starting grpc & http server")
	// Create new server for grpc & http. Also will support in process grpc potentially too
	s := server.NewOpenTDFServer(conf.Server)
	defer s.Stop()

	mux := runtime.NewServeMux()
	s.HttpServer.Handler = mux

	slog.Info("registering acre server")
	err = acre.NewAcreServer(dbClient, s.GrpcServer, mux)
	if err != nil {
		slog.Error("failed to register acre server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("registering attributes server")
	err = attributes.NewAttributesServer(dbClient, s.GrpcServer, mux)
	if err != nil {
		slog.Error("failed to register attributes server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("registering acse server")
	err = acse.NewServer(dbClient, s.GrpcServer, s.GrpcInProcess.GetGrpcServer(), mux)
	if err != nil {
		slog.Error("failed to register acse server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("registering entitlements service")
	err = entitlements.NewEntitlementsServer(conf.OpenTDF.Entitlements, s.GrpcServer, nil, s.GrpcInProcess.Conn(), mux, eng)
	if err != nil {
		slog.Error("failed to register entitlements server", slog.String("error", err.Error()))
		os.Exit(1)
	}
	// TODO: make this conditional
	reflection.Register(s.GrpcServer)

	// Start the server
	s.Run()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

}
