/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/internal/server"
	"github.com/opentdf/opentdf-v2-poc/pkg/acre"
	"github.com/opentdf/opentdf-v2-poc/pkg/attributes"
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

	// Lets make sure we can establish a new db client
	dbClient, err := db.NewClient(os.Getenv("DB_URL"))
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
	s := server.NewOpenTDFServer(":8082", ":8081")
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

	// TODO: make this conditional
	reflection.Register(s.GrpcServer)

	// Start the server
	s.Run()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

}
