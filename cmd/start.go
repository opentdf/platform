/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/acre"
	"github.com/opentdf/opentdf-v2-poc/pkg/attributes"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	writeTimeoutSeconds = 5
	readTimeoutSeconds  = 10
	shutdownTimeout     = 5
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
	migrationResults, err := dbClient.RunMigrations("./migrations")
	if err != nil {
		slog.Error("issue running database migrations", slog.String("error", err.Error()))
		os.Exit(1)
	}
	slog.Info("database migrations complete", slog.Int("applied", len(migrationResults.Applied)))

	slog.Info("starting grpc & http server")

	listener, err := net.Listen("tcp", ":8082")
	if err != nil {
		slog.Error("failed to listen", slog.String("error", err.Error()))
		os.Exit(1)
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	httpServer := &http.Server{
		Addr:         ":8081",
		WriteTimeout: writeTimeoutSeconds * time.Second,
		ReadTimeout:  readTimeoutSeconds * time.Second,
	}
	mux := runtime.NewServeMux()

	slog.Info("registering acre server")
	err = acre.NewAcreServer(dbClient, grpcServer, mux)
	if err != nil {
		slog.Error("failed to register acre server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("registering attributes server")
	err = attributes.NewAttributesServer(dbClient, grpcServer, mux)
	if err != nil {
		slog.Error("failed to register attributes server", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// TODO: make this conditional
	reflection.Register(grpcServer)

	stop := func(g *grpc.Server, h *http.Server) {
		slog.Info("shutting down grpc server")
		g.GracefulStop()
		slog.Info("shutting down http server")
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout*time.Second)
		defer cancel()
		if err := h.Shutdown(ctx); err != nil {
			slog.Error("failed to shutdown http server", slog.String("error", err.Error()))
			return
		}
		slog.Info("shutdown complete")
	}

	defer stop(grpcServer, httpServer)

	go func() {
		slog.Info("starting grpc server")
		if err := grpcServer.Serve(listener); err != nil {
			slog.Error("failed to serve grpc", slog.String("error", err.Error()))
			return
		}
	}()

	go func() {
		slog.Info("starting http server")

		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			slog.Error("failed to serve http", slog.String("error", err.Error()))
			return
		}
	}()
	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

}
