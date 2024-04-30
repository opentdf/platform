package cmd

import (
	"context"
	"embed"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/policy"
	"github.com/spf13/cobra"
)

var (
	serviceMigrations = map[string]*embed.FS{
		"policy": policy.Migrations,
	}

	migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
	}

	migrateUpCmd = &cobra.Command{
		Use:   "up [service, ...]",
		Short: "Run database migrations up to the latest version",
		Run: func(cmd *cobra.Command, args []string) {
			migrateService(cmd, args, func(dbClient *db.Client, fs *embed.FS) {
				if _, err := dbClient.RunMigrations(cmd.Context(), fs); err != nil {
					panic(fmt.Errorf("migration up failed: %w", err))
				}
			})
		},
	}

	migrateDownCmd = &cobra.Command{
		Use:   "down [service, ...]",
		Short: "Run database migration down one version",
		Run: func(cmd *cobra.Command, args []string) {
			migrateService(cmd, args, func(dbClient *db.Client, fs *embed.FS) {
				if err := dbClient.MigrationDown(cmd.Context(), fs); err != nil {
					panic(fmt.Errorf("migration down failed: %w", err))
				}
			})
		},
	}

	migrateStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Show the status of the database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			c, err := migrateDBClient(cmd)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}

			status, err := c.MigrationStatus(cmd.Context())
			if err != nil {
				panic(fmt.Errorf("migration status failed: %w", err))
			}
			for _, s := range status {
				slog.Info("migration",
					slog.String("state", string(s.State)),
					slog.String("source", s.Source.Path),
					slog.String("applied_on",
						s.AppliedAt.String()),
				)
			}
		},
	}
)

func migrateService(cmd *cobra.Command, args []string, migrationFunc func(*db.Client, *embed.FS)) {
	// get all the services
	allSvcs := make([]string, 0, len(serviceMigrations))
	for k := range serviceMigrations {
		allSvcs = append(allSvcs, k)
	}
	svcs := allSvcs

	// if --all flag is set then return all the services
	all, err := cmd.Flags().GetBool("all")
	if err != nil {
		panic(fmt.Errorf("could not get flag: %w", err))
	}

	// if args are passed then check if they are valid
	if !all {
		// if no args are passed then return error
		if len(args) == 0 {
			slog.Info("valid services", slog.Any("services", allSvcs))
			panic(fmt.Errorf("service %s not found", args))
		}

		// check for invalid services
		for _, a := range args {
			if _, ok := serviceMigrations[a]; !ok {
				slog.Info("valid services", slog.Any("services", allSvcs))
				panic(fmt.Errorf("service %s not found", args))
			}
		}

		svcs = args
	}

	// run the migration
	for _, s := range svcs {
		slog.Info("running migration", slog.String("service", s))
		dbClient, err := migrateDBClient(cmd,
			db.WithMigrations(serviceMigrations[s]),
			db.WithService(s),
		)
		if err != nil {
			panic(fmt.Errorf("could not load config: %w", err))
		}
		migrationFunc(dbClient, serviceMigrations[s])
	}
}

func migrateDBClient(cmd *cobra.Command, opts ...db.OptsFunc) (*db.Client, error) {
	configFile, _ := cmd.Flags().GetString(configFileFlag)
	configKey, _ := cmd.Flags().GetString(configKeyFlag)
	conf, err := config.LoadConfig(configKey, configFile)
	if err != nil {
		panic(fmt.Errorf("could not load config: %w", err))
	}
	return db.New(context.Background(), conf.DB, opts...)
}

func init() {
	migrateDownCmd.Flags().Bool("all", false, "Run all service migrations")
	migrateUpCmd.Flags().Bool("all", false, "Run all service migrations")
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	rootCmd.AddCommand(migrateCmd)
}
