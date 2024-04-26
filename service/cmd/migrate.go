package cmd

import (
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/service/internal/config"
	"github.com/opentdf/platform/service/internal/db"
	"github.com/spf13/cobra"
)

var (
	migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
	}

	migrateDownCmd = &cobra.Command{
		Use:   "down",
		Short: "Run database migration down one version",
		Run: func(cmd *cobra.Command, args []string) {
			configFile, _ := cmd.Flags().GetString(configFileFlag)
			configKey, _ := cmd.Flags().GetString(configKeyFlag)
			cfg, err := config.LoadConfig(configKey, configFile)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}

			dbClient, err := migrateDBClient(cfg)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}

			err = dbClient.MigrationDown(cmd.Context())
			if err != nil {
				panic(fmt.Errorf("migration down failed: %w", err))
			}
			cmd.Println("migration down applied successfully")
		},
	}
	migrateUpCmd = &cobra.Command{
		Use:   "up",
		Short: "Run database migrations up to the latest version",
		Run: func(cmd *cobra.Command, _ []string) {
			configFile, _ := cmd.Flags().GetString(configFileFlag)
			configKey, _ := cmd.Flags().GetString(configKeyFlag)
			cfg, err := config.LoadConfig(configKey, configFile)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}
			dbClient, err := migrateDBClient(cfg)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}

			count, err := dbClient.RunMigrations(cmd.Context())
			if err != nil {
				panic(fmt.Errorf("migration up failed: %w", err))
			}
			cmd.Printf("migration up applied: %d versions up\n", count)
		},
	}

	migrateStatusCmd = &cobra.Command{
		Use:   "status",
		Short: "Show the status of the database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			configFile, _ := cmd.Flags().GetString(configFileFlag)
			configKey, _ := cmd.Flags().GetString(configKeyFlag)
			cfg, err := config.LoadConfig(configKey, configFile)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}
			dbClient, err := migrateDBClient(cfg)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}

			status, err := dbClient.MigrationStatus(cmd.Context())
			if err != nil {
				panic(fmt.Errorf("migration status failed: %w", err))
			}
			for _, s := range status {
				slog.Info("migration", slog.String("state", string(s.State)), slog.String("source", s.Source.Path), slog.String("applied_on", s.AppliedAt.String()))
			}
		},
	}
)

func migrateDBClient(conf *config.Config) (*db.Client, error) {
	slog.Info("creating database client")
	dbClient, err := db.NewClient(conf.DB)
	if err != nil {
		//nolint:wrapcheck // we want to return the error as is. the start command will wrap it
		return nil, err
	}
	return dbClient, nil
}

func init() {
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	rootCmd.AddCommand(migrateCmd)
}
