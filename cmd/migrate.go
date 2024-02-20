package cmd

import (
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/internal/config"
	"github.com/opentdf/platform/internal/db"
	"github.com/spf13/cobra"
)

var (
	migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
	}

	migrateDownCmd = &cobra.Command{
		Use:   "down",
		Short: "Run database migrations",
		Run: func(cmd *cobra.Command, args []string) {
			dbClient, err := migrateDbClient()
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}

			res, err := dbClient.MigrationDown()
			if err != nil {
				panic(fmt.Errorf("migration down failed: %w", err))
			}
			fmt.Print("migration down applied: ", slog.Any("res", res))
		},
	}
)

func migrateDbClient() (*db.Client, error) {
	// Load the config
	conf, err := config.LoadConfig()
	if err != nil {
		return nil, err
	}

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
	rootCmd.AddCommand(migrateCmd)
}
