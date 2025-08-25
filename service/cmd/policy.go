package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/policy"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/spf13/cobra"
)

var policyFqnReindexCmdLong = `
Reindex FQN across namespaces, attributes, and attribute values

This command will reindex all FQNs across namespaces, attributes, and attribute values. This is
useful when the FQN generation logic changes and the FQNs need to be updated across the platform.
`

var (
	policyCmd = &cobra.Command{
		Use:   "policy",
		Short: "Run policy migrations",
	}

	policyFqnReindexCmd = &cobra.Command{
		Use:   "fqn-reindex",
		Short: "Reindex FQNs across the platform",
		Long:  policyFqnReindexCmdLong,

		Run: func(cmd *cobra.Command, _ []string) {
			configFile, _ := cmd.Flags().GetString(configFileFlag)
			configKey, _ := cmd.Flags().GetString(configKeyFlag)
			envLoader, err := config.NewEnvironmentValueLoader(configKey, nil)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}
			configFileLoader, err := config.NewConfigFileLoader(configKey, configFile)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}
			defaultSettingsLoader, err := config.NewDefaultSettingsLoader()
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}
			cfg, err := config.LoadConfig(cmd.Context(), []config.Loader{
				envLoader,
				configFileLoader,
				defaultSettingsLoader,
			})
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}
			dbClient, err := policyDBClient(cfg)
			if err != nil {
				panic(fmt.Errorf("could not load config: %w", err))
			}

			ctx := context.Background()

			// ignore error as dbClient.AttrFqnReindex will panic on error
			_ = dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
				res := txClient.AttrFqnReindex(ctx)

				cmd.Print("Namespace FQNs reindexed:\n")
				for _, r := range res.Namespaces {
					cmd.Printf("\t%s: %s\n", r.ID, r.Fqn)
				}

				cmd.Print("Attribute FQNs reindexed:\n")
				for _, r := range res.Attributes {
					cmd.Printf("\t%s: %s\n", r.ID, r.Fqn)
				}

				cmd.Print("Attribute Value FQNs reindexed:\n")
				for _, r := range res.Values {
					cmd.Printf("\t%s: %s\n", r.ID, r.Fqn)
				}

				return nil
			})
		},
	}
)

func policyDBClient(conf *config.Config) (policydb.PolicyDBClient, error) {
	slog.Info("creating database client")
	if !strings.HasSuffix(conf.DB.Schema, "_policy") {
		conf.DB.Schema += "_policy"
	}
	dbClient, err := db.New(context.Background(), conf.DB, conf.Logger, nil, db.WithMigrations(policy.Migrations))
	if err != nil {
		//nolint:wrapcheck // we want to return the error as is. the start command will wrap it
		return policydb.PolicyDBClient{}, err
	}

	logger, err := logger.NewLogger(logger.Config{
		Level:  conf.Logger.Level,
		Output: conf.Logger.Output,
		Type:   conf.Logger.Type,
	})
	if err != nil {
		return policydb.PolicyDBClient{}, err
	}

	// This command connects directly to the database so runtime policy config list limit settings can be ignored
	var (
		limitDefault int32 = 1000
		limitMax     int32 = 2500
	)

	return policydb.NewClient(dbClient, logger, limitMax, limitDefault), nil
}

func init() {
	policyCmd.AddCommand(policyFqnReindexCmd)
	rootCmd.AddCommand(policyCmd)
}
