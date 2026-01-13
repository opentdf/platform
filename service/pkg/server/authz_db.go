package server

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// setupAuthzGORMConnection sets up a GORM database connection for v2 authorization.
// Returns the cleanup function and any error encountered.
func setupAuthzGORMConnection(ctx context.Context, cfg *config.Config, log *logger.Logger) (func(), error) {
	log.Info("initializing SQL-backed policy storage for v2 authorization")

	// Create DB client
	dbClient, err := db.New(ctx, cfg.DB, cfg.Logger, nil,
		db.WithService("authz"),
	)
	if err != nil {
		log.Error("failed to create database client for authz", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create database client for authz: %w", err)
	}
	cleanup := func() { dbClient.Close() }

	// Get schema for GORM configuration
	dbSchema := dbClient.Schema()

	// Build PostgreSQL DSN
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.DB.Host,
		cfg.DB.Port,
		cfg.DB.User,
		cfg.DB.Password,
		cfg.DB.Database,
		cfg.DB.SSLMode,
	)
	if dbSchema != "" {
		dsn += fmt.Sprintf(" options='-c search_path=%s'", dbSchema)
	}

	// Create GORM connection
	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		SkipDefaultTransaction: true,
	})
	if err != nil {
		cleanup()
		log.Error("failed to create GORM connection for authz", slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to create GORM connection for authz: %w", err)
	}

	// Verify search_path is set correctly
	var currentSearchPath string
	if err := gormDB.Raw("SHOW search_path").Scan(&currentSearchPath).Error; err != nil {
		log.Warn("failed to verify search_path", slog.String("error", err.Error()))
	} else {
		log.Debug("verified GORM search_path", slog.String("search_path", currentSearchPath))
	}

	cfg.Server.Auth.Policy.GormDB = gormDB
	cfg.Server.Auth.Policy.Schema = dbSchema
	log.Info("SQL-backed policy storage configured",
		slog.String("schema", cfg.Server.Auth.Policy.Schema),
	)

	return cleanup, nil
}
