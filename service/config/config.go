package config

import (
	"context"
	"embed"
	"log/slog"

	"github.com/opentdf/platform/service/config/db"
	"github.com/opentdf/platform/service/config/db/migrations"
	otdfDb "github.com/opentdf/platform/service/pkg/db"
)

var Migrations *embed.FS

func init() {
	Migrations = &migrations.FS
}

type ConfigService struct {
	queries *db.Queries
}

func New(dbClient *otdfDb.Client) *ConfigService {
	return &ConfigService{
		queries: db.New(dbClient.Pgx),
	}
}

func (s *ConfigService) LoadConfig(ctx context.Context, svcNamespace string) error {
	slog.Info("loaded configuration for service", slog.Any("namespace", svcNamespace))

	// todo: implement

	return nil
}
