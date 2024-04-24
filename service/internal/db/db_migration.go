package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func migrationInit(ctx context.Context, c *Client, migrations *embed.FS) (*goose.Provider, int64, func(), error) {
	if !c.config.RunMigrations {
		return nil, 0, nil, fmt.Errorf("migrations are disabled")
	}

	// Set the schema
	q := fmt.Sprintf("SET search_path TO %s", c.config.Schema)
	if tag, err := c.Pgx.Exec(ctx, q); err != nil {
		slog.Error("migration error", slog.String("query", q), slog.String("error", err.Error()), slog.Any("tag", tag))
		return nil, 0, nil, fmt.Errorf("failed to SET search_path [%w]", err)
	}

	// Cast the pgxpool.Pool to a *sql.DB
	pool, ok := c.Pgx.(*pgxpool.Pool)
	if !ok || pool == nil {
		return nil, 0, nil, fmt.Errorf("failed to cast pgxpool.Pool")
	}
	conn := stdlib.OpenDBFromPool(pool)

	// Create the goose provider
	provider, err := goose.NewProvider(goose.DialectPostgres, conn, migrations)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to create goose provider: %w", err)
	}

	// Get the current version
	v, e := provider.GetDBVersion(ctx)
	if e != nil {
		return nil, 0, nil, errors.Join(fmt.Errorf("failed to get current version"), e)
	}
	slog.Info("migration db info ", slog.Any("current version", v))

	// Return the provider, version, and close function
	return provider, v, func() {
		if err := conn.Close(); err != nil {
			slog.Error("failed to close connection", "err", err)
		}
	}, nil
}

// RunMigrations runs the migrations for the schema
// Schema will be created if it doesn't exist
func (c *Client) RunMigrations(ctx context.Context, migrations *embed.FS) (int, error) {
	slog.Info("running migration up", slog.String("schema", c.config.Schema), slog.String("database", c.config.Database))

	// Create schema if it doesn't exist
	q := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", c.config.Schema)
	tag, err := c.Pgx.Exec(ctx, q)
	if err != nil {
		slog.ErrorContext(ctx, "Error while running command", slog.String("command", q), slog.String("error", err.Error()))
		return 0, err
	}
	applied := int(tag.RowsAffected())

	provider, version, closeProvider, err := migrationInit(ctx, c, migrations)
	if err != nil {
		slog.Error("failed to create goose provider", "err", err)
		return 0, err
	}
	defer closeProvider()

	res, err := provider.Up(ctx)
	if err != nil {
		return applied, errors.Join(fmt.Errorf("failed to run migrations"), err)
	}

	if len(res) != 0 {
		version = res[len(res)-1].Source.Version
	}

	for _, r := range res {
		if r.Error != nil {
			return applied, errors.Join(fmt.Errorf("failed to run migrations"), err)
		}
		if !r.Empty {
			applied++
		}
	}

	slog.Info("migration up complete", slog.Any("post-op version", version))
	return applied, nil
}

func (c *Client) MigrationStatus(ctx context.Context) ([]*goose.MigrationStatus, error) {
	slog.Info("running migrations status", slog.String("schema", c.config.Schema), slog.String("database", c.config.Database))
	provider, _, closeProvider, err := migrationInit(ctx, c, nil)
	if err != nil {
		slog.Error("failed to create goose provider", "err", err)
		return nil, err
	}
	defer closeProvider()

	return provider.Status(ctx)
}

func (c *Client) MigrationDown(ctx context.Context, migrations *embed.FS) error {
	slog.Info("running migration down", slog.String("schema", c.config.Schema), slog.String("database", c.config.Database))
	provider, _, closeProvider, err := migrationInit(ctx, c, migrations)
	if err != nil {
		slog.Error("failed to create goose provider", "err", err)
		return err
	}
	defer closeProvider()

	res, err := provider.Down(ctx)
	if err != nil {
		return errors.Join(fmt.Errorf("failed to run migrations"), err)
	}
	if res.Error != nil {
		return errors.Join(fmt.Errorf("failed to run migrations"), res.Error)
	}

	slog.Info("migration down complete ", slog.Any("post-op version", res.Source.Version))
	return nil
}
