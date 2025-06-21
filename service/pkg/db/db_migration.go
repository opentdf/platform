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
		return nil, 0, nil, errors.New("migrations are disabled")
	}

	// Cast the pgxpool.Pool to a *sql.DB
	pool, ok := c.Pgx.(*pgxpool.Pool)
	if !ok || pool == nil {
		return nil, 0, nil, errors.New("failed to cast pgxpool.Pool")
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
		return nil, 0, nil, errors.Join(errors.New("failed to get current version"), e)
	}
	slog.Info("migration db info", slog.Int64("current_version", v))

	// Return the provider, version, and close function
	return provider, v, func() {
		if err := conn.Close(); err != nil {
			slog.Error("failed to close connection", slog.Any("err", err))
		}
	}, nil
}

// RunMigrations runs the migrations for the schema
// Schema will be created if it doesn't exist
func (c *Client) RunMigrations(ctx context.Context, migrations *embed.FS) (int, error) {
	if migrations == nil {
		return 0, errors.New("migrations FS is required to run migrations")
	}
	slog.Info("running migration up",
		slog.String("schema", c.config.Schema),
		slog.String("database", c.config.Database),
	)

	// Create schema if it doesn't exist
	q := "CREATE SCHEMA IF NOT EXISTS " + c.config.Schema
	tag, err := c.Pgx.Exec(ctx, q)
	if err != nil {
		slog.ErrorContext(ctx,
			"error while running command",
			slog.String("command", q),
			slog.Any("error", err),
		)
		return 0, err
	}
	applied := int(tag.RowsAffected())

	provider, version, closeProvider, err := migrationInit(ctx, c, migrations)
	if err != nil {
		slog.Error("failed to create goose provider", slog.Any("err", err))
		return 0, err
	}
	defer closeProvider()

	res, err := provider.Up(ctx)
	if err != nil {
		return applied, errors.Join(errors.New("failed to run migrations"), err)
	}

	if len(res) != 0 {
		version = res[len(res)-1].Source.Version
	}

	for _, r := range res {
		if r.Error != nil {
			return applied, errors.Join(errors.New("failed to run migrations"), err)
		}
		if !r.Empty {
			applied++
		}
	}
	c.ranMigrations = true
	slog.Info("migration up complete", slog.Int64("post_op_version", version))
	return applied, nil
}

func (c *Client) MigrationStatus(ctx context.Context) ([]*goose.MigrationStatus, error) {
	slog.Info("running migrations status",
		slog.String("schema", c.config.Schema),
		slog.String("database", c.config.Database),
	)
	provider, _, closeProvider, err := migrationInit(ctx, c, nil)
	if err != nil {
		slog.Error("failed to create goose provider", slog.Any("err", err))
		return nil, err
	}
	defer closeProvider()

	return provider.Status(ctx)
}

func (c *Client) MigrationDown(ctx context.Context, migrations *embed.FS) error {
	slog.Info("running migration down",
		slog.String("schema", c.config.Schema),
		slog.String("database", c.config.Database),
	)
	provider, _, closeProvider, err := migrationInit(ctx, c, migrations)
	if err != nil {
		slog.Error("failed to create goose provider", slog.Any("err", err))
		return err
	}
	defer closeProvider()

	res, err := provider.Down(ctx)
	if err != nil {
		return errors.Join(errors.New("failed to run migrations"), err)
	}
	if res.Error != nil {
		return errors.Join(errors.New("failed to run migrations"), res.Error)
	}

	slog.Info("migration down complete", slog.Int64("post_op_version", res.Source.Version))
	return nil
}

func (c *Client) MigrationsEnabled() bool {
	return c.config.RunMigrations
}

func (c *Client) RanMigrations() bool {
	return c.ranMigrations
}
