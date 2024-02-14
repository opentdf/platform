package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/opentdf/opentdf-v2-poc/migrations"
	"github.com/pressly/goose/v3"
)

func (c *Client) RunMigrations(ctx context.Context) (int, error) {
	var (
		applied int
		err     error
	)

	exec := func(q string) {
		if err != nil {
			return
		}
		var tag pgconn.CommandTag
		tag, err = c.Exec(ctx, q)
		if err != nil {
			slog.ErrorContext(ctx, "Error while running command", "query", q, "err", err)
		}
		applied += int(tag.RowsAffected())
	}

	if !c.config.RunMigrations {
		slog.Info("skipping migrations",
			slog.String("reason", "runMigrations is false"),
			slog.Bool("runMigrations", c.config.RunMigrations))
		return applied, nil
	}

	// create the schema
	exec(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", c.config.Schema))
	// set the search path
	exec(fmt.Sprintf("SET search_path TO %s", c.config.Schema))

	pool, ok := c.PgxIface.(*pgxpool.Pool)
	if !ok || pool == nil {
		return applied, fmt.Errorf("failed to cast pgxpool.Pool")
	}

	conn := stdlib.OpenDBFromPool(pool)
	defer conn.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, conn, migrations.MigrationsFS)
	if err != nil {
		return applied, errors.Join(fmt.Errorf("failed to create goose provider"), err)
	}

	res, err := provider.Up(context.Background())
	if err != nil {
		return applied, errors.Join(fmt.Errorf("failed to run migrations"), err)
	}

	for _, r := range res {
		if r.Error != nil {
			return applied, errors.Join(fmt.Errorf("failed to run migrations"), err)
		}
		if !r.Empty {
			applied++
		}
	}

	return applied, nil
}

func (c *Client) MigrationDown() (int, error) {
	var (
		applied int
	)

	if !c.config.RunMigrations {
		slog.Info("skipping migrations",
			slog.String("reason", "runMigrations is false"),
			slog.Bool("runMigrations", c.config.RunMigrations))
		return applied, nil
	}

	pool, ok := c.PgxIface.(*pgxpool.Pool)
	if !ok || pool == nil {
		return applied, fmt.Errorf("failed to cast pgxpool.Pool")
	}

	conn := stdlib.OpenDBFromPool(pool)
	defer conn.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, conn, migrations.MigrationsFS)
	if err != nil {
		return applied, errors.Join(fmt.Errorf("failed to create goose provider"), err)
	}

	res, err := provider.Down(context.Background())
	if err != nil {
		return applied, errors.Join(fmt.Errorf("failed to run migrations"), err)
	}
	if res.Error != nil {
		return applied, errors.Join(fmt.Errorf("failed to run migrations"), err)
	}

	return applied, nil
}
