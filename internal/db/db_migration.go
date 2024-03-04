package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/opentdf/platform/migrations"
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
		tag, err = c.Pgx.Exec(ctx, q)
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

	pool, ok := c.Pgx.(*pgxpool.Pool)
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

func (c *Client) MigrationDown(ctx context.Context) error {
	if !c.config.RunMigrations {
		slog.Info("skipping migrations",
			slog.String("reason", "runMigrations is false"),
			slog.Bool("runMigrations", c.config.RunMigrations))
		return nil
	}

	c.Pgx.Exec(ctx, fmt.Sprintf("SET search_path TO %s", c.config.Schema))

	pool, ok := c.Pgx.(*pgxpool.Pool)
	if !ok || pool == nil {
		return fmt.Errorf("failed to cast pgxpool.Pool")
	}

	conn := stdlib.OpenDBFromPool(pool)
	defer conn.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, conn, migrations.MigrationsFS)
	if err != nil {
		return errors.Join(fmt.Errorf("failed to create goose provider"), err)
	}

	v, e := provider.GetDBVersion(context.Background())
	if e != nil {
		return errors.Join(fmt.Errorf("failed to get current version"), e)
	}
	slog.Info("DB Info: ", slog.Any("current version", v), slog.Any("post-migration version", v-1))

	res, err := provider.Down(context.Background())
	if err != nil {
		return errors.Join(fmt.Errorf("failed to run migrations"), err)
	}
	if res.Error != nil {
		return errors.Join(fmt.Errorf("failed to run migrations"), res.Error)
	}

	return nil
}
