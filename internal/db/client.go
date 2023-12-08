package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// We can rename this but wanted to get mocks working
type PgxIface interface {
	Acquire(ctx context.Context) (*pgxpool.Conn, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
	Ping(context.Context) error
	Close()
	Config() *pgxpool.Config
}

type Client struct {
	PgxIface
}

func NewClient(url string) (*Client, error) {
	// urlExample := "postgres://username:password@localhost:5432/database_name"
	// switch to config
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return &Client{
		PgxIface: pool,
	}, err
}

//go:embed migrations/*.sql
var embedMigrations embed.FS

func (c *Client) RunMigrations() (int, error) {
	var (
		applied int
	)

	fsys, err := fs.Sub(embedMigrations, "migrations")
	if err != nil {
		return applied, errors.Join(fmt.Errorf("failed to create migrations filesystem"), err)
	}

	conn := stdlib.OpenDBFromPool(c.PgxIface.(*pgxpool.Pool))
	defer conn.Close()

	provider, err := goose.NewProvider(goose.DialectPostgres, conn, fsys)
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
