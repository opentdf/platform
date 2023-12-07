package db

import (
	"context"
	"errors"
	"fmt"
	"os"

	"ariga.io/atlas-go-sdk/atlasexec"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// We can rename this but wanted to get mocks working
type PgxIface interface {
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

func (c *Client) RunMigrations(dir string) (*atlasexec.MigrateApply, error) {
	workdir, err := atlasexec.NewWorkingDir(
		atlasexec.WithMigrations(
			os.DirFS(dir),
		),
	)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to load working directory"), err)
	}
	// atlasexec works on a temporary directory, so we need to close it
	defer workdir.Close()

	// Initialize the client.
	client, err := atlasexec.NewClient(workdir.Path(), "atlas")
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to initialize atlas"), err)
	}
	// Run `atlas migrate apply` on a SQLite database under /tmp.
	res, err := client.Apply(context.Background(), &atlasexec.MigrateApplyParams{
		URL: c.Config().ConnString(),
	})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to apply migrations"), err)
	}
	if res.Error != "" {
		return nil, fmt.Errorf("failed to apply migrations: %s", res.Error)
	}
	return res, nil
}
