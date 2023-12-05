package db

import (
	"context"
	"errors"
	"fmt"
	"os"

	"ariga.io/atlas-go-sdk/atlasexec"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Client struct {
	*pgxpool.Pool
}

func NewClient(url string) (*Client, error) {
	// urlExample := "postgres://username:password@localhost:5432/database_name"
	// switch to config
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		return nil, err
	}
	return &Client{
		Pool: pool,
	}, err
}

func (c *Client) RunMigrations(dir string) (*atlasexec.MigrateApply, error) {
	workdir, err := atlasexec.NewWorkingDir(
		atlasexec.WithMigrations(
			os.DirFS(dir),
		),
	)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to load working directory: %v", err))
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
