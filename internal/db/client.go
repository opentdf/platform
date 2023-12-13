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
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
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

type Config struct {
	Host     string `yaml:"host" default:"localhost"`
	Port     int    `yaml:"port" default:"5432"`
	Database string `yaml:"database" default:"opentdf"`
	User     string `yaml:"user" default:"postgres"`
	Password string `yaml:"password" default:"changeme"`
	// TODO: add support for sslmode
}

type Client struct {
	PgxIface
}

func NewClient(config Config) (*Client, error) {
	// urlExample := "postgres://username:password@localhost:5432/database_name"
	// switch to config

	pool, err := pgxpool.New(context.Background(), config.buildURL())
	if err != nil {
		return nil, err
	}
	return &Client{
		PgxIface: pool,
	}, err
}

func (c Config) buildURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		c.User,
		c.Password,
		c.Host,
		c.Port,
		c.Database,
	)
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

func (c Client) CreateResource(descriptor *commonv1.ResourceDescriptor, resource []byte, policyType string) error {
	var err error

	args := pgx.NamedArgs{
		"namespace":   descriptor.Namespace,
		"version":     descriptor.Version,
		"fqn":         descriptor.Fqn,
		"label":       descriptor.Label,
		"description": descriptor.Description,
		"policytype":  policyType,
		"resource":    resource,
	}
	_, err = c.Exec(context.TODO(), `
	INSERT INTO opentdf.resources (
		namespace,
		version,
		fqn,
		label,
		description,
		policytype,
		resource
	)
	VALUES (
		@namespace,
		@version,
		@fqn,
		@label,
		@description,
		@policytype,
		@resource
	)
	`, args)
	return err
}

func (c Client) ListResources(policyType string) (pgx.Rows, error) {
	args := pgx.NamedArgs{
		"policytype": policyType,
	}
	return c.Query(context.TODO(), `
		SELECT
			id,
		  resource
		FROM opentdf.resources
		WHERE policytype = @policytype
	`, args)
}

func (c Client) GetResource(id string, policyType string) pgx.Row {
	args := pgx.NamedArgs{
		"id":         id,
		"policytype": policyType,
	}
	return c.QueryRow(context.TODO(), `
		SELECT
			id,
		  resource
		FROM opentdf.resources
		WHERE id = @id AND policytype = @policytype
	`, args)
}

func (c Client) UpdateResource(descriptor *commonv1.ResourceDescriptor, resource []byte, policyType string) error {
	var err error

	args := pgx.NamedArgs{
		"namespace":   descriptor.Namespace,
		"version":     descriptor.Version,
		"fqn":         descriptor.Fqn,
		"label":       descriptor.Label,
		"description": descriptor.Description,
		"policytype":  policyType,
		"resource":    resource,
		"id":          descriptor.Id,
	}
	_, err = c.Exec(context.TODO(), `
	UPDATE opentdf.resources
	SET 
	namespace = @namespace,
	version = @version,
	description = @description,
	fqn = @fqn,
	label = @label,
	policyType = @policytype,
	resource = @resource
	WHERE id = @id
	`, args)
	return err
}

func (c Client) DeleteResource(id string, policyType string) error {
	args := pgx.NamedArgs{
		"id":         id,
		"policytype": policyType,
	}
	_, err := c.Query(context.TODO(), `
	DELETE FROM opentdf.resources
	WHERE id = @id AND policytype = @policytype
	`, args)
	return err
}
