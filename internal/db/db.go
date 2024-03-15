package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net"

	sq "github.com/Masterminds/squirrel"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

var (
	TableAttributes                      = "attribute_definitions"
	TableAttributeValues                 = "attribute_values"
	TableNamespaces                      = "attribute_namespaces"
	TableAttrFqn                         = "attribute_fqns"
	TableKeyAccessServerRegistry         = "key_access_servers"
	TableAttributeKeyAccessGrants        = "attribute_definition_key_access_grants"
	TableAttributeValueKeyAccessGrants   = "attribute_value_key_access_grants"
	TableResourceMappings                = "resource_mappings"
	TableSubjectMappings                 = "subject_mappings"
	TableSubjectMappingConditionSetPivot = "subject_mapping_condition_set_pivot"
	TableSubjectConditionSet             = "subject_condition_set"
)

var Tables struct {
	Attributes                      Table
	AttributeValues                 Table
	Namespaces                      Table
	AttrFqn                         Table
	KeyAccessServerRegistry         Table
	AttributeKeyAccessGrants        Table
	AttributeValueKeyAccessGrants   Table
	ResourceMappings                Table
	SubjectMappings                 Table
	SubjectMappingConditionSetPivot Table
	SubjectConditionSet             Table
}

type Table struct {
	name       string
	schema     string
	withSchema bool
}

func NewTable(name string, schema string) Table {
	return Table{
		name:       name,
		schema:     schema,
		withSchema: true,
	}
}

func (t Table) WithoutSchema() Table {
	nT := NewTable(t.name, t.schema)
	nT.withSchema = false
	return nT
}

func (t Table) Name() string {
	if t.withSchema {
		return t.schema + "." + string(t.name)
	}
	return string(t.name)
}

func (t Table) Field(field string) string {
	return t.Name() + "." + field
}

// We can rename this but wanted to get mocks working.
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
	Host          string `yaml:"host" default:"localhost"`
	Port          int    `yaml:"port" default:"5432"`
	Database      string `yaml:"database" default:"opentdf"`
	User          string `yaml:"user" default:"postgres"`
	Password      string `yaml:"password" default:"changeme"`
	RunMigrations bool   `yaml:"runMigrations" default:"true"`
	SSLMode       string `yaml:"sslmode" default:"prefer"`
	Schema        string `yaml:"schema" default:"opentdf"`
}

type Client struct {
	Pgx    PgxIface
	config Config

	// This is the stdlib connection that is used for transactions
	SqlDB *sql.DB
}

func NewClient(config Config) (*Client, error) {
	c := Client{
		config: config,
	}

	dbConfig, err := pgxpool.ParseConfig(config.buildURL())
	if err != nil {
		return nil, fmt.Errorf("failed to parse pgx config: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), dbConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgxpool: %w", err)
	}

	c.Pgx = pool
	// We need to create a stdlib connection for transactions
	c.SqlDB = stdlib.OpenDBFromPool(pool)

	// Connect to the database to verify the connection
	if err := c.Pgx.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations
	slog.Info("running database migrations")
	appliedMigrations, err := c.RunMigrations(context.Background())
	if err != nil {
		return nil, fmt.Errorf("issue running database migrations: %w", err)
	}
	slog.Info("database migrations complete", slog.Int("applied", appliedMigrations))

	Tables.Attributes = NewTable(TableAttributes, config.Schema)
	Tables.AttributeValues = NewTable(TableAttributeValues, config.Schema)
	Tables.Namespaces = NewTable(TableNamespaces, config.Schema)
	Tables.AttrFqn = NewTable(TableAttrFqn, config.Schema)
	Tables.KeyAccessServerRegistry = NewTable(TableKeyAccessServerRegistry, config.Schema)
	Tables.AttributeKeyAccessGrants = NewTable(TableAttributeKeyAccessGrants, config.Schema)
	Tables.AttributeValueKeyAccessGrants = NewTable(TableAttributeValueKeyAccessGrants, config.Schema)
	Tables.ResourceMappings = NewTable(TableResourceMappings, config.Schema)
	Tables.SubjectMappings = NewTable(TableSubjectMappings, config.Schema)
	Tables.SubjectMappingConditionSetPivot = NewTable(TableSubjectMappingConditionSetPivot, config.Schema)
	Tables.SubjectConditionSet = NewTable(TableSubjectConditionSet, config.Schema)

	return &c, nil
}

func (c *Client) Close() {
	c.Pgx.Close()
	c.SqlDB.Close()
}

func (c Config) buildURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		c.User,
		c.Password,
		net.JoinHostPort(c.Host, fmt.Sprint(c.Port)),
		c.Database,
		c.SSLMode,
	)
}

// Common function for all queryRow calls
func (c Client) QueryRow(ctx context.Context, sql string, args []interface{}, err error) (pgx.Row, error) {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	if err != nil {
		return nil, err
	}
	return c.Pgx.QueryRow(ctx, sql, args...), nil
}

// Common function for all query calls
func (c Client) Query(ctx context.Context, sql string, args []interface{}, err error) (pgx.Rows, error) {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	if err != nil {
		return nil, err
	}
	r, e := c.Pgx.Query(ctx, sql, args...)
	return r, WrapIfKnownInvalidQueryErr(e)
}

// Common function for all exec calls
func (c Client) Exec(ctx context.Context, sql string, args []interface{}) error {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	tag, err := c.Pgx.Exec(ctx, sql, args...)
	if err != nil {
		return WrapIfKnownInvalidQueryErr(err)
	}

	if tag.RowsAffected() == 0 {
		return WrapIfKnownInvalidQueryErr(pgx.ErrNoRows)
	}

	return nil
}

//
// Helper functions for building SQL
//

// Postgres uses $1, $2, etc. for placeholders
func NewStatementBuilder() sq.StatementBuilderType {
	return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}
