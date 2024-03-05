package db

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
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
}

func NewClient(config Config) (*Client, error) {
	pool, err := pgxpool.New(context.Background(), config.buildURL())
	if err != nil {
		return nil, fmt.Errorf("failed to create pgxpool: %w", err)
	}

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

	return &Client{
		Pgx:    pool,
		config: config,
	}, nil
}

func (c *Client) Close() {
	c.Pgx.Close()
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

func (c Client) QueryCount(ctx context.Context, sql string, args []interface{}) (int, error) {
	rows, err := c.Query(ctx, sql, args, nil)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		if _, err := rows.Values(); err != nil {
			return 0, err
		}
		count++
	}
	if count == 0 {
		return 0, pgx.ErrNoRows
	}

	return count, nil
}

// Common function for all exec calls
func (c Client) Exec(ctx context.Context, sql string, args []interface{}, err error) error {
	slog.Debug("sql", slog.String("sql", sql), slog.Any("args", args))
	if err != nil {
		return err
	}
	_, err = c.Pgx.Exec(ctx, sql, args...)
	return WrapIfKnownInvalidQueryErr(err)
}

//
// Helper functions for building SQL
//

// Postgres uses $1, $2, etc. for placeholders
func NewStatementBuilder() sq.StatementBuilderType {
	return sq.StatementBuilder.PlaceholderFormat(sq.Dollar)
}
