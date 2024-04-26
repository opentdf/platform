package fixtures

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/opentdf/platform/service/internal/config"

	"github.com/opentdf/platform/service/internal/db"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type DBInterface struct {
	Client       *db.Client
	PolicyClient policydb.PolicyDBClient
	Schema       string
}

func NewDBInterface(cfg config.Config) DBInterface {
	config := cfg.DB
	config.Schema = cfg.DB.Schema
	c, err := db.New(context.Background(), config)
	if err != nil {
		slog.Error("issue creating database client", slog.String("error", err.Error()))
		panic(err)
	}
	return DBInterface{
		Client:       c,
		Schema:       config.Schema,
		PolicyClient: policydb.NewClient(c),
	}
}

func (d *DBInterface) StringArrayWrap(values []string) string {
	// if len(values) == 0 {
	// 	return "null"
	// }
	var vs []string
	for _, v := range values {
		vs = append(vs, d.StringWrap(v))
	}
	return "ARRAY [" + strings.Join(vs, ",") + "]"
}

func (d *DBInterface) UUIDArrayWrap(v []string) string {
	return "(" + d.StringArrayWrap(v) + ")" + "::uuid[]"
}

func (d *DBInterface) StringWrap(v string) string {
	return "'" + v + "'"
}

func (d *DBInterface) OptionalStringWrap(v string) string {
	if v == "" {
		return "NULL"
	}
	return d.StringWrap(v)
}

func (d *DBInterface) BoolWrap(b bool) string {
	return strconv.FormatBool(b)
}

func (d *DBInterface) UUIDWrap(v string) string {
	return "(" + d.StringWrap(v) + ")" + "::uuid"
}

func (d *DBInterface) TableName(v string) string {
	return d.Schema + "." + v
}

func (d *DBInterface) ExecInsert(table string, columns []string, values ...[]string) (int64, error) {
	sql := "INSERT INTO " + d.TableName(table) +
		" (" + strings.Join(columns, ",") + ")" +
		" VALUES "
	for i, v := range values {
		if i > 0 {
			sql += ","
		}
		sql += " (" + strings.Join(v, ",") + ")"
	}
	pconn, err := d.Client.Pgx.Exec(context.Background(), sql)
	if err != nil {
		slog.Error("insert error", "stmt", sql, "err", err)
		return 0, err
	}
	return pconn.RowsAffected(), err
}

func (d *DBInterface) DropSchema() error {
	sql := "DROP SCHEMA IF EXISTS " + d.Schema + " CASCADE"
	_, err := d.Client.Pgx.Exec(context.Background(), sql)
	if err != nil {
		slog.Error("drop error", "stmt", sql, "err", err)
		return err
	}
	return nil
}
