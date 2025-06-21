package fixtures

import (
	"context"
	"log/slog"
	"strconv"
	"strings"

	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/opentdf/platform/service/tracing"
	"go.opentelemetry.io/otel"
)

var (
	// Configured default LIST Limit when working with fixtures
	fixtureLimitDefault int32 = 1000
	fixtureLimitMax     int32 = 5000
)

type DBInterface struct {
	Client       *db.Client
	PolicyClient policydb.PolicyDBClient
	Schema       string
	LimitDefault int32
	LimitMax     int32
}

func NewDBInterface(cfg config.Config) DBInterface {
	config := cfg.DB
	config.Schema = cfg.DB.Schema
	logCfg := cfg.Logger
	tracer := otel.Tracer(tracing.ServiceName)

	c, err := db.New(context.Background(), config, logCfg, &tracer)
	if err != nil {
		slog.Error("issue creating database client", slog.String("error", err.Error()))
		panic(err)
	}

	logger, err := logger.NewLogger(logger.Config{
		Level:  cfg.Logger.Level,
		Output: cfg.Logger.Output,
		Type:   cfg.Logger.Type,
	})
	if err != nil {
		slog.Error("issue creating logger", slog.String("error", err.Error()))
		panic(err)
	}

	return DBInterface{
		Client:       c,
		Schema:       config.Schema,
		PolicyClient: policydb.NewClient(c, logger, fixtureLimitMax, fixtureLimitDefault),
		LimitDefault: fixtureLimitDefault,
		LimitMax:     fixtureLimitMax,
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
	escaped := strings.ReplaceAll(v, "'", "''")
	return "'" + escaped + "'"
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
		slog.Error("insert error",
			slog.Any("stmt", sql),
			slog.Any("err", err),
		)
		return 0, err
	}
	return pconn.RowsAffected(), err
}

func (d *DBInterface) DropSchema() error {
	sql := "DROP SCHEMA IF EXISTS " + d.Schema + " CASCADE"
	_, err := d.Client.Pgx.Exec(context.Background(), sql)
	if err != nil {
		slog.Error("drop error",
			slog.String("stmt", sql),
			slog.Any("err", err),
		)
		return err
	}
	return nil
}
