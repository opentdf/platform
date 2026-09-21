package namespaces

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/require"
)

func TestCreateNamespaceAuditsTransactionOutcome(t *testing.T) {
	failure := errors.New("database unavailable")
	for _, tt := range []struct {
		name         string
		beginErr     error
		writeErr     error
		commitErr    error
		auditErr     error
		wantResult   audit.ActionResult
		wantCommit   bool
		wantRollback bool
	}{
		{name: "begin failure", beginErr: failure, wantResult: audit.ActionResultError},
		{name: "write failure", writeErr: failure, wantResult: audit.ActionResultError, wantRollback: true},
		{name: "commit failure", commitErr: failure, wantResult: audit.ActionResultError, wantCommit: true},
		{name: "committed", wantResult: audit.ActionResultSuccess, wantCommit: true},
		{name: "committed with audit failure", auditErr: failure, wantResult: audit.ActionResultSuccess, wantCommit: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			var diagnostics bytes.Buffer
			var options []audit.Option
			attempts := 0
			if tt.auditErr != nil {
				options = append(options, audit.WithProcessor(audit.ProcessorFunc(func(_ context.Context, event audit.Event) error {
					attempts++
					require.Equal(t, audit.ActionResultSuccess, event.Action.Result)
					return tt.auditErr
				})))
			}
			auditLogger := audit.CreateAuditLogger(*slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{
				Level: audit.LevelAudit, ReplaceAttr: audit.ReplaceAttrAuditLevel,
			})), options...)
			serviceLogger := &logger.Logger{
				Logger: slog.New(slog.NewJSONHandler(&diagnostics, nil)),
				Audit:  auditLogger,
			}
			tx := &namespaceAuditTx{
				t: t, writeErr: tt.writeErr, commitErr: tt.commitErr,
				onCommit: func() { require.Empty(t, output.String(), "audit must follow the commit outcome") },
			}
			client := &db.Client{Pgx: &namespaceAuditPool{tx: tx, beginErr: tt.beginErr}}
			svc := NamespacesService{
				dbClient: policydb.NewClient(client, serviceLogger, 100, 100),
				logger:   serviceLogger,
				config:   &policyconfig.Config{},
			}
			handler := audit.ContextServerInterceptor()(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
				return svc.CreateNamespace(ctx, connect.NewRequest(&namespaces.CreateNamespaceRequest{Name: "audit.example"}))
			})
			_, err := handler(t.Context(), connect.NewRequest(&namespaces.CreateNamespaceRequest{}))
			if tt.wantResult == audit.ActionResultSuccess {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, tt.wantCommit, tx.committed)
			require.Equal(t, tt.wantRollback, tx.rolledBack)
			if tt.auditErr != nil {
				require.Equal(t, 1, attempts)
				require.Empty(t, output.String())
				require.Contains(t, diagnostics.String(), tt.auditErr.Error())
				return
			}

			var event struct {
				Audit struct {
					Action struct {
						Result string `json:"result"`
					} `json:"action"`
				} `json:"audit"`
			}
			decoder := json.NewDecoder(&output)
			require.NoError(t, decoder.Decode(&event))
			require.Equal(t, tt.wantResult.String(), event.Audit.Action.Result)
			require.ErrorIs(t, decoder.Decode(&event), io.EOF, "exactly one audit event must describe the transaction outcome")
		})
	}
}

type namespaceAuditPool struct {
	db.PgxIface
	tx       *namespaceAuditTx
	beginErr error
}

func (p *namespaceAuditPool) Begin(context.Context) (pgx.Tx, error) {
	return p.tx, p.beginErr
}

type namespaceAuditTx struct {
	pgx.Tx
	t          *testing.T
	writeErr   error
	commitErr  error
	onCommit   func()
	committed  bool
	rolledBack bool
}

func (tx *namespaceAuditTx) Commit(context.Context) error {
	tx.onCommit()
	tx.committed = true
	return tx.commitErr
}

func (tx *namespaceAuditTx) Rollback(context.Context) error {
	tx.rolledBack = true
	return nil
}

func (tx *namespaceAuditTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	require.True(tx.t, strings.HasPrefix(query, "-- name: createNamespace ") || strings.HasPrefix(query, "-- name: getNamespace "), "unexpected query: %s", query)
	return namespaceAuditRow{t: tx.t, err: tx.writeErr}
}

func (tx *namespaceAuditTx) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	require.True(tx.t, strings.HasPrefix(query, "-- name: upsertAttributeNamespaceFqn "), "unexpected query: %s", query)
	return namespaceAuditRows{}, nil
}

func (tx *namespaceAuditTx) Exec(_ context.Context, query string, _ ...any) (pgconn.CommandTag, error) {
	require.True(tx.t, strings.HasPrefix(query, "-- name: seedStandardActionsForNamespace "), "unexpected query: %s", query)
	return pgconn.NewCommandTag("INSERT 0 4"), nil
}

type namespaceAuditRow struct {
	t   *testing.T
	err error
}

func (r namespaceAuditRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, target := range dest {
		switch target := target.(type) {
		case *string:
			if i == 0 {
				*target = "954bc2d1-fac0-4a80-ae58-a1171ebc71f6"
			} else {
				*target = "audit.example"
			}
		case *bool:
			*target = true
		case *pgtype.Text:
			*target = pgtype.Text{String: "https://audit.example", Valid: true}
		case *[]byte:
			*target = nil
		default:
			r.t.Fatalf("unexpected namespace column type %T", target)
		}
	}
	return nil
}

type namespaceAuditRows struct{ pgx.Rows }

func (namespaceAuditRows) Next() bool { return false }
func (namespaceAuditRows) Err() error { return nil }
func (namespaceAuditRows) Close()     {}
