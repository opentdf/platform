package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/obligations/obligationsconnectv2"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources/registeredresourcesconnectv2"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/policy"
	policydb "github.com/opentdf/platform/service/policy/db"
	obligationsservice "github.com/opentdf/platform/service/policy/obligations"
	registeredresourcesservice "github.com/opentdf/platform/service/policy/registeredresources"
	"github.com/stretchr/testify/require"
)

// BenchmarkPolicyWriteRPC measures serialized HTTP RPCs against real Postgres,
// including service transactions, response hydration, and audit event construction.
// Authentication and deployment middleware are outside this benchmark. Each
// definition has 100 sibling values; the catalog size varies independently.
// Cleanup and five warmup requests are excluded from the measurements.
func BenchmarkPolicyWriteRPC(b *testing.B) {
	for _, valueCount := range []int{100, 10000, 100000} {
		b.Run(fmt.Sprintf("Values%d", valueCount), func(b *testing.B) {
			ctx := b.Context()
			cfg := *Config
			cfg.DB.Schema = "benchmark_policy_write_" + uuid.NewString()[:8]
			d := fixtures.NewDBInterface(ctx, cfg)
			b.Cleanup(func() {
				require.NoError(b, d.DropSchema(context.Background())) //nolint:usetesting // b.Context is canceled before cleanup
				d.Client.Close()
			})
			_, err := d.Client.RunMigrations(ctx, policy.Migrations)
			require.NoError(b, err)

			// Keep audit processing in the measured path, with output directed to a
			// discard writer so terminal throughput does not determine the result.
			slogLogger := slog.New(slog.NewJSONHandler(io.Discard, nil)) //nolint:sloglint // include audit JSON serialization in the measurement
			log := &logger.Logger{Logger: slogLogger, Audit: audit.CreateAuditLogger(*slogLogger)}
			d.PolicyClient = policydb.NewClient(d.Client, log, 2500, 1000)
			ns, err := d.PolicyClient.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{Name: "benchmark.example"})
			require.NoError(b, err)
			action, err := d.PolicyClient.CreateAction(ctx, &actions.CreateActionRequest{Name: "benchmark_action", NamespaceId: ns.GetId()})
			require.NoError(b, err)
			obl, err := d.PolicyClient.CreateObligation(ctx, &obligations.CreateObligationRequest{Name: "benchmark_obligation", NamespaceId: ns.GetId()})
			require.NoError(b, err)
			oblValue, err := d.PolicyClient.CreateObligationValue(ctx, &obligations.CreateObligationValueRequest{ObligationId: obl.GetId(), Value: "required"})
			require.NoError(b, err)
			resource, err := d.PolicyClient.CreateRegisteredResource(ctx, &registeredresources.CreateRegisteredResourceRequest{Name: "benchmark_resource", NamespaceId: ns.GetId()})
			require.NoError(b, err)

			// Deterministic IDs and names give each revision the same catalog. Bulk
			// seed through SQL; the normal values_order trigger remains enabled.
			_, err = d.Client.Pgx.Exec(ctx, "INSERT INTO "+d.TableName("attribute_definitions")+`
				(id, namespace_id, name, rule)
				SELECT md5('definition-' || i)::uuid, $1::uuid, 'attribute-' || i, 'ALL_OF'
				FROM generate_series(0, $2::int / 100 - 1) AS i`, ns.GetId(), valueCount)
			require.NoError(b, err)
			_, err = d.Client.Pgx.Exec(ctx, "INSERT INTO "+d.TableName("attribute_values")+`
				(id, attribute_definition_id, value)
				SELECT md5('value-' || i)::uuid, md5('definition-' || (i / 100))::uuid, 'value-' || i
				FROM generate_series(0, $1::int - 1) AS i`, valueCount)
			require.NoError(b, err)
			_, err = d.Client.Pgx.Exec(ctx, "INSERT INTO "+d.TableName("attribute_fqns")+`
				(namespace_id, attribute_id, value_id, fqn)
				SELECT ad.namespace_id, ad.id, av.id,
				'https://benchmark.example/attr/' || ad.name || '/value/' || av.value
				FROM `+d.TableName("attribute_values")+" av JOIN "+d.TableName("attribute_definitions")+" ad ON ad.id = av.attribute_definition_id")
			require.NoError(b, err)
			for _, table := range []string{"attribute_values", "attribute_definitions", "attribute_fqns"} {
				_, err = d.Client.Pgx.Exec(ctx, "ANALYZE "+d.TableName(table))
				require.NoError(b, err)
			}
			var valueID string
			err = d.Client.Pgx.QueryRow(ctx, "SELECT id FROM "+d.TableName("attribute_values")+" WHERE value = 'value-0'").Scan(&valueID)
			require.NoError(b, err)
			const valueFQN = "https://benchmark.example/attr/attribute-0/value/value-0"

			params := serviceregistry.RegistrationParams{
				DBClient: d.Client, Logger: log, Config: config.ServiceConfig{"namespaced_policy": true},
			}
			rrHandler, _ := registeredresourcesservice.NewRegistration("policy", serviceregistry.DBRegister{}).RegisterFunc(params)
			oblHandler, _ := obligationsservice.NewRegistration("policy", serviceregistry.DBRegister{}).RegisterFunc(params)
			server := connect.NewServer()
			registeredresourcesconnectv2.RegisterRegisteredResourcesServiceHandler(server, rrHandler)
			obligationsconnectv2.RegisterServiceHandler(server, oblHandler)
			mux := http.NewServeMux()
			connecthttp.Mount(mux, server)
			httpServer := httptest.NewServer(mux)
			b.Cleanup(httpServer.Close)
			client := connect.NewClient(connecthttp.NewTransport(httpServer.Client(), httpServer.URL))
			rrClient := registeredresourcesconnectv2.NewRegisteredResourcesServiceClient(client)
			oblClient := obligationsconnectv2.NewServiceClient(client)

			for _, useFQN := range []bool{false, true} {
				identifier := "UUID"
				if useFQN {
					identifier = "FQN"
				}
				b.Run("RegisteredResource/"+identifier, func(b *testing.B) {
					aav := &registeredresources.ActionAttributeValue{
						ActionIdentifier:         &registeredresources.ActionAttributeValue_ActionId{ActionId: action.GetId()},
						AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueId{AttributeValueId: valueID},
					}
					if useFQN {
						aav.AttributeValueIdentifier = &registeredresources.ActionAttributeValue_AttributeValueFqn{AttributeValueFqn: valueFQN}
					}
					benchmarkPolicyWriteRequests(b, func(i int) (string, error) {
						response, err := rrClient.CreateRegisteredResourceValue(ctx, &registeredresources.CreateRegisteredResourceValueRequest{
							ResourceId: resource.GetId(), Value: fmt.Sprintf("value-%d", i), ActionAttributeValues: []*registeredresources.ActionAttributeValue{aav},
						})
						return response.GetValue().GetId(), err
					}, func(id string) {
						_, err := d.Client.Pgx.Exec(ctx, "DELETE FROM "+d.TableName("registered_resource_values")+" WHERE id = $1", id)
						require.NoError(b, err)
					})
				})
				b.Run("ObligationTrigger/"+identifier, func(b *testing.B) {
					av := &common.IdFqnIdentifier{Id: valueID}
					if useFQN {
						av = &common.IdFqnIdentifier{Fqn: valueFQN}
					}
					benchmarkPolicyWriteRequests(b, func(_ int) (string, error) {
						response, err := oblClient.AddObligationTrigger(ctx, &obligations.AddObligationTriggerRequest{
							ObligationValue: &common.IdFqnIdentifier{Id: oblValue.GetId()}, AttributeValue: av, Action: &common.IdNameIdentifier{Id: action.GetId()},
						})
						return response.GetTrigger().GetId(), err
					}, func(id string) {
						_, err := d.Client.Pgx.Exec(ctx, "DELETE FROM "+d.TableName("obligation_triggers")+" WHERE id = $1", id)
						require.NoError(b, err)
					})
				})
			}
		})
	}
}

func benchmarkPolicyWriteRequests(b *testing.B, request func(int) (string, error), cleanup func(string)) {
	b.Helper()
	for i := range 5 {
		id, err := request(i)
		require.NoError(b, err)
		require.NotEmpty(b, id)
		cleanup(id)
	}
	durations := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for i := range b.N {
		start := time.Now()
		id, err := request(i)
		durations = append(durations, time.Since(start))
		b.StopTimer()
		require.NoError(b, err)
		require.NotEmpty(b, id)
		cleanup(id)
		b.StartTimer()
	}
	b.StopTimer()
	slices.Sort(durations)
	b.ReportMetric(float64(durations[len(durations)/2].Nanoseconds()), "p50-ns")
	b.ReportMetric(float64(durations[(len(durations)-1)*95/100].Nanoseconds()), "p95-ns")
}
