package kasregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/require"
)

func TestGetKeyAuditUsesDatabaseIDAndKeyContext(t *testing.T) {
	const kasURI = "https://kas.example.com"
	key := &policy.KasKey{
		KasUri: kasURI,
		Key: &policy.AsymmetricKey{
			Id:            validUUID,
			KeyId:         validKeyID,
			PrivateKeyCtx: validPrivCtx,
		},
	}
	requests := map[string]*kasregistry.GetKeyRequest{
		"database ID": {Identifier: &kasregistry.GetKeyRequest_Id{Id: validUUID}},
		"KID and URI": {Identifier: &kasregistry.GetKeyRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Kid:        validKeyID,
				Identifier: &kasregistry.KasKeyIdentifier_Uri{Uri: kasURI},
			},
		}},
	}
	for name, req := range requests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			slogLogger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: audit.LevelAudit}))
			svc := KeyAccessServerRegistry{logger: &logger.Logger{
				Logger: slogLogger,
				Audit:  audit.CreateAuditLogger(*slogLogger),
			}}
			resolverCtx := authz.NewResolverContext()
			resolverCtx.SetResolvedData(resolverCacheKeyKasKey, key)
			ctx := authz.ContextWithResolverContext(t.Context(), &resolverCtx)
			handler := audit.ContextServerInterceptor(svc.logger.Audit)(
				func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
					resp, err := svc.GetKey(ctx, connect.NewRequest(req))
					if err != nil {
						return nil, err
					}
					require.Same(t, key, resp.Msg.GetKasKey())
					return resp, nil
				},
			)
			_, err := handler(ctx, connect.NewRequest(req))
			require.NoError(t, err)

			var entry struct {
				Audit struct {
					Object struct {
						ID string `json:"id"`
					} `json:"object"`
					Original map[string]any `json:"original"`
				} `json:"audit"`
			}
			require.NoError(t, json.Unmarshal(output.Bytes(), &entry))
			require.Equal(t, validUUID, entry.Audit.Object.ID)
			require.Equal(t, map[string]any{
				"kasUri": kasURI,
				"key":    map[string]any{"keyId": validKeyID},
			}, entry.Audit.Original)
		})
	}
}
