package access

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	"github.com/opentdf/platform/protocol/go/policy"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJITPDP_AuditFailurePreservesDecision(t *testing.T) {
	for _, tc := range []struct {
		name      string
		clientID  string
		permitted bool
	}{
		{name: "permit", clientID: "abc", permitted: true},
		{name: "deny", clientID: "other", permitted: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []audit.Event
			log, err := logger.NewLogger(logger.Config{
				Level: "info", Output: "stdout", Type: "json",
				AuditProcessor: audit.ProcessorFunc(func(ctx context.Context, event audit.Event) error {
					require.NoError(t, ctx.Err())
					events = append(events, event)
					return errors.New("audit destination unavailable")
				}),
			})
			require.NoError(t, err)
			var diagnostics bytes.Buffer
			log.Logger = slog.New(slog.NewJSONHandler(&diagnostics, nil))
			definitionFQN := "https://example.com/attr/classification"
			valueFQN := definitionFQN + "/value/confidential"
			p := &JustInTimePDP{
				logger: log,
				sdk: &otdfSDK.SDK{
					Attributes: decisionAttrFake(definitionFQN, valueFQN, "abc"),
					EntityResolutionV2: &recordingERSV2Client{resolveResponse: &entityresolutionV2.ResolveEntitiesResponse{
						EntityRepresentations: []*entityresolutionV2.EntityRepresentation{entityRepWithClientID(tc.clientID)},
					}},
				},
				obligationsPDP:                newTestObligationsPDP(t),
				registeredResourceValuesByFQN: make(map[string]*policy.RegisteredResourceValue),
			}
			ctx := audit.ContextWithActorID(t.Context(), "test-actor")
			decision, err := p.GetDecision(ctx, entityChainIdentifier(), &policy.Action{Name: "read"}, attrValueResource(valueFQN), nil, nil)
			require.NoError(t, err)
			require.NotNil(t, decision)
			assert.Equal(t, tc.permitted, decision.AllPermitted)
			require.Len(t, events, 1)
			assert.Contains(t, diagnostics.String(), "failed to record authorization audit event")
			assert.Contains(t, diagnostics.String(), "audit destination unavailable")
		})
	}
}
