package audit_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/require"
)

func TestExternalRecorderAPI(t *testing.T) {
	ctx := audit.ContextWithActorID(t.Context(), "actor-1")
	logger := audit.CreateAuditLogger(*slog.New(slog.DiscardHandler))

	event := audit.RecordedEvent{
		Object: audit.RecordedObject{Type: "external_resource", ID: "resource-1"},
		Action: audit.RecordedAction{Type: "read", Result: "success"},
		Actor:  audit.RecordedActor{ID: "actor-1"},
		ClientInfo: audit.RecordedClientInfo{
			Platform: "external-service",
		},
	}

	var recorder audit.Recorder = logger
	require.NoError(t, recorder.Record(context.WithoutCancel(ctx), audit.Verb("external read"), event))
}
