package audit_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/require"
)

func TestExternalServiceCanConstructCanonicalEvent(t *testing.T) {
	var processedObjectType string
	var _ audit.Recorder = audit.CreateAuditLogger(
		*slog.Default(),
		audit.WithProcessor(audit.ProcessorFunc(func(_ context.Context, event audit.Event) error {
			processedObjectType = event.Object.Type.String()
			return nil
		})),
	)

	event := audit.NewEvent(audit.EventObjectParams{
		Object: audit.EventObjectInfo{Type: audit.ObjectTypeRegisteredResource, ID: "document-1", Attributes: audit.EventObjectAttributes{Attrs: []string{"classification"}}},
		Action: audit.EventObjectAction{Type: audit.ActionTypeRead, Result: audit.ActionResultSuccess},
		Actor:  audit.EventObjectActor{ID: "subject-1", Attributes: []any{"attribute"}},
		EventMetaData: audit.EventMetaData{
			"authoritative_namespace": "https://example.com/attr/organization/value/org-1",
		},
		ClientInfo: audit.EventClientInfo{Platform: "extension"},
	})
	event.Verb = audit.Verb("share")
	event.Phase = audit.PhaseCompleted

	require.NoError(t, audit.CreateAuditLogger(
		*slog.Default(),
		audit.WithProcessor(audit.ProcessorFunc(func(_ context.Context, event audit.Event) error {
			processedObjectType = event.Object.Type.String()
			return nil
		})),
	).Record(t.Context(), *event))
	require.Equal(t, "registered_resource", processedObjectType)
}
