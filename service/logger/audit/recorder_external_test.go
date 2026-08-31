package audit_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/service/logger/audit"
	"github.com/stretchr/testify/require"
)

func TestExternalServiceCanConstructCanonicalEvent(t *testing.T) {
	var _ audit.Recorder = audit.CreateAuditLogger(
		*slog.Default(),
		audit.WithProcessor(audit.ProcessorFunc(func(context.Context, audit.Event) error { return nil })),
	)

	event := audit.Event{
		Verb:   audit.Verb("share"),
		Phase:  audit.PhaseCompleted,
		Object: audit.Object{Type: "document", ID: "document-1", Attributes: audit.ObjectAttributes{Attrs: []string{"classification"}}},
		Action: audit.Action{Type: "share", Result: "success"},
		Actor:  audit.Actor{ID: "subject-1", Attributes: []any{"attribute"}},
		EventMetaData: audit.EventMetadata{
			"authoritative_namespace": "https://example.com/attr/organization/value/org-1",
		},
		ClientInfo: audit.ClientInfo{Platform: "extension"},
	}

	require.NoError(t, audit.CreateAuditLogger(
		*slog.Default(),
		audit.WithProcessor(audit.ProcessorFunc(func(context.Context, audit.Event) error { return nil })),
	).Record(t.Context(), event))
}
