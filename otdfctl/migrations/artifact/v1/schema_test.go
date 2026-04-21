package v1

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	artifactmetadata "github.com/opentdf/platform/otdfctl/migrations/artifact/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInitializesCanonicalShape(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	doc, err := New(&buf)
	require.NoError(t, err)

	require.NotNil(t, doc)
	assert.Equal(t, SchemaVersion, doc.MetadataData.SchemaValue)
	assert.Equal(t, artifactmetadata.ArtifactName, doc.MetadataData.Name())
	assert.NotEmpty(t, doc.MetadataData.RunID())
	assert.WithinDuration(t, time.Now().UTC(), doc.MetadataData.CreatedAt(), time.Minute)
	assert.Empty(t, doc.Actions)
	assert.Empty(t, doc.Skipped)

	summaryBytes, err := doc.Summary()
	require.NoError(t, err)

	var summary Summary
	require.NoError(t, json.Unmarshal(summaryBytes, &summary))
	assert.Equal(t, 0, summary.Counts.Actions)
	assert.Equal(t, 0, summary.Counts.Skipped)
}

func TestSummaryReturnsEncodedJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	doc, err := New(&buf)
	require.NoError(t, err)
	doc.Actions = append(doc.Actions, actionRecord{})
	doc.Skipped = append(doc.Skipped, skippedEntry{})

	summaryBytes, err := doc.Summary()
	require.NoError(t, err)

	var summary Summary
	require.NoError(t, json.Unmarshal(summaryBytes, &summary))
	assert.Equal(t, SummaryCounts{
		Namespaces:           0,
		Actions:              1,
		SubjectConditionSets: 0,
		SubjectMappings:      0,
		RegisteredResources:  0,
		ObligationTriggers:   0,
		Skipped:              1,
	}, summary.Counts)
}

func TestWriteProducesJSONDocument(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	doc, err := New(&buf)
	require.NoError(t, err)
	doc.Actions = append(doc.Actions, actionRecord{
		Source: actionSource{
			ID:         "action-export-legacy",
			Name:       "export",
			IsStandard: false,
		},
		Targets: []actionTarget{
			{
				NamespaceID:  "ns-finance-001",
				NamespaceFQN: "https://finance.example.com",
				ID:           "action-export-finance",
			},
		},
	})
	doc.Skipped = append(doc.Skipped, skippedEntry{
		Type:              "registered_resource_value_action_attribute_value",
		SkippedReasonCode: "ambiguous_target_action",
		SkippedReason:     "Could not determine a safe target action for this RAAV.",
	})

	require.NoError(t, doc.Write())

	var decoded artifact
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))

	assert.Equal(t, SchemaVersion, decoded.MetadataData.SchemaValue)
	assert.Equal(t, artifactmetadata.ArtifactName, decoded.MetadataData.Name())
	assert.NotEmpty(t, decoded.MetadataData.RunID())
	assert.NotEmpty(t, decoded.MetadataData.CreatedAt())
	assert.Equal(t, 1, decoded.SummaryData.Counts.Actions)
	assert.Equal(t, 1, decoded.SummaryData.Counts.Skipped)
}

func TestNewFailsWithoutWriter(t *testing.T) {
	t.Parallel()

	_, err := New(nil)
	require.ErrorIs(t, err, ErrNilWriter)
}
