// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMergeEncryptedMetadata_NoBase(t *testing.T) {
	resourceMetadata := map[string]any{
		"file_name": "report.txt",
		"byte_size": int64(123),
		"source":    "unit-test",
	}

	merged, err := mergeEncryptedMetadata("", resourceMetadata)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(merged), &decoded))

	resource, ok := decoded["resourceMetadata"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "report.txt", resource["file_name"])
	require.EqualValues(t, 123, resource["byte_size"])
	require.Equal(t, "unit-test", resource["source"])
}

func TestMergeEncryptedMetadata_JSONBase(t *testing.T) {
	base := `{"classification":"secret","resourceMetadata":{"file_name":"old.txt"}}`
	resourceMetadata := map[string]any{
		"file_name": "report.txt",
		"byte_size": int64(123),
	}

	merged, err := mergeEncryptedMetadata(base, resourceMetadata)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(merged), &decoded))

	require.Equal(t, "secret", decoded["classification"])
	resource, ok := decoded["resourceMetadata"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "report.txt", resource["file_name"])
	require.EqualValues(t, 123, resource["byte_size"])
}

func TestMergeEncryptedMetadata_NonJSONBase(t *testing.T) {
	resourceMetadata := map[string]any{
		"byte_size": int64(5),
	}

	merged, err := mergeEncryptedMetadata("custom metadata", resourceMetadata)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(merged), &decoded))

	require.Equal(t, "custom metadata", decoded["metadata"])
	_, ok := decoded["resourceMetadata"]
	require.True(t, ok)
}
