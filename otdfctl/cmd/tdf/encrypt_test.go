package tdf

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectMimeTypePreservesPayload(t *testing.T) {
	payload := []byte("hello streaming world")
	mimeType, reader, err := detectMimeType(bytes.NewReader(payload), "txt")
	require.NoError(t, err)
	assert.Equal(t, "text/plain; charset=utf-8", mimeType)

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestDetectMimeTypePreservesPayloadLargerThanWindow(t *testing.T) {
	payload := strings.Repeat("a", Size1MB+17)
	_, reader, err := detectMimeType(strings.NewReader(payload), "")
	require.NoError(t, err)

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, payload, string(got))
}

func TestDetectMimeTypeFallsBackToKnownExtension(t *testing.T) {
	mimeType, reader, err := detectMimeType(bytes.NewReader([]byte{0, 1, 2, 3}), "pdf")
	require.NoError(t, err)
	assert.Equal(t, "application/pdf", mimeType)

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, []byte{0, 1, 2, 3}, got)
}
