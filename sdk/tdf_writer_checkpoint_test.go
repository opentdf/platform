package sdk

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResumableTDFWriterRestoresAndDecrypts(t *testing.T) {
	kas := newChunkedFakeKAS(t)
	t.Cleanup(kas.server.Close)
	client := newChunkedTestSDK(t)
	writer, err := client.NewResumableTDFWriter(t.Context(), WithAutoconfigure(false), WithKasInformation(KASInfo{URL: kas.url, PublicKey: kas.publicPEM, KID: kas.kid}), WithSegmentSize(16*1024), WithMimeType("text/plain"))
	require.NoError(t, err)
	first := bytes.Repeat([]byte("a"), 16*1024)
	last := []byte("remaining plaintext")
	segment, err := writer.WriteSegment(t.Context(), 0, first)
	require.NoError(t, err)
	prefix, err := io.ReadAll(segment.TDFData)
	require.NoError(t, err)
	snapshot, err := writer.Snapshot()
	require.NoError(t, err)
	var before tdfWriterState
	require.NoError(t, json.Unmarshal(snapshot, &before))
	writer = nil   //nolint:wastedassign // Discard the old writer before reconstruction.
	client = SDK{} //nolint:wastedassign // Restore does not require the original client.
	restored, err := RestoreResumableTDFWriter(bytes.Clone(snapshot))
	require.NoError(t, err)
	require.Equal(t, before.DEK, restored.writer.dek)
	require.Equal(t, before.Encryptions, restored.writer.encryptions)
	segment, err = restored.WriteSegment(t.Context(), 1, last)
	require.NoError(t, err)
	suffix, err := io.ReadAll(segment.TDFData)
	require.NoError(t, err)
	fin, err := restored.Finalize(t.Context())
	require.NoError(t, err)
	payload := append(append(prefix, suffix...), fin.Data...)
	reader, err := newChunkedTestSDK(t).LoadTDF(bytes.NewReader(payload), WithKasAllowlist([]string{kas.url}))
	require.NoError(t, err)
	plaintext, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, append(first, last...), plaintext)
	require.Equal(t, "text/plain", reader.Manifest().MimeType)
}

func TestResumableTDFWriterRejectsInvalidSnapshots(t *testing.T) {
	_, err := RestoreResumableTDFWriter([]byte(`{"Version":2}`))
	require.Error(t, err)
	_, err = RestoreResumableTDFWriter([]byte(`not json`))
	require.Error(t, err)
}
