package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTraceLog(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "traces.log"), []byte(body), 0o600))
	return dir
}

func TestRunTracesAcceptsPrettyPrintedStream(t *testing.T) {
	dir := writeTraceLog(t, `
{
  "Name": "kas.AccessService/Rewrap",
  "StartTime": "2026-10-05T12:00:00Z",
  "EndTime": "2026-10-05T12:00:00.010Z"
}
{
  "Name": "kas.AccessService/Rewrap",
  "StartTime": "2026-10-05T12:00:01Z",
  "EndTime": "2026-10-05T12:00:01.030Z"
}
`)

	require.NoError(t, runTraces([]string{"--folder", dir}))
}

func TestRunTracesRejectsMalformedRecord(t *testing.T) {
	dir := writeTraceLog(t, `{"Name":`)

	err := runTraces([]string{"--folder", dir})
	require.Error(t, err)
	assert.ErrorContains(t, err, "decode trace record")
}

func TestRunTracesRejectsEmptyLog(t *testing.T) {
	dir := writeTraceLog(t, "")

	err := runTraces([]string{"--folder", dir})
	require.Error(t, err)
	assert.ErrorContains(t, err, "no records")
}

func TestGFMCellEscape(t *testing.T) {
	assert.Equal(t, `one\|two<br>three`, gfmCellEscape("one|two\nthree"))
}
