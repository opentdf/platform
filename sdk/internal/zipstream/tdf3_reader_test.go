// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"bytes"
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The OpenTDF spec names the manifest entry manifest.json; this SDK writes
// 0.manifest.json. Readers accept either.
// See https://github.com/opentdf/platform/issues/3513.

// manifestJSON builds representative JSON with the top-level manifest fields.
// It is deliberately incomplete: these tests exercise ZIP entry selection,
// and this package treats the manifest as opaque bytes. A fully valid manifest
// would add fields unrelated to the behavior under test. The literal is spelled
// out here because importing the sdk Manifest type would create an import cycle.
func manifestJSON(mimeType string) string {
	return `{"payload":{"type":"reference","url":"` + TDFPayloadFileName +
		`","protocol":"zip","isEncrypted":true,"mimeType":"` + mimeType +
		`"},"encryptionInformation":{"type":"split"}}`
}

var (
	// testManifest is what nearly every fixture here stores. These tests
	// exercise the entry name, not manifest contents, so the same manifest
	// serves whichever name it is filed under.
	testManifest = manifestJSON("application/octet-stream")

	// otherManifest exists only for the two tests that must tell the entries
	// apart -- with identical content, neither could say which one the reader
	// returned. It is deliberately shorter than testManifest, which is what
	// lets the size-limit test admit one entry and not the other.
	otherManifest = manifestJSON("text/plain")
)

func manifestOf(t *testing.T, entries []rawZipEntry) (string, error) {
	t.Helper()

	reader, err := NewTDFReader(bytes.NewReader(buildRawZip(t, entries, false)))
	require.NoError(t, err)

	return reader.Manifest()
}

func TestManifest_ReadsSpecName(t *testing.T) {
	manifest, err := manifestOf(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: "manifest.json", data: []byte(testManifest)},
	})

	require.NoError(t, err)
	require.JSONEq(t, testManifest, manifest)
}

func TestManifest_ReadsOffspecName(t *testing.T) {
	manifest, err := manifestOf(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: "0.manifest.json", data: []byte(testManifest)},
	})

	require.NoError(t, err)
	require.JSONEq(t, testManifest, manifest)
}

// The entries hold different manifests, so the assertion cannot pass by
// reading whichever one the reader happened to pick.
func TestManifest_PrefersSpecNameOverOffspec(t *testing.T) {
	manifest, err := manifestOf(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: "0.manifest.json", data: []byte(otherManifest)},
		{name: "manifest.json", data: []byte(testManifest)},
	})

	require.NoError(t, err)
	require.JSONEq(t, testManifest, manifest)
}

func TestManifest_MissingUnderEitherName(t *testing.T) {
	_, err := manifestOf(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
	})

	require.ErrorIs(t, err, errZipFileNotFound)
	// The error has to name both candidates: a bare "file not found" gives no
	// hint that a second name was tried.
	require.ErrorContains(t, err, TDFManifestFileNameSpec)
	require.ErrorContains(t, err, TDFManifestFileName)
}

// An oversized manifest under the spec name is a size failure, not a missing
// entry. A reader that fell back on any error would quietly hand back the
// superseded non-aligned manifest here, so the size limit is set between the two
// entries: only the spec one exceeds it.
func TestManifest_OversizedSpecNameDoesNotFallBack(t *testing.T) {
	require.Greater(t, len(testManifest), len(otherManifest))

	data := buildRawZip(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: "0.manifest.json", data: []byte(otherManifest)},
		{name: "manifest.json", data: []byte(testManifest)},
	}, false)

	reader, err := NewTDFReader(bytes.NewReader(data), WithTDFManifestMaxSize(int64(len(otherManifest))))
	require.NoError(t, err)

	manifest, err := reader.Manifest()
	require.Error(t, err)
	require.NotErrorIs(t, err, errZipFileNotFound)
	require.Empty(t, manifest)
}

// TestManifest_NoDefaultSizeCap asserts a default reader returns a manifest
// past the former 10 MB default cap. Very large payloads carry manifests far
// bigger than that (DSPX-4502), so the default is no cap at all.
func TestManifest_NoDefaultSizeCap(t *testing.T) {
	big := `{"pad":"` + strings.Repeat("a", 11*1024*1024) + `"}`
	data := buildRawZip(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: TDFManifestFileName, data: []byte(big)},
	}, false)

	reader, err := NewTDFReader(bytes.NewReader(data))
	require.NoError(t, err)
	manifest, err := reader.Manifest()
	require.NoError(t, err)
	assert.Len(t, manifest, len(big))

	// A non-positive explicit limit also means no cap.
	reader, err = NewTDFReader(bytes.NewReader(data), WithTDFManifestMaxSize(0))
	require.NoError(t, err)
	_, err = reader.Manifest()
	require.NoError(t, err)
}

// TestManifest_ExplicitSizeCapEnforced asserts an opt-in cap still applies,
// with the boundary inclusive.
func TestManifest_ExplicitSizeCapEnforced(t *testing.T) {
	data := buildRawZip(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: TDFManifestFileName, data: []byte(otherManifest)},
	}, false)

	reader, err := NewTDFReader(bytes.NewReader(data), WithTDFManifestMaxSize(int64(len(otherManifest))))
	require.NoError(t, err)
	_, err = reader.Manifest()
	require.NoError(t, err)

	reader, err = NewTDFReader(bytes.NewReader(data), WithTDFManifestMaxSize(int64(len(otherManifest)-1)))
	require.NoError(t, err)
	_, err = reader.Manifest()
	require.ErrorContains(t, err, "size too large")
}

// TestManifest_DeclaredSizeBeyondArchiveRejectedWithoutCap asserts that with
// no size cap, a manifest entry declaring more bytes than the archive holds is
// still refused -- by the archive bounds, before any allocation.
func TestManifest_DeclaredSizeBeyondArchiveRejectedWithoutCap(t *testing.T) {
	for _, size := range []uint64{beyondEOF, beyondInt64, math.MaxUint64} {
		data := buildRawZip(t, []rawZipEntry{
			{name: TDFPayloadFileName, data: []byte("payload bytes")},
			{name: TDFManifestFileName, data: []byte(otherManifest), zip64: true, zip64CompressedSize: size},
		}, false)

		_, err := NewTDFReader(bytes.NewReader(data))
		require.ErrorIs(t, err, errZipFormat)
		require.ErrorContains(t, err, "file data at")
	}
}
