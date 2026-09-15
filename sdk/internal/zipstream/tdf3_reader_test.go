// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"bytes"
	"hash/crc32"
	"testing"

	"github.com/stretchr/testify/require"
)

// The OpenTDF spec names the manifest entry manifest.json; SDK versions
// before the spec alignment wrote 0.manifest.json. Readers accept either.
// See https://github.com/opentdf/platform/issues/3513.

// manifestJSON builds a manifest carrying the fields the TDF manifest schema
// requires, so the fixtures below are manifests rather than arbitrary JSON.
// This package treats the manifest as opaque bytes and never parses it, so the
// literal is spelled out here: importing the sdk package for its Manifest type
// would be an import cycle, since sdk imports this one.
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
}

// The writer emits the spec name. The payload entry name is unchanged: it is
// recorded in the manifest's payload URL field, so renaming it would alter
// manifest contents rather than just archive layout.
func TestSegmentWriter_WritesSpecManifestName(t *testing.T) {
	ctx := t.Context()
	payload := []byte("payload bytes")

	writer := NewSegmentTDFWriter(1)
	defer func() { require.NoError(t, writer.Close()) }()

	out := &bytes.Buffer{}
	header, err := writer.WriteSegment(ctx, 0, uint64(len(payload)), crc32.ChecksumIEEE(payload))
	require.NoError(t, err)
	out.Write(header)
	out.Write(payload)

	final, err := writer.Finalize(ctx, []byte(testManifest))
	require.NoError(t, err)
	out.Write(final)

	archive, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	require.NoError(t, err)

	names := make([]string, 0, len(archive.File))
	for _, entry := range archive.File {
		names = append(names, entry.Name)
	}

	require.ElementsMatch(t, []string{TDFPayloadFileName, "manifest.json"}, names)
	require.NotContains(t, names, "0.manifest.json")
}

// WithRequireSpecManifestName turns the off-spec name off entirely, for
// callers that want to reject archives the spec does not describe rather than
// read them. See https://github.com/opentdf/platform/issues/3513.
func TestManifest_RequireSpecName_RejectsOffspecName(t *testing.T) {
	data := buildRawZip(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: "0.manifest.json", data: []byte(testManifest)},
	}, false)

	reader, err := NewTDFReader(bytes.NewReader(data), WithRequireSpecManifestName())
	require.NoError(t, err)

	manifest, err := reader.Manifest()
	require.ErrorIs(t, err, ErrOffspecManifestName)
	require.Empty(t, manifest)
}

func TestManifest_RequireSpecName_ReadsSpecName(t *testing.T) {
	data := buildRawZip(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
		{name: "manifest.json", data: []byte(testManifest)},
	}, false)

	reader, err := NewTDFReader(bytes.NewReader(data), WithRequireSpecManifestName())
	require.NoError(t, err)

	manifest, err := reader.Manifest()
	require.NoError(t, err)
	require.JSONEq(t, testManifest, manifest)
}

// An archive with no manifest at all reports a missing entry, not an off-spec
// name: the two are different problems and a caller may want to tell them
// apart.
func TestManifest_RequireSpecName_MissingEntirely(t *testing.T) {
	data := buildRawZip(t, []rawZipEntry{
		{name: TDFPayloadFileName, data: []byte("payload bytes")},
	}, false)

	reader, err := NewTDFReader(bytes.NewReader(data), WithRequireSpecManifestName())
	require.NoError(t, err)

	_, err = reader.Manifest()
	require.ErrorIs(t, err, errZipFileNotFound)
	require.NotErrorIs(t, err, ErrOffspecManifestName)
}

// An oversized manifest under the spec name is a size failure, not a missing
// entry. A reader that fell back on any error would quietly hand back the
// superseded off-spec manifest here, so the size limit is set between the two
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
