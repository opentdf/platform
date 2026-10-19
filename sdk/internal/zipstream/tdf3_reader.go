// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"errors"
	"fmt"
	"io"
	"math"
)

// ErrPrefixedManifestName reports an archive whose manifest is filed under the
// legacy 0.manifest.json entry name, read by a caller that asked to reject
// such archives. It is distinct from a missing manifest: the manifest is there,
// it is just not where the spec says to put it.
var ErrPrefixedManifestName = errors.New("tdf: manifest entry is named " +
	TDFManifestFileName + ", not " + TDFManifestFileNameSpec)

type TDFReader struct {
	archiveReader Reader
	// manifestMaxSize caps the manifest entry in bytes. Zero, the default,
	// means no cap: the archive bounds checks in NewReader already keep a
	// declared size within the physical archive, and very large payloads
	// legitimately carry manifests well beyond any fixed limit.
	manifestMaxSize int64
	// requireUnprefixedManifestName suppresses the legacy 0.manifest.json
	// fallback in Manifest.
	requireUnprefixedManifestName bool
}

type TDFReaderOptions func(*TDFReader)

// WithTDFManifestMaxSize caps the manifest size in bytes. A size of zero or
// less means no cap.
func WithTDFManifestMaxSize(size int64) TDFReaderOptions {
	return func(tdfReader *TDFReader) {
		tdfReader.manifestMaxSize = size
	}
}

// WithRequireUnprefixedManifestName rejects an archive whose manifest is filed
// under the legacy 0.manifest.json entry name rather than reading it. Off by
// default: the reader accepts both names so archives written by earlier
// releases keep working.
func WithRequireUnprefixedManifestName() TDFReaderOptions {
	return func(tdfReader *TDFReader) {
		tdfReader.requireUnprefixedManifestName = true
	}
}

// NewTDFReader Create tdf reader instance.
func NewTDFReader(readSeeker io.ReadSeeker, opt ...TDFReaderOptions) (TDFReader, error) {
	archiveReader, err := NewReader(readSeeker)
	if err != nil {
		return TDFReader{}, err
	}

	tdfArchiveReader := TDFReader{}
	tdfArchiveReader.archiveReader = archiveReader
	for _, o := range opt {
		o(&tdfArchiveReader)
	}

	return tdfArchiveReader, nil
}

// Manifest Return the manifest of the tdf.
//
// The spec name wins over the name this SDK writes when an archive carries
// both. Only a missing entry triggers the fallback: a manifest that is present
// but too large is a size failure, and retrying under the other name would
// both report the wrong reason and, in an archive holding both, hand back the
// superseded manifest.
//
// WithRequireUnprefixedManifestName drops the fallback. The legacy prefixed
// entry is still looked up in that mode, so an archive that has one is told
// apart from an archive that has no manifest at all.
func (tdfReader TDFReader) Manifest() (string, error) {
	maxSize := tdfReader.manifestMaxSize
	if maxSize <= 0 {
		maxSize = math.MaxInt64
	}
	fileContent, err := tdfReader.archiveReader.ReadAllFileData(TDFManifestFileNameSpec, maxSize)
	if errors.Is(err, errZipFileNotFound) {
		fileContent, err = tdfReader.archiveReader.ReadAllFileData(TDFManifestFileName, maxSize)
		switch {
		case errors.Is(err, errZipFileNotFound):
			return "", fmt.Errorf("no %s or %s entry: %w", TDFManifestFileNameSpec, TDFManifestFileName, err)
		case err == nil && tdfReader.requireUnprefixedManifestName:
			return "", ErrPrefixedManifestName
		}
	}
	if err != nil {
		return "", err
	}
	return string(fileContent), nil
}

// ReadPayload Return the payload of given length from index.
func (tdfReader TDFReader) ReadPayload(index, length int64) ([]byte, error) {
	return tdfReader.archiveReader.ReadFileData(TDFPayloadFileName, index, length)
}

// PayloadSize Return the size of the payload.
func (tdfReader TDFReader) PayloadSize() (int64, error) {
	size, err := tdfReader.archiveReader.ReadFileSize(TDFPayloadFileName)
	if err != nil {
		return -1, err
	}
	return size, nil
}
