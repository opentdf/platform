// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"errors"
	"fmt"
	"io"
)

// ErrOffspecManifestName reports an archive whose manifest is filed under the
// off-spec name, read by a caller that asked for spec names only. It is
// distinct from a missing manifest: the manifest is there, it is just not
// where the spec says to put it.
var ErrOffspecManifestName = errors.New("tdf: manifest entry is named " +
	TDFManifestFileNameOffspec + ", not " + TDFManifestFileName)

type TDFReader struct {
	archiveReader   Reader
	manifestMaxSize int64
	// requireSpecManifestName suppresses the off-spec fallback in Manifest.
	requireSpecManifestName bool
}

const (
	manifestMaxSize = 1024 * 1024 * 10 // 10 MB
)

type TDFReaderOptions func(*TDFReader)

func WithTDFManifestMaxSize(size int64) TDFReaderOptions {
	return func(tdfReader *TDFReader) {
		tdfReader.manifestMaxSize = size
	}
}

// WithRequireSpecManifestName rejects an archive whose manifest is filed under
// the off-spec name rather than reading it. Off by default: the reader accepts
// both names so archives written by earlier releases keep working.
func WithRequireSpecManifestName() TDFReaderOptions {
	return func(tdfReader *TDFReader) {
		tdfReader.requireSpecManifestName = true
	}
}

// NewTDFReader Create tdf reader instance.
func NewTDFReader(readSeeker io.ReadSeeker, opt ...TDFReaderOptions) (TDFReader, error) {
	archiveReader, err := NewReader(readSeeker)
	if err != nil {
		return TDFReader{}, err
	}

	tdfArchiveReader := TDFReader{manifestMaxSize: manifestMaxSize}
	tdfArchiveReader.archiveReader = archiveReader
	for _, o := range opt {
		o(&tdfArchiveReader)
	}

	return tdfArchiveReader, nil
}

// Manifest Return the manifest of the tdf.
//
// The spec name wins over the off-spec one when an archive carries both. Only a
// missing entry triggers the fallback: a manifest that is present but too
// large is a size failure, and retrying under the other name would both report
// the wrong reason and, in an archive holding both, hand back the superseded
// manifest.
//
// WithRequireSpecManifestName drops the fallback. The off-spec entry is still
// looked up in that mode, so an archive that has one is told apart from an
// archive that has no manifest at all.
func (tdfReader TDFReader) Manifest() (string, error) {
	fileContent, err := tdfReader.archiveReader.ReadAllFileData(TDFManifestFileName, tdfReader.manifestMaxSize)
	if errors.Is(err, errZipFileNotFound) {
		fileContent, err = tdfReader.archiveReader.ReadAllFileData(TDFManifestFileNameOffspec, tdfReader.manifestMaxSize)
		switch {
		case errors.Is(err, errZipFileNotFound):
			return "", fmt.Errorf("no %s or %s entry: %w", TDFManifestFileName, TDFManifestFileNameOffspec, err)
		case err == nil && tdfReader.requireSpecManifestName:
			return "", ErrOffspecManifestName
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
