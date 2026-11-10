// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"io"
)

type TDFReader struct {
	archiveReader   Reader
	manifestMaxSize int64
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
func (tdfReader TDFReader) Manifest() (string, error) {
	fileContent, err := tdfReader.archiveReader.ReadAllFileData(TDFManifestFileName, tdfReader.manifestMaxSize)
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
