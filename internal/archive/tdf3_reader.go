package archive

import (
	"io"
)

type TDFReader struct {
	archiveReader Reader
}

const (
	TDFManifestFileName = "0.manifest.json"
	TDFPayloadFileName  = "0.payload"
)

// NewTDFReader Create tdf reader instance.
func NewTDFReader(readSeeker io.ReadSeeker) (TDFReader, error) {
	archiveReader, err := NewReader(readSeeker)
	if err != nil {
		return TDFReader{}, err
	}

	tdfArchiveReader := TDFReader{}
	tdfArchiveReader.archiveReader = archiveReader

	return tdfArchiveReader, nil
}

// Manifest Return the manifest of the tdf.
func (tdfReader TDFReader) Manifest() (string, error) {
	fileContent, err := tdfReader.archiveReader.ReadAllFileData(TDFManifestFileName)
	if err != nil {
		return "", err
	}
	return string(fileContent), nil
}

// ReadPayload Return the payload of given length from index.
func (tdfReader TDFReader) ReadPayload(index, length int64) ([]byte, error) {
	buf, err := tdfReader.archiveReader.ReadFileData(TDFPayloadFileName, index, length)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// PayloadSize Return the size of the payload.
func (tdfReader TDFReader) PayloadSize() (int64, error) {
	size, err := tdfReader.archiveReader.ReadFileSize(TDFPayloadFileName)
	if err != nil {
		return -1, err
	}
	return size, nil
}
