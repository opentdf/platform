// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type TDFReader struct {
	archiveReader    Reader
	manifestMaxSize  int64
	manifestFileName string
	payloadFileName  string
}

const (
	manifestMaxSize = 1024 * 1024 * 10 // 10 MB
)

var (
	errManifestNotFound = errors.New("zip: neither manifest.json nor 0.manifest.json found in archive")
	errUnsafePayloadURL = errors.New("manifest payload.url is unsafe")
)

type TDFReaderOptions func(*TDFReader)

func WithTDFManifestMaxSize(size int64) TDFReaderOptions {
	return func(tdfReader *TDFReader) {
		tdfReader.manifestMaxSize = size
	}
}

// NewTDFReader Create tdf reader instance. It locates the manifest member
// (manifest.json, else 0.manifest.json) and the payload member named by
// manifest.payload.url (else 0.payload).
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

	if err := tdfArchiveReader.resolveEntryNames(); err != nil {
		return TDFReader{}, err
	}
	return tdfArchiveReader, nil
}

func (tdfReader *TDFReader) resolveEntryNames() error {
	for _, candidate := range []string{TDFManifestFileName, LegacyTDFManifestFileName} {
		if _, ok := tdfReader.archiveReader.fileEntries[candidate]; ok {
			tdfReader.manifestFileName = candidate
			break
		}
	}
	if tdfReader.manifestFileName == "" {
		return errManifestNotFound
	}

	manifestBytes, err := tdfReader.archiveReader.ReadAllFileData(tdfReader.manifestFileName, tdfReader.manifestMaxSize)
	if err != nil {
		return err
	}
	var probe struct {
		Payload struct {
			URL string `json:"url"`
		} `json:"payload"`
	}
	// A manifest that is not JSON is reported later by the schema/unmarshal
	// step; here we only need payload.url, so ignore decode errors.
	_ = json.Unmarshal(manifestBytes, &probe)

	name := probe.Payload.URL
	if name == "" {
		name = TDFPayloadFileName
	} else if !isSafeEntryName(name) {
		return fmt.Errorf("%w: %q", errUnsafePayloadURL, name)
	}
	if _, ok := tdfReader.archiveReader.fileEntries[name]; !ok {
		return fmt.Errorf("%w: payload entry %q named by manifest payload.url", errZipFileNotFound, name)
	}
	tdfReader.payloadFileName = name
	return nil
}

func isSafeEntryName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) {
		return false
	}
	for _, r := range name {
		// Reject control characters (including JSON escapes like \b, \n that
		// decode to raw control bytes): they have no legitimate place in a
		// zip member name and are a common injection vector.
		if r < 0x20 {
			return false
		}
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// ManifestFileName returns the zip member the manifest was read from.
func (tdfReader TDFReader) ManifestFileName() string { return tdfReader.manifestFileName }

// PayloadFileName returns the zip member the payload is read from.
func (tdfReader TDFReader) PayloadFileName() string { return tdfReader.payloadFileName }

// Manifest Return the manifest of the tdf.
func (tdfReader TDFReader) Manifest() (string, error) {
	fileContent, err := tdfReader.archiveReader.ReadAllFileData(tdfReader.manifestFileName, tdfReader.manifestMaxSize)
	if err != nil {
		return "", err
	}
	return string(fileContent), nil
}

// ReadPayload Return the payload of given length from index.
func (tdfReader TDFReader) ReadPayload(index, length int64) ([]byte, error) {
	return tdfReader.archiveReader.ReadFileData(tdfReader.payloadFileName, index, length)
}

// PayloadSize Return the size of the payload.
func (tdfReader TDFReader) PayloadSize() (int64, error) {
	size, err := tdfReader.archiveReader.ReadFileSize(tdfReader.payloadFileName)
	if err != nil {
		return -1, err
	}
	return size, nil
}
