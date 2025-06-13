// Package stream provides indeterministic, out-of-order chunked encryption for TDF files.
package sdk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/internal/archive"
)

// TDFStreamWriter enables indeterministic streaming encryption for TDF.
type TDFStreamWriter struct {
	writer      io.Writer
	tdfWriter   *archive.TDFWriter
	manifest    Manifest
	segmentSize int64
	segments    []Segment
	payloadKey  [kKeySize]byte
	aesGcm      ocrypto.AesGcm
	buf         *bytes.Buffer
	totalSize   int64
	closed      bool
}

// NewTDFStreamWriter creates a new streaming TDF writer.
func NewTDFStreamWriter(writer io.Writer, manifest Manifest, payloadKey [kKeySize]byte, segmentSize int64) (*TDFStreamWriter, error) {
	aesGcm, err := ocrypto.NewAESGcm(payloadKey[:])
	if err != nil {
		return nil, err
	}
	tsw := &TDFStreamWriter{
		writer:      writer,
		tdfWriter:   archive.NewTDFWriter(writer),
		manifest:    manifest,
		segmentSize: segmentSize,
		segments:    []Segment{},
		payloadKey:  payloadKey,
		aesGcm:      aesGcm,
		buf:         bytes.NewBuffer(nil),
	}
	return tsw, nil
}

// WriteChunk encrypts and writes a chunk to the TDF payload.
func (tsw *TDFStreamWriter) WriteChunk(chunk []byte) error {
	if tsw.closed {
		return fmt.Errorf("TDFStreamWriter is closed")
	}
	cipherData, err := tsw.aesGcm.Encrypt(chunk)
	if err != nil {
		return err
	}
	err = tsw.tdfWriter.AppendPayload(cipherData)
	if err != nil {
		return err
	}
	segmentSig, err := calculateSignature(cipherData, tsw.payloadKey[:], HS256, false)
	if err != nil {
		return err
	}
	ts := Segment{
		Hash:          string(ocrypto.Base64Encode([]byte(segmentSig))),
		Size:          int64(len(chunk)),
		EncryptedSize: int64(len(cipherData)),
	}
	tsw.segments = append(tsw.segments, ts)
	tsw.totalSize += int64(len(chunk))
	return nil
}

// Close finalizes the TDF, writes the manifest, and closes the archive.
func (tsw *TDFStreamWriter) Close() error {
	if tsw.closed {
		return nil
	}
	// Update manifest with segments
	tsw.manifest.EncryptionInformation.IntegrityInformation.Segments = tsw.segments
	manifestBytes, err := json.Marshal(tsw.manifest)
	if err != nil {
		return err
	}
	err = tsw.tdfWriter.AppendManifest(string(manifestBytes))
	if err != nil {
		return err
	}
	_, err = tsw.tdfWriter.Finish()
	tsw.closed = true
	return err
}
