// Package stream provides indeterministic, out-of-order chunked encryption for TDF files.
package sdk

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/internal/archive"
)

/*
TDFChunkManager: Indeterministic, Out-of-Order Streaming API
-----------------------------------------------------------

The TDFChunkManager enables secure, out-of-order encryption and assembly of large files in chunks, without requiring the total file size or chunk order in advance. This is ideal for scenarios like distributed uploads, parallel processing, or unpredictable data streams.

Usage Example:

	// 1. Prepare manifest, payloadKey, and tempDir (see SDK for details)
	manifest := ... // Manifest struct
	payloadKey := ... // [kKeySize]byte
	tempDir := os.TempDir()
	chunkCount := N // total number of chunks expected
	segmentSize := int64(4 * 1024 * 1024) // e.g., 4MB
	finalFile, _ := os.Create("output.tdf")

	cm, err := NewTDFChunkManager(finalFile, manifest, payloadKey, segmentSize, chunkCount, tempDir)
	if err != nil {
		panic(err)
	}

	// 2. As chunks arrive (in any order):
	for idx, chunk := range incomingChunks {
		go func(i int, data []byte) {
			err := cm.WriteChunk(i, data)
			if err != nil {
				log.Printf("Chunk %d failed: %v", i, err)
			}
		}(idx, chunk)
	}

	// 3. Wait for all chunks to complete (application logic)
	// ...

	// 4. Finalize the TDF when all chunks are done
	if cm.AllChunksComplete() {
		err := cm.Finalize()
		if err != nil {
			panic(err)
		}
		fmt.Println("TDF file assembled successfully!")
	}

Notes:
- Chunks are encrypted and written to disk immediately; plaintext is not retained.
- Chunks can be written in any order and in parallel.
- The manifest and TDF are assembled only after all chunks are complete.
- Temporary files are used for chunk storage; clean up as needed.
*/

// TDFChunkManager enables indeterministic, out-of-order chunked encryption for TDF.
type TDFChunkManager struct {
	chunkCount  int
	chunkStatus map[int]bool    // chunk index -> complete
	chunkFiles  map[int]string  // chunk index -> temp file path
	segments    map[int]Segment // chunk index -> segment metadata
	manifest    Manifest
	payloadKey  [kKeySize]byte
	aesGcm      ocrypto.AesGcm
	tempDir     string
	finalWriter io.Writer
	segmentSize int64
	closed      bool
}

// NewTDFChunkManager initializes the chunk manager.
func NewTDFChunkManager(finalWriter io.Writer, manifest Manifest, payloadKey [kKeySize]byte, segmentSize int64, chunkCount int, tempDir string) (*TDFChunkManager, error) {
	aesGcm, err := ocrypto.NewAESGcm(payloadKey[:])
	if err != nil {
		return nil, err
	}
	return &TDFChunkManager{
		chunkCount:  chunkCount,
		chunkStatus: make(map[int]bool),
		chunkFiles:  make(map[int]string),
		segments:    make(map[int]Segment),
		manifest:    manifest,
		payloadKey:  payloadKey,
		aesGcm:      aesGcm,
		tempDir:     tempDir,
		finalWriter: finalWriter,
		segmentSize: segmentSize,
	}, nil
}

// WriteChunk encrypts and stores a chunk out-of-order.
func (cm *TDFChunkManager) WriteChunk(idx int, chunk []byte) error {
	if cm.closed {
		return fmt.Errorf("TDFChunkManager is closed")
	}
	cipherData, err := cm.aesGcm.Encrypt(chunk)
	if err != nil {
		return err
	}
	tmpFile := fmt.Sprintf("%s/chunk_%d.enc", cm.tempDir, idx)
	f, err := os.Create(tmpFile)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(cipherData)
	if err != nil {
		return err
	}
	cm.chunkFiles[idx] = tmpFile
	cm.chunkStatus[idx] = true
	segmentSig, err := calculateSignature(cipherData, cm.payloadKey[:], HS256, false)
	if err != nil {
		return err
	}
	cm.segments[idx] = Segment{
		Hash:          string(ocrypto.Base64Encode([]byte(segmentSig))),
		Size:          int64(len(chunk)),
		EncryptedSize: int64(len(cipherData)),
	}
	return nil
}

// AllChunksComplete returns true if all chunks are written.
func (cm *TDFChunkManager) AllChunksComplete() bool {
	return len(cm.chunkStatus) == cm.chunkCount
}

// Finalize assembles the encrypted chunks in order, writes the manifest, and produces the final TDF.
func (cm *TDFChunkManager) Finalize() error {
	if cm.closed {
		return nil
	}
	if !cm.AllChunksComplete() {
		return fmt.Errorf("not all chunks are complete")
	}
	tdfWriter := archive.NewTDFWriter(cm.finalWriter)
	var totalPayloadSize int64
	for i := 0; i < cm.chunkCount; i++ {
		f, err := os.Open(cm.chunkFiles[i])
		if err != nil {
			return err
		}
		stat, _ := f.Stat()
		totalPayloadSize += stat.Size()
		f.Close()
	}
	err := tdfWriter.SetPayloadSize(totalPayloadSize)
	if err != nil {
		return err
	}
	for i := 0; i < cm.chunkCount; i++ {
		f, err := os.Open(cm.chunkFiles[i])
		if err != nil {
			return err
		}
		cipherData, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return err
		}
		err = tdfWriter.AppendPayload(cipherData)
		if err != nil {
			return err
		}
	}
	// Assemble segments in order
	orderedSegments := make([]Segment, cm.chunkCount)
	for i := 0; i < cm.chunkCount; i++ {
		orderedSegments[i] = cm.segments[i]
	}
	cm.manifest.EncryptionInformation.IntegrityInformation.Segments = orderedSegments
	manifestBytes, err := json.Marshal(cm.manifest)
	if err != nil {
		return err
	}
	err = tdfWriter.AppendManifest(string(manifestBytes))
	if err != nil {
		return err
	}
	_, err = tdfWriter.Finish()
	cm.closed = true
	return err
}
