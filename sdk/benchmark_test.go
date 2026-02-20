package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/internal/zipstream"
)

// createBenchTDF builds a valid TDF from scratch without any KAS infrastructure.
// It returns the TDF bytes (or a temp file for large sizes) and the payload key.
func createBenchTDF(b *testing.B, plaintextSize int64) (io.ReadSeeker, []byte) {
	b.Helper()

	// Generate random AES-256 key
	payloadKey := make([]byte, kKeySize)
	if _, err := rand.Read(payloadKey); err != nil {
		b.Fatal(err)
	}

	aesGcm, err := ocrypto.NewAESGcm(payloadKey)
	if err != nil {
		b.Fatal(err)
	}

	segmentSize := int64(defaultSegmentSize)
	totalSegments := plaintextSize / segmentSize
	if plaintextSize%segmentSize != 0 {
		totalSegments++
	}
	if totalSegments == 0 {
		totalSegments = 1
	}

	encryptedSegmentSize := segmentSize + gcmIvSize + aesBlockSize
	payloadSize := plaintextSize + (totalSegments * (gcmIvSize + aesBlockSize))

	zipMode := zipstream.Zip64Auto
	if payloadSize >= zip64MagicVal {
		zipMode = zipstream.Zip64Always
	}

	expectedSegments := int(totalSegments)
	archiveWriter := zipstream.NewSegmentTDFWriter(
		expectedSegments,
		zipstream.WithZip64Mode(zipMode),
		zipstream.WithMaxSegments(expectedSegments),
	)

	var tdfBuf bytes.Buffer

	// Pre-allocate a plaintext segment buffer (reused across segments)
	plainBuf := make([]byte, segmentSize)
	if _, err := rand.Read(plainBuf); err != nil {
		b.Fatal(err)
	}

	var readPos int64
	var aggregateHashBuilder strings.Builder
	var segments []Segment

	ctx := context.Background()
	for i := 0; i < expectedSegments; i++ {
		readSize := segmentSize
		if (plaintextSize - readPos) < segmentSize {
			readSize = plaintextSize - readPos
		}

		cipherData, err := aesGcm.Encrypt(plainBuf[:readSize])
		if err != nil {
			b.Fatal(err)
		}

		crc := crc32.ChecksumIEEE(cipherData)
		headerBytes, err := archiveWriter.WriteSegment(ctx, i, uint64(len(cipherData)), crc)
		if err != nil {
			b.Fatal(err)
		}

		if len(headerBytes) > 0 {
			tdfBuf.Write(headerBytes)
		}
		tdfBuf.Write(cipherData)

		segSig, err := calculateSignature(cipherData, payloadKey, HS256, false)
		if err != nil {
			b.Fatal(err)
		}

		aggregateHashBuilder.WriteString(segSig)
		segments = append(segments, Segment{
			Hash:          string(ocrypto.Base64Encode([]byte(segSig))),
			Size:          readSize,
			EncryptedSize: int64(len(cipherData)),
		})

		readPos += readSize
	}

	// Root signature
	rootSig, err := calculateSignature([]byte(aggregateHashBuilder.String()), payloadKey, HS256, false)
	if err != nil {
		b.Fatal(err)
	}

	manifest := Manifest{
		EncryptionInformation: EncryptionInformation{
			KeyAccessType: kSplitKeyType,
			Method: Method{
				Algorithm:    kGCMCipherAlgorithm,
				IsStreamable: true,
			},
			IntegrityInformation: IntegrityInformation{
				RootSignature: RootSignature{
					Algorithm: hmacIntegrityAlgorithm,
					Signature: string(ocrypto.Base64Encode([]byte(rootSig))),
				},
				SegmentHashAlgorithm:    hmacIntegrityAlgorithm,
				DefaultSegmentSize:      segmentSize,
				DefaultEncryptedSegSize: encryptedSegmentSize,
				Segments:                segments,
			},
		},
		Payload: Payload{
			Type:        tdfZipReference,
			URL:         zipstream.TDFPayloadFileName,
			Protocol:    tdfAsZip,
			MimeType:    defaultMimeType,
			IsEncrypted: true,
		},
		TDFVersion: TDFSpecVersion,
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		b.Fatal(err)
	}

	finalBytes, err := archiveWriter.Finalize(ctx, manifestJSON)
	if err != nil {
		b.Fatal(err)
	}
	tdfBuf.Write(finalBytes)

	if err := archiveWriter.Close(); err != nil {
		b.Fatal(err)
	}

	return bytes.NewReader(tdfBuf.Bytes()), payloadKey
}

// createBenchTDFFile is like createBenchTDF but writes to a temp file for large sizes.
func createBenchTDFFile(b *testing.B, plaintextSize int64) (*os.File, []byte) {
	b.Helper()

	payloadKey := make([]byte, kKeySize)
	if _, err := rand.Read(payloadKey); err != nil {
		b.Fatal(err)
	}

	aesGcm, err := ocrypto.NewAESGcm(payloadKey)
	if err != nil {
		b.Fatal(err)
	}

	segmentSize := int64(defaultSegmentSize)
	totalSegments := plaintextSize / segmentSize
	if plaintextSize%segmentSize != 0 {
		totalSegments++
	}
	if totalSegments == 0 {
		totalSegments = 1
	}

	encryptedSegmentSize := segmentSize + gcmIvSize + aesBlockSize
	payloadSize := plaintextSize + (totalSegments * (gcmIvSize + aesBlockSize))

	zipMode := zipstream.Zip64Auto
	if payloadSize >= zip64MagicVal {
		zipMode = zipstream.Zip64Always
	}

	expectedSegments := int(totalSegments)
	archiveWriter := zipstream.NewSegmentTDFWriter(
		expectedSegments,
		zipstream.WithZip64Mode(zipMode),
		zipstream.WithMaxSegments(expectedSegments),
	)

	f, err := os.CreateTemp(b.TempDir(), "bench-tdf-*.tdf")
	if err != nil {
		b.Fatal(err)
	}

	plainBuf := make([]byte, segmentSize)
	if _, err := rand.Read(plainBuf); err != nil {
		b.Fatal(err)
	}

	var readPos int64
	var aggregateHashBuilder strings.Builder
	var segments []Segment

	ctx := context.Background()
	for i := 0; i < expectedSegments; i++ {
		readSize := segmentSize
		if (plaintextSize - readPos) < segmentSize {
			readSize = plaintextSize - readPos
		}

		cipherData, err := aesGcm.Encrypt(plainBuf[:readSize])
		if err != nil {
			b.Fatal(err)
		}

		crc := crc32.ChecksumIEEE(cipherData)
		headerBytes, err := archiveWriter.WriteSegment(ctx, i, uint64(len(cipherData)), crc)
		if err != nil {
			b.Fatal(err)
		}

		if len(headerBytes) > 0 {
			if _, err := f.Write(headerBytes); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := f.Write(cipherData); err != nil {
			b.Fatal(err)
		}

		segSig, err := calculateSignature(cipherData, payloadKey, HS256, false)
		if err != nil {
			b.Fatal(err)
		}

		aggregateHashBuilder.WriteString(segSig)
		segments = append(segments, Segment{
			Hash:          string(ocrypto.Base64Encode([]byte(segSig))),
			Size:          readSize,
			EncryptedSize: int64(len(cipherData)),
		})

		readPos += readSize
	}

	rootSig, err := calculateSignature([]byte(aggregateHashBuilder.String()), payloadKey, HS256, false)
	if err != nil {
		b.Fatal(err)
	}

	manifest := Manifest{
		EncryptionInformation: EncryptionInformation{
			KeyAccessType: kSplitKeyType,
			Method: Method{
				Algorithm:    kGCMCipherAlgorithm,
				IsStreamable: true,
			},
			IntegrityInformation: IntegrityInformation{
				RootSignature: RootSignature{
					Algorithm: hmacIntegrityAlgorithm,
					Signature: string(ocrypto.Base64Encode([]byte(rootSig))),
				},
				SegmentHashAlgorithm:    hmacIntegrityAlgorithm,
				DefaultSegmentSize:      segmentSize,
				DefaultEncryptedSegSize: encryptedSegmentSize,
				Segments:                segments,
			},
		},
		Payload: Payload{
			Type:        tdfZipReference,
			URL:         zipstream.TDFPayloadFileName,
			Protocol:    tdfAsZip,
			MimeType:    defaultMimeType,
			IsEncrypted: true,
		},
		TDFVersion: TDFSpecVersion,
	}

	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		b.Fatal(err)
	}

	finalBytes, err := archiveWriter.Finalize(ctx, manifestJSON)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := f.Write(finalBytes); err != nil {
		b.Fatal(err)
	}

	if err := archiveWriter.Close(); err != nil {
		b.Fatal(err)
	}

	return f, payloadKey
}

// loadTDFForBenchmark constructs a Reader with a known payload key, bypassing KAS.
func loadTDFForBenchmark(b *testing.B, rs io.ReadSeeker, payloadKey []byte) *Reader {
	b.Helper()

	tdfReader, err := zipstream.NewTDFReader(rs)
	if err != nil {
		b.Fatal(err)
	}

	manifestStr, err := tdfReader.Manifest()
	if err != nil {
		b.Fatal(err)
	}

	var manifest Manifest
	if err := json.Unmarshal([]byte(manifestStr), &manifest); err != nil {
		b.Fatal(err)
	}

	var payloadSize int64
	for _, seg := range manifest.Segments {
		payloadSize += seg.Size
	}

	aesGcm, err := ocrypto.NewAESGcm(payloadKey)
	if err != nil {
		b.Fatal(err)
	}

	return &Reader{
		tdfReader:   tdfReader,
		manifest:    manifest,
		payloadSize: payloadSize,
		payloadKey:  payloadKey,
		aesGcm:      aesGcm,
	}
}

func BenchmarkDecrypt(b *testing.B) {
	cases := []struct {
		name       string
		size       int64
		useTmpFile bool
		skipShort  bool
	}{
		{"1MB", 1 << 20, false, false},
		{"100MB", 100 << 20, false, false},
		{"1GB", 1 << 30, true, true},
		{"2GB", 2 << 30, true, true},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if tc.skipShort && testing.Short() {
				b.Skipf("skipping %s in short mode", tc.name)
			}

			var rs io.ReadSeeker
			var payloadKey []byte

			if tc.useTmpFile {
				f, key := createBenchTDFFile(b, tc.size)
				rs = f
				payloadKey = key
			} else {
				rs, payloadKey = createBenchTDF(b, tc.size)
			}

			b.SetBytes(tc.size)
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				if _, err := rs.Seek(0, io.SeekStart); err != nil {
					b.Fatal(err)
				}

				r := loadTDFForBenchmark(b, rs, payloadKey)
				r.cursor = 0

				n, err := r.WriteTo(io.Discard)
				if err != nil {
					b.Fatal(err)
				}
				if n != tc.size {
					b.Fatalf("expected %d bytes, got %d", tc.size, n)
				}
			}
		})
	}
}

func BenchmarkStreamDecrypt(b *testing.B) {
	const payloadSize = 100 << 20 // 100MB

	rs, payloadKey := createBenchTDF(b, payloadSize)

	b.SetBytes(payloadSize)
	b.ReportAllocs()
	b.ResetTimer()

	buf := make([]byte, 32*1024) // 32KB read buffer
	for range b.N {
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}

		r := loadTDFForBenchmark(b, rs, payloadKey)
		r.cursor = 0

		var total int64
		for {
			n, err := r.Read(buf)
			total += int64(n)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
		}
		if total != payloadSize {
			b.Fatalf("expected %d bytes, got %d", payloadSize, total)
		}
	}
}

func BenchmarkDecryptSegmentSizes(b *testing.B) {
	const payloadSize = 10 << 20 // 10MB - small enough to be fast

	// Only test the default segment size since createBenchTDF uses it,
	// but this validates the per-segment overhead at a smaller scale.
	rs, payloadKey := createBenchTDF(b, payloadSize)

	b.SetBytes(payloadSize)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}

		r := loadTDFForBenchmark(b, rs, payloadKey)
		r.cursor = 0

		n, err := r.WriteTo(io.Discard)
		if err != nil {
			b.Fatal(err)
		}
		if n != payloadSize {
			b.Fatalf("expected %d bytes, got %d", payloadSize, n)
		}
	}
}
