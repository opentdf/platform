// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
)

// benchKASKey generates a mock KAS key for benchmarks that need Finalize.
func benchKASKey(b *testing.B) *policy.SimpleKasKey {
	b.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		b.Fatal(err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return &policy.SimpleKasKey{
		KasUri: "https://kas.example.com/",
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       "bench-kid",
			Pem:       string(publicKeyPEM),
		},
	}
}

func BenchmarkWriterEncrypt(b *testing.B) {
	cases := []struct {
		name        string
		payloadSize int64
		segmentSize int
		skipShort   bool
	}{
		{"1MB", 1 << 20, 2 << 20, false},
		{"100MB", 100 << 20, 2 << 20, false},
		{"1GB", 1 << 30, 2 << 20, true},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if tc.skipShort && testing.Short() {
				b.Skipf("skipping %s in short mode", tc.name)
			}

			ctx := context.Background()
			kasKey := benchKASKey(b)

			// Generate one segment-sized random buffer, reused as source
			srcBuf := make([]byte, tc.segmentSize)
			if _, err := rand.Read(srcBuf); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(tc.payloadSize)
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				writer, err := NewWriter(ctx)
				if err != nil {
					b.Fatal(err)
				}

				remaining := tc.payloadSize
				for i := 0; remaining > 0; i++ {
					segSize := int64(tc.segmentSize)
					if remaining < segSize {
						segSize = remaining
					}

					// Copy source data since EncryptInPlace mutates the buffer
					data := make([]byte, segSize)
					copy(data, srcBuf[:segSize])

					_, err := writer.WriteSegment(ctx, i, data)
					if err != nil {
						b.Fatal(err)
					}

					remaining -= segSize
				}

				_, err = writer.Finalize(ctx, WithDefaultKAS(kasKey))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkWriterWriteSegment(b *testing.B) {
	// Benchmark just the WriteSegment call (encrypt + hash) for a single 2MB segment
	const segSize = 2 << 20

	ctx := context.Background()

	srcBuf := make([]byte, segSize)
	if _, err := rand.Read(srcBuf); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(segSize)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		writer, err := NewWriter(ctx)
		if err != nil {
			b.Fatal(err)
		}

		data := make([]byte, segSize)
		copy(data, srcBuf)

		_, err = writer.WriteSegment(ctx, 0, data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkWriterAssemble benchmarks creating a complete TDF archive
// (segment bytes + finalize bytes) that could be read by the standard sdk.Reader.
func BenchmarkWriterAssemble(b *testing.B) {
	cases := []struct {
		name        string
		payloadSize int64
		segmentSize int
		skipShort   bool
	}{
		{"1MB", 1 << 20, 2 << 20, false},
		{"100MB", 100 << 20, 2 << 20, false},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			if tc.skipShort && testing.Short() {
				b.Skipf("skipping %s in short mode", tc.name)
			}

			ctx := context.Background()
			kasKey := benchKASKey(b)

			srcBuf := make([]byte, tc.segmentSize)
			if _, err := rand.Read(srcBuf); err != nil {
				b.Fatal(err)
			}

			b.SetBytes(tc.payloadSize)
			b.ReportAllocs()
			b.ResetTimer()

			for range b.N {
				writer, err := NewWriter(ctx)
				if err != nil {
					b.Fatal(err)
				}

				var tdfBuf bytes.Buffer
				remaining := tc.payloadSize
				for i := 0; remaining > 0; i++ {
					segSize := int64(tc.segmentSize)
					if remaining < segSize {
						segSize = remaining
					}

					data := make([]byte, segSize)
					copy(data, srcBuf[:segSize])

					result, err := writer.WriteSegment(ctx, i, data)
					if err != nil {
						b.Fatal(err)
					}

					if _, err := io.Copy(&tdfBuf, result.TDFData); err != nil {
						b.Fatal(err)
					}

					remaining -= segSize
				}

				finalResult, err := writer.Finalize(ctx, WithDefaultKAS(kasKey))
				if err != nil {
					b.Fatal(err)
				}
				tdfBuf.Write(finalResult.Data)
			}
		})
	}
}
