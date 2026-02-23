//go:build wasip1

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash/crc32"

	"github.com/opentdf/platform/sdk/experimental/tdf/wasm/hostcrypto"
	"github.com/opentdf/platform/sdk/experimental/tdf/wasm/tinyjson/types"
	zs "github.com/opentdf/platform/sdk/experimental/tdf/wasm/zipstream/zipstream"
)

const (
	algHS256           = 0
	algGMAC            = 1
	kGMACPayloadLength = 16
)

func algString(alg int) string {
	if alg == algGMAC {
		return "GMAC"
	}
	return "HS256"
}

// calculateSignature computes an integrity signature using the given algorithm.
// For HS256: HMAC-SHA256(secret, data).
// For GMAC: extracts the last 16 bytes of data (the GCM authentication tag).
func calculateSignature(data, secret []byte, alg int) ([]byte, error) {
	if alg == algHS256 {
		return hostcrypto.HmacSHA256(secret, data)
	}
	if len(data) < kGMACPayloadLength {
		return nil, errors.New("data too short for GMAC signature")
	}
	sig := make([]byte, kGMACPayloadLength)
	copy(sig, data[len(data)-kGMACPayloadLength:])
	return sig, nil
}

// encryptStream performs TDF3 encryption using streaming I/O. Plaintext is
// read via hostcrypto.ReadInput and the TDF output is written via
// hostcrypto.WriteOutput. Two fixed buffers (ptBuf, ctBuf) are reused across
// segments so memory usage is ~2x segmentSize regardless of total file size.
func encryptStream(kasPubPEM, kasURL string, attrs []string, plaintextSize int64, integrityAlg, segIntegrityAlg, segmentSize int) (int64, error) {
	// 1. Generate 32-byte AES-256 DEK
	dek, err := hostcrypto.RandomBytes(32)
	if err != nil {
		return 0, err
	}

	// 2. RSA-OAEP wrap DEK with KAS public key
	wrappedKey, err := hostcrypto.RsaOaepSha1Encrypt(kasPubPEM, dek)
	if err != nil {
		return 0, err
	}

	// 3. Generate pseudo-UUID for policy
	uuid, err := generatePseudoUUID()
	if err != nil {
		return 0, err
	}

	// 4. Build policy JSON using tinyjson types
	policyJSON, err := buildPolicyJSON(uuid, attrs)
	if err != nil {
		return 0, err
	}

	// 5. Base64-encode policy
	base64Policy := base64.StdEncoding.EncodeToString(policyJSON)

	// 6. Policy binding: HMAC-SHA256(dek, base64Policy) → hex → base64
	bindingHMAC, err := hostcrypto.HmacSHA256(dek, []byte(base64Policy))
	if err != nil {
		return 0, err
	}
	bindingHash := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(bindingHMAC)))

	// 7. Determine segment boundaries
	ptLen := int(plaintextSize)
	if ptLen == 0 {
		segmentSize = 0
	} else if segmentSize <= 0 || segmentSize >= ptLen {
		segmentSize = ptLen
	}
	numSegments := 1
	if segmentSize > 0 {
		numSegments = ptLen / segmentSize
		if ptLen%segmentSize != 0 {
			numSegments++
		}
	}

	defaultEncSegSize := int64(segmentSize + 28)

	// 8. Allocate reusable buffers
	ptBuf := make([]byte, segmentSize)
	ctBuf := make([]byte, segmentSize+28)

	// 9. Create ZIP segment writer
	sw := zs.NewSegmentTDFWriter(numSegments)
	ctx := context.Background()

	var segments []types.Segment
	var aggregateHash []byte
	var totalWritten int64

	remaining := ptLen
	for i := 0; i < numSegments; i++ {
		chunkSize := segmentSize
		if chunkSize > remaining {
			chunkSize = remaining
		}

		// Read plaintext chunk via ReadInput (loop for partial reads)
		if err := readFull(ptBuf[:chunkSize]); err != nil {
			return 0, err
		}

		// Encrypt into reusable ctBuf
		ctLen, err := hostcrypto.AesGcmEncryptInto(dek, ptBuf[:chunkSize], ctBuf)
		if err != nil {
			return 0, err
		}

		// Segment integrity
		segmentSig, err := calculateSignature(ctBuf[:ctLen], dek, segIntegrityAlg)
		if err != nil {
			return 0, err
		}
		aggregateHash = append(aggregateHash, segmentSig...)

		segments = append(segments, types.Segment{
			Hash:          base64.StdEncoding.EncodeToString(segmentSig),
			Size:          int64(chunkSize),
			EncryptedSize: int64(ctLen),
		})

		// Get ZIP header bytes (non-empty for segment 0 only)
		crc := crc32.ChecksumIEEE(ctBuf[:ctLen])
		header, err := sw.WriteSegment(ctx, i, uint64(ctLen), crc)
		if err != nil {
			return 0, err
		}

		// Write header (if any) then ciphertext via WriteOutput
		if len(header) > 0 {
			if _, err := hostcrypto.WriteOutput(header); err != nil {
				return 0, err
			}
			totalWritten += int64(len(header))
		}
		if _, err := hostcrypto.WriteOutput(ctBuf[:ctLen]); err != nil {
			return 0, err
		}
		totalWritten += int64(ctLen)

		remaining -= chunkSize
	}

	// 10. Root signature over aggregated segment hashes
	rootSig, err := calculateSignature(aggregateHash, dek, integrityAlg)
	if err != nil {
		return 0, err
	}
	rootSigB64 := base64.StdEncoding.EncodeToString(rootSig)

	// 11. Build manifest
	manifest := types.Manifest{
		TDFVersion: "4.3.0",
		EncryptionInformation: types.EncryptionInformation{
			KeyAccessType: "split",
			Policy:        base64Policy,
			KeyAccessObjs: []types.KeyAccess{{
				KeyType:    "wrapped",
				KasURL:     kasURL,
				Protocol:   "kas",
				WrappedKey: base64.StdEncoding.EncodeToString(wrappedKey),
				PolicyBinding: types.PolicyBinding{
					Alg:  "HS256",
					Hash: bindingHash,
				},
			}},
			Method: types.Method{
				Algorithm:    "AES-256-GCM",
				IsStreamable: true,
			},
			IntegrityInformation: types.IntegrityInformation{
				RootSignature: types.RootSignature{
					Algorithm: algString(integrityAlg),
					Signature: rootSigB64,
				},
				SegmentHashAlgorithm:    algString(segIntegrityAlg),
				DefaultSegmentSize:      int64(segmentSize),
				DefaultEncryptedSegSize: defaultEncSegSize,
				Segments:                segments,
			},
		},
		Payload: types.Payload{
			Type:        "reference",
			URL:         "0.payload",
			Protocol:    "zip",
			MimeType:    "application/octet-stream",
			IsEncrypted: true,
		},
	}

	manifestJSON, err := manifest.MarshalJSON()
	if err != nil {
		return 0, err
	}

	// 12. Finalize ZIP — get tail bytes (data descriptor + manifest entry + central dir)
	tail, err := sw.Finalize(ctx, manifestJSON)
	if err != nil {
		return 0, err
	}
	if _, err := hostcrypto.WriteOutput(tail); err != nil {
		return 0, err
	}
	totalWritten += int64(len(tail))

	return totalWritten, nil
}

// readFull reads exactly len(buf) bytes from ReadInput, looping to handle
// partial reads. Returns an error if EOF is reached before the buffer is full.
func readFull(buf []byte) error {
	offset := 0
	for offset < len(buf) {
		n, err := hostcrypto.ReadInput(buf[offset:])
		offset += n
		if err != nil {
			if offset < len(buf) {
				return errors.New("unexpected EOF reading input")
			}
			return nil
		}
	}
	return nil
}

// generatePseudoUUID generates a UUID v4-like string from 16 random bytes.
// Format: xxxxxxxx-xxxx-4xxx-Nxxx-xxxxxxxxxxxx (version 4, variant 1).
func generatePseudoUUID() (string, error) {
	b, err := hostcrypto.RandomBytes(16)
	if err != nil {
		return "", err
	}
	// Set version 4 (bits 12-15 of time_hi_and_version)
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant 1 (bits 6-7 of clock_seq_hi_and_reserved)
	b[8] = (b[8] & 0x3f) | 0x80

	return hex.EncodeToString(b[0:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16]), nil
}

// buildPolicyJSON constructs a TDF policy and marshals it to JSON via tinyjson.
func buildPolicyJSON(uuid string, attrs []string) ([]byte, error) {
	dataAttrs := make([]types.PolicyAttribute, len(attrs))
	for i, attr := range attrs {
		dataAttrs[i] = types.PolicyAttribute{
			Attribute: attr,
		}
	}

	policy := types.Policy{
		UUID: uuid,
		Body: types.PolicyBody{
			DataAttributes: dataAttrs,
			Dissem:         []string{},
		},
	}

	return policy.MarshalJSON()
}
