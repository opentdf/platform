//go:build wasip1

package main

import (
	"bytes"
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

// encrypt performs TDF3 encryption (single or multi-segment). All crypto is
// delegated to the host via hostcrypto; manifest construction, integrity
// computation, and ZIP assembly run inside the WASM sandbox.
//
// segmentSize controls the plaintext chunk size per segment. If <= 0, the
// entire plaintext is encrypted as a single segment (backward compatible).
func encrypt(kasPubPEM, kasURL string, attrs []string, plaintext []byte, integrityAlg, segIntegrityAlg, segmentSize int) ([]byte, error) {
	// 1. Generate 32-byte AES-256 DEK
	dek, err := hostcrypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	// 2. RSA-OAEP wrap DEK with KAS public key
	wrappedKey, err := hostcrypto.RsaOaepSha1Encrypt(kasPubPEM, dek)
	if err != nil {
		return nil, err
	}

	// 3. Generate pseudo-UUID for policy
	uuid, err := generatePseudoUUID()
	if err != nil {
		return nil, err
	}

	// 4. Build policy JSON using tinyjson types
	policyJSON, err := buildPolicyJSON(uuid, attrs)
	if err != nil {
		return nil, err
	}

	// 5. Base64-encode policy
	base64Policy := base64.StdEncoding.EncodeToString(policyJSON)

	// 6. Policy binding: HMAC-SHA256(dek, base64Policy) → hex → base64
	// Double-encoding required for Go SDK decrypt compatibility
	bindingHMAC, err := hostcrypto.HmacSHA256(dek, []byte(base64Policy))
	if err != nil {
		return nil, err
	}
	bindingHash := base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(bindingHMAC)))

	// 7. Determine segment boundaries
	ptLen := len(plaintext)
	if ptLen == 0 {
		// Empty plaintext → single segment of 0 bytes
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

	// Default sizes for manifest (based on full-sized segments)
	defaultEncSegSize := int64(segmentSize + 28) // nonce(12) + tag(16)

	// 8. Encrypt each segment and compute integrity
	var segments []types.Segment
	var ciphertexts [][]byte
	var aggregateHash []byte

	ptOffset := 0
	for i := 0; i < numSegments; i++ {
		chunkEnd := ptOffset + segmentSize
		if chunkEnd > ptLen {
			chunkEnd = ptLen
		}
		chunk := plaintext[ptOffset:chunkEnd]

		// Encrypt with AES-256-GCM: returns [nonce(12) || ciphertext || tag(16)]
		fullCT, err := hostcrypto.AesGcmEncrypt(dek, chunk)
		if err != nil {
			return nil, err
		}
		ciphertexts = append(ciphertexts, fullCT)

		// Segment integrity — signature is over the full encrypted blob
		// [nonce(12) || ciphertext || tag(16)], matching the standard SDK.
		segmentSig, err := calculateSignature(fullCT, dek, segIntegrityAlg)
		if err != nil {
			return nil, err
		}

		// Accumulate raw signature bytes for root hash
		aggregateHash = append(aggregateHash, segmentSig...)

		segments = append(segments, types.Segment{
			Hash:          base64.StdEncoding.EncodeToString(segmentSig),
			Size:          int64(len(chunk)),
			EncryptedSize: int64(len(fullCT)),
		})

		ptOffset = chunkEnd
	}

	// 9. Root signature over aggregated segment hashes
	rootSig, err := calculateSignature(aggregateHash, dek, integrityAlg)
	if err != nil {
		return nil, err
	}
	rootSigB64 := base64.StdEncoding.EncodeToString(rootSig)

	// 10. Build manifest
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
		return nil, err
	}

	// 11. Assemble ZIP
	sw := zs.NewSegmentTDFWriter(numSegments)
	ctx := context.Background()

	var result bytes.Buffer
	for i, ct := range ciphertexts {
		crc := crc32.ChecksumIEEE(ct)
		header, err := sw.WriteSegment(ctx, i, uint64(len(ct)), crc)
		if err != nil {
			return nil, err
		}
		result.Write(header)
		result.Write(ct)
	}

	tail, err := sw.Finalize(ctx, manifestJSON)
	if err != nil {
		return nil, err
	}
	result.Write(tail)

	return result.Bytes(), nil
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
