//go:build wasip1

package main

import (
	"encoding/base64"
	"errors"

	"github.com/opentdf/platform/sdk/experimental/tdf/wasm/hostcrypto"
	"github.com/opentdf/platform/sdk/experimental/tdf/wasm/tinyjson/types"
)

// ZIP local file header signature.
const zipLocalFileHeaderSig = 0x04034b50

// readUint16LE reads a little-endian uint16 from b at offset off.
func readUint16LE(b []byte, off int) uint16 {
	return uint16(b[off]) | uint16(b[off+1])<<8
}

// readUint32LE reads a little-endian uint32 from b at offset off.
func readUint32LE(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// algFromString converts algorithm name to constant. Returns error for unknown algorithms.
func algFromString(s string) (int, error) {
	switch s {
	case "HS256":
		return algHS256, nil
	case "GMAC":
		return algGMAC, nil
	default:
		return 0, errors.New("unknown integrity algorithm: " + s)
	}
}

// parseTDFZip performs a forward scan through ZIP local file headers to extract
// the manifest and payload from a TDF ZIP. TDF ZIPs always contain exactly
// 2 entries: "0.payload" and "0.manifest.json". This avoids encoding/binary
// and io.ReadSeeker which are problematic under TinyGo.
func parseTDFZip(data []byte) (manifestBytes, payloadBytes []byte, err error) {
	off := 0
	for off+30 <= len(data) {
		sig := readUint32LE(data, off)
		if sig != zipLocalFileHeaderSig {
			break
		}

		compressedSize := readUint32LE(data, off+18)
		nameLen := int(readUint16LE(data, off+26))
		extraLen := int(readUint16LE(data, off+28))

		headerEnd := off + 30
		if headerEnd+nameLen > len(data) {
			return nil, nil, errors.New("ZIP: truncated file name")
		}
		name := string(data[headerEnd : headerEnd+nameLen])

		dataStart := headerEnd + nameLen + extraLen
		dataEnd := dataStart + int(compressedSize)
		if dataEnd > len(data) {
			return nil, nil, errors.New("ZIP: truncated entry data for " + name)
		}

		switch name {
		case "0.payload":
			payloadBytes = data[dataStart:dataEnd]
		case "0.manifest.json":
			manifestBytes = data[dataStart:dataEnd]
		}

		off = dataEnd
	}

	if manifestBytes == nil {
		return nil, nil, errors.New("ZIP: 0.manifest.json not found")
	}
	if payloadBytes == nil {
		return nil, nil, errors.New("ZIP: 0.payload not found")
	}
	return manifestBytes, payloadBytes, nil
}

// decrypt performs a single-segment TDF3 decryption. The caller provides the
// pre-unwrapped DEK (from host-side KAS rewrap). All crypto is delegated to
// the host via hostcrypto; manifest parsing, integrity verification, and ZIP
// extraction run inside the WASM sandbox.
func decrypt(tdfData, dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, errors.New("DEK must be 32 bytes")
	}

	// 1. Parse ZIP to extract manifest and payload
	manifestBytes, payloadBytes, err := parseTDFZip(tdfData)
	if err != nil {
		return nil, err
	}

	// 2. Unmarshal manifest via tinyjson
	var manifest types.Manifest
	if err := manifest.UnmarshalJSON(manifestBytes); err != nil {
		return nil, errors.New("unmarshal manifest: " + err.Error())
	}

	// 3. Validate manifest fields
	if manifest.Method.Algorithm != "AES-256-GCM" {
		return nil, errors.New("unsupported algorithm: " + manifest.Method.Algorithm)
	}
	if len(manifest.Segments) == 0 {
		return nil, errors.New("manifest has no segments")
	}
	if len(manifest.Segments) > 1 {
		return nil, errors.New("multi-segment TDFs not yet supported")
	}
	seg := manifest.Segments[0]
	if seg.EncryptedSize != int64(len(payloadBytes)) {
		return nil, errors.New("payload size mismatch with manifest segment")
	}

	// 4. Determine integrity algorithms
	segAlg, err := algFromString(manifest.SegmentHashAlgorithm)
	if err != nil {
		return nil, err
	}
	rootAlg, err := algFromString(manifest.RootSignature.Algorithm)
	if err != nil {
		return nil, err
	}

	// 5. Verify segment integrity
	// cipher = payload[12:] (ciphertext+tag, without nonce)
	if len(payloadBytes) < 28 {
		return nil, errors.New("payload too short for AES-GCM")
	}
	cipher := payloadBytes[12:]

	segmentSig, err := calculateSignature(cipher, dek, segAlg)
	if err != nil {
		return nil, errors.New("calculate segment signature: " + err.Error())
	}
	expectedSegHash := base64.StdEncoding.EncodeToString(segmentSig)
	if seg.Hash != expectedSegHash {
		return nil, errors.New("segment integrity check failed")
	}

	// 6. Verify root signature
	rootSig, err := calculateSignature(segmentSig, dek, rootAlg)
	if err != nil {
		return nil, errors.New("calculate root signature: " + err.Error())
	}
	expectedRootSig := base64.StdEncoding.EncodeToString(rootSig)
	if manifest.RootSignature.Signature != expectedRootSig {
		return nil, errors.New("root signature verification failed")
	}

	// 7. Decrypt payload with AES-256-GCM
	plaintext, err := hostcrypto.AesGcmDecrypt(dek, payloadBytes)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
