//go:build wasip1

package main

import (
	"encoding/base64"
	"errors"

	"github.com/opentdf/platform/sdk/experimental/tdf/wasm/hostcrypto"
	"github.com/opentdf/platform/sdk/experimental/tdf/wasm/tinyjson/types"
)

// ZIP signatures.
const (
	zipLocalFileHeaderSig   = 0x04034b50
	zipEOCDSig              = 0x06054b50
	zipCDHeaderSig          = 0x02014b50
	zip64EOCDLocatorSig     = 0x07064b50
	zip64EOCDSig            = 0x06064b50
	zip64MagicVal32  uint32 = 0xFFFFFFFF
	zip64MagicVal16  uint16 = 0xFFFF
	zip64ExtraFieldTag      = 0x0001
)

// readUint16LE reads a little-endian uint16 from b at offset off.
func readUint16LE(b []byte, off int) uint16 {
	return uint16(b[off]) | uint16(b[off+1])<<8
}

// readUint32LE reads a little-endian uint32 from b at offset off.
func readUint32LE(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}

// readUint64LE reads a little-endian uint64 from b at offset off.
func readUint64LE(b []byte, off int) uint64 {
	return uint64(b[off]) | uint64(b[off+1])<<8 | uint64(b[off+2])<<16 | uint64(b[off+3])<<24 |
		uint64(b[off+4])<<32 | uint64(b[off+5])<<40 | uint64(b[off+6])<<48 | uint64(b[off+7])<<56
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

// parseTDFZip extracts the manifest and payload from a TDF ZIP archive.
// Uses the central directory (at the end of the ZIP) to locate entries,
// which correctly handles both single-segment TDFs (sizes in local file
// header) and multi-segment TDFs (sizes deferred to data descriptor).
func parseTDFZip(data []byte) (manifestBytes, payloadBytes []byte, err error) {
	// 1. Find End of Central Directory record by scanning backwards.
	eocdOff := -1
	for i := len(data) - 22; i >= 0; i-- {
		if readUint32LE(data, i) == zipEOCDSig {
			eocdOff = i
			break
		}
	}
	if eocdOff < 0 {
		return nil, nil, errors.New("ZIP: end of central directory not found")
	}

	numEntries := int(readUint16LE(data, eocdOff+8))
	cdOffset := int(readUint32LE(data, eocdOff+16))

	// Handle ZIP64: sentinel values redirect to the ZIP64 EOCD record.
	if readUint32LE(data, eocdOff+16) == zip64MagicVal32 || readUint16LE(data, eocdOff+8) == zip64MagicVal16 {
		// ZIP64 EOCD locator is 20 bytes before the standard EOCD.
		locOff := eocdOff - 20
		if locOff < 0 || readUint32LE(data, locOff) != zip64EOCDLocatorSig {
			return nil, nil, errors.New("ZIP: ZIP64 EOCD locator not found")
		}
		z64Off := int(readUint64LE(data, locOff+8))
		if z64Off < 0 || z64Off+56 > len(data) {
			return nil, nil, errors.New("ZIP: invalid ZIP64 EOCD record offset")
		}
		if readUint32LE(data, z64Off) != zip64EOCDSig {
			return nil, nil, errors.New("ZIP: invalid ZIP64 EOCD signature")
		}
		numEntries = int(readUint64LE(data, z64Off+24))
		cdOffset = int(readUint64LE(data, z64Off+48))
	}

	// 2. Parse central directory entries.
	off := cdOffset
	for i := 0; i < numEntries; i++ {
		if off+46 > len(data) {
			return nil, nil, errors.New("ZIP: truncated central directory")
		}
		if readUint32LE(data, off) != zipCDHeaderSig {
			return nil, nil, errors.New("ZIP: invalid central directory entry")
		}

		compressedSize := int(readUint32LE(data, off+20))
		nameLen := int(readUint16LE(data, off+28))
		extraLen := int(readUint16LE(data, off+30))
		commentLen := int(readUint16LE(data, off+32))
		localHeaderOffset := int(readUint32LE(data, off+42))

		// If ZIP64, read actual values from the extended info extra field.
		if readUint32LE(data, off+20) == zip64MagicVal32 || readUint32LE(data, off+42) == zip64MagicVal32 {
			extraOff := off + 46 + nameLen
			if extraOff+4 <= len(data) && readUint16LE(data, extraOff) == zip64ExtraFieldTag {
				// Zip64ExtendedInfoExtraField layout: tag(2) + size(2) + origSize(8) + compressedSize(8) + localHeaderOffset(8)
				if readUint32LE(data, off+20) == zip64MagicVal32 && extraOff+20 <= len(data) {
					compressedSize = int(readUint64LE(data, extraOff+12))
				}
				if readUint32LE(data, off+42) == zip64MagicVal32 && extraOff+28 <= len(data) {
					localHeaderOffset = int(readUint64LE(data, extraOff+20))
				}
			}
		}

		if off+46+nameLen > len(data) {
			return nil, nil, errors.New("ZIP: truncated CD entry name")
		}
		name := string(data[off+46 : off+46+nameLen])

		// Read data from local file header using CD's known compressed size.
		lfhOff := localHeaderOffset
		if lfhOff+30 > len(data) {
			return nil, nil, errors.New("ZIP: truncated local file header for " + name)
		}
		lfhNameLen := int(readUint16LE(data, lfhOff+26))
		lfhExtraLen := int(readUint16LE(data, lfhOff+28))
		dataStart := lfhOff + 30 + lfhNameLen + lfhExtraLen
		dataEnd := dataStart + compressedSize
		if dataEnd > len(data) {
			return nil, nil, errors.New("ZIP: truncated entry data for " + name)
		}

		switch name {
		case "0.payload":
			payloadBytes = data[dataStart:dataEnd]
		case "0.manifest.json":
			manifestBytes = data[dataStart:dataEnd]
		}

		off += 46 + nameLen + extraLen + commentLen
	}

	if manifestBytes == nil {
		return nil, nil, errors.New("ZIP: 0.manifest.json not found")
	}
	if payloadBytes == nil {
		return nil, nil, errors.New("ZIP: 0.payload not found")
	}
	return manifestBytes, payloadBytes, nil
}

// decrypt performs TDF3 decryption (single or multi-segment). The caller
// provides the pre-unwrapped DEK (from host-side KAS rewrap). All crypto
// is delegated to the host via hostcrypto; manifest parsing, integrity
// verification, and ZIP extraction run inside the WASM sandbox.
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

	// Validate total encrypted size matches payload
	var totalEncSize int64
	for _, seg := range manifest.Segments {
		totalEncSize += seg.EncryptedSize
	}
	if totalEncSize != int64(len(payloadBytes)) {
		return nil, errors.New("payload size mismatch with manifest segments")
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

	// 5. Verify segment integrity and decrypt each segment
	var plaintext []byte
	var aggregateHash []byte
	payloadOffset := 0

	for i, seg := range manifest.Segments {
		encData := payloadBytes[payloadOffset : payloadOffset+int(seg.EncryptedSize)]
		if len(encData) < 28 {
			return nil, errors.New("segment too short for AES-GCM")
		}

		// Segment integrity — signature is over the full encrypted blob
		// [nonce(12) || ciphertext || tag(16)], matching the standard SDK.
		segmentSig, err := calculateSignature(encData, dek, segAlg)
		if err != nil {
			return nil, errors.New("calculate segment signature: " + err.Error())
		}
		expectedSegHash := base64.StdEncoding.EncodeToString(segmentSig)
		if seg.Hash != expectedSegHash {
			return nil, errors.New("segment " + itoa(i) + " integrity check failed")
		}

		// Accumulate raw signature bytes for root hash
		aggregateHash = append(aggregateHash, segmentSig...)

		// Decrypt segment
		segPlaintext, err := hostcrypto.AesGcmDecrypt(dek, encData)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, segPlaintext...)

		payloadOffset += int(seg.EncryptedSize)
	}

	// 6. Verify root signature over aggregate hash
	rootSig, err := calculateSignature(aggregateHash, dek, rootAlg)
	if err != nil {
		return nil, errors.New("calculate root signature: " + err.Error())
	}
	expectedRootSig := base64.StdEncoding.EncodeToString(rootSig)
	if manifest.RootSignature.Signature != expectedRootSig {
		return nil, errors.New("root signature verification failed")
	}

	return plaintext, nil
}

// itoa converts a non-negative int to a string without fmt (TinyGo-safe).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
