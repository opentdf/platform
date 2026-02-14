// Canary: encoding/binary, hash/crc32, bytes, sort, sync
// These are used by the zipstream package for writing TDF ZIP archives.
// encoding/binary and hash/crc32 have test failures in TinyGo — this
// validates whether the specific operations we use actually work.
package main

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"sort"
	"sync"
)

// Minimal ZIP local file header — same struct pattern as zipstream/zip_headers.go
type localFileHeader struct {
	Signature             uint32
	Version               uint16
	GeneralPurposeBitFlag uint16
	CompressionMethod     uint16
	LastModifiedTime      uint16
	LastModifiedDate      uint16
	Crc32                 uint32
	CompressedSize        uint32
	UncompressedSize      uint32
	FilenameLength        uint16
	ExtraFieldLength      uint16
}

func main() {
	// binary.Write with LittleEndian (used for all ZIP header serialization)
	var buf bytes.Buffer
	header := localFileHeader{
		Signature:        0x04034b50,
		Version:          20,
		CompressedSize:   1024,
		UncompressedSize: 1024,
		FilenameLength:   9, // "0.payload"
	}
	if err := binary.Write(&buf, binary.LittleEndian, header); err != nil {
		panic("binary.Write failed: " + err.Error())
	}
	if buf.Len() != 30 { // ZIP local file header is always 30 bytes
		panic("unexpected header size")
	}

	// binary.Read back
	var readBack localFileHeader
	if err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &readBack); err != nil {
		panic("binary.Read failed: " + err.Error())
	}
	if readBack.Signature != 0x04034b50 {
		panic("signature mismatch after round-trip")
	}

	// CRC32 IEEE (used for ZIP segment integrity)
	payload := []byte("encrypted TDF segment data placeholder")
	checksum := crc32.ChecksumIEEE(payload)
	if checksum == 0 {
		panic("crc32 returned zero for non-empty data")
	}

	// Incremental CRC32 (used in zipstream for segment CRC combining)
	hasher := crc32.NewIEEE()
	hasher.Write(payload[:10])
	hasher.Write(payload[10:])
	if hasher.Sum32() != checksum {
		panic("incremental crc32 mismatch")
	}

	// sort.Ints (used for ordering sparse segment indices)
	indices := []int{3, 1, 4, 1, 5, 9, 2, 6}
	sort.Ints(indices)
	for i := 1; i < len(indices); i++ {
		if indices[i] < indices[i-1] {
			panic("sort.Ints produced unsorted output")
		}
	}

	// sync.Mutex (used for thread-safe segment writing)
	var mu sync.Mutex
	mu.Lock()
	mu.Unlock()

	// bytes.Buffer composition (used throughout zipstream)
	var out bytes.Buffer
	out.Write(buf.Bytes())
	out.Write(payload)
	if out.Len() != 30+len(payload) {
		panic("buffer composition size mismatch")
	}
}
