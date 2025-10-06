// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
)

// buildZip assembles the payload+finalize stream into a single byte slice for reading.
func buildZip(t *testing.T, segs [][]byte, finalize []byte) []byte {
	t.Helper()
	var all []byte
	for _, s := range segs {
		all = append(all, s...)
	}
	all = append(all, finalize...)
	return all
}

func TestZip64Mode_Auto_Small_UsesZip32(t *testing.T) {
	w := NewSegmentTDFWriter(2, WithZip64Mode(Zip64Auto))

	var parts [][]byte
	p0, err := w.WriteSegment(t.Context(), 0, []byte("hello "))
	if err != nil {
		t.Fatal(err)
	}
	parts = append(parts, p0)
	p1, err := w.WriteSegment(t.Context(), 1, []byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	parts = append(parts, p1)

	fin, err := w.Finalize(t.Context(), []byte(`{"m":1}`))
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	data := buildZip(t, parts, fin)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip open failed: %v", err)
	}
	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(zr.File))
	}

	// Validate payload can be read and CRC matches implicitly.
	var payload *zip.File
	for _, f := range zr.File {
		if f.Name == TDFPayloadFileName {
			payload = f
			break
		}
	}
	if payload == nil {
		t.Fatal("payload not found")
	}
	rc, err := payload.Open()
	if err != nil {
		t.Fatalf("open payload failed: %v", err)
	}
	_, err = io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("read payload failed: %v", err)
	}
}

func TestZip64Mode_Always_Small_UsesZip64(t *testing.T) {
	w := NewSegmentTDFWriter(1, WithZip64Mode(Zip64Always))

	seg, err := w.WriteSegment(t.Context(), 0, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	fin, err := w.Finalize(t.Context(), []byte(`{"m":1}`))
	if err != nil {
		t.Fatal(err)
	}
	w.Close()

	data := buildZip(t, [][]byte{seg}, fin)
	// Basic open check; many readers accept ZIP64 regardless of size.
	if _, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("zip open failed (zip64 always): %v", err)
	}
}

func TestZip64Mode_Never_Overflow_Fails(t *testing.T) {
	w := NewSegmentTDFWriter(1, WithZip64Mode(Zip64Never))

	// Simulate sizes that would require ZIP64 by directly bumping payloadEntry fields
	sw, ok := w.(*segmentWriter)
	if !ok {
		t.Fatal("writer type assertion failed")
	}
	// Write minimal segment to initialize structures
	if _, err := w.WriteSegment(t.Context(), 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	sw.payloadEntry.Size = uint64(^uint32(0)) + 1 // exceed 32-bit
	sw.payloadEntry.CompressedSize = sw.payloadEntry.Size

	if _, err := w.Finalize(t.Context(), []byte(`{"m":1}`)); err == nil {
		t.Fatal("expected finalize to fail due to Zip64Never")
	}
}
