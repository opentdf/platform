// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSegmentWriter_SequentialOrder(t *testing.T) {
	// Test basic sequential segment writing (0, 1, 2, 3, 4)
	writer := NewSegmentTDFWriter(5)
	ctx := t.Context()

	testSegments := [][]byte{
		[]byte("First"),         // 5 bytes
		[]byte("SecondPart"),    // 10 bytes
		[]byte("Third"),         // 5 bytes
		[]byte("FourthSection"), // 13 bytes
		[]byte("Last"),          // 4 bytes
	}

	manifest := []byte(`{"segments": 5}`)
	var allBytes []byte

	// Write segments in sequential order
	for i, data := range testSegments {
		crc := crc32.ChecksumIEEE(data)
		segmentBytes, err := writer.WriteSegment(ctx, i, uint64(len(data)), crc)
		require.NoError(t, err, "Failed to write segment %d", i)

		t.Logf("Sequential segment %d: %d bytes", i, len(segmentBytes))

		if i == 0 {
			// Segment 0 should be larger due to ZIP header
			assert.NotEmpty(t, segmentBytes, "Segment 0 should include ZIP header")
		} else {
			// Other segments should be approximately the size of the data
			assert.Empty(t, segmentBytes, "Segment %d should have no zip bytes", i)
		}

		allBytes = append(allBytes, segmentBytes...)
		allBytes = append(allBytes, data...)
	}

	t.Logf("Sequential total payload bytes before finalization: %d", len(allBytes))

	// Finalize
	finalBytes, err := writer.Finalize(ctx, manifest)
	require.NoError(t, err, "Failed to finalize")
	assert.Greater(t, len(finalBytes), len(manifest), "Final bytes should include manifest and ZIP structures")

	allBytes = append(allBytes, finalBytes...)

	// Validate ZIP structure
	zipReader, err := zip.NewReader(bytes.NewReader(allBytes), int64(len(allBytes)))
	require.NoError(t, err, "Should create valid ZIP")
	assert.Len(t, zipReader.File, 2, "Should have 2 files: payload and manifest")

	// Verify payload content
	payloadFile := findFileByName(zipReader, "0.payload")
	require.NotNil(t, payloadFile, "Should have payload file")

	payloadReader, err := payloadFile.Open()
	require.NoError(t, err, "Should open payload")
	defer payloadReader.Close()

	payloadContent, err := io.ReadAll(payloadReader)
	require.NoError(t, err, "Should read payload")

	// Verify content is in correct order
	expectedPayload := bytes.Join(testSegments, nil)
	assert.Equal(t, expectedPayload, payloadContent, "Payload should be in correct order")

	writer.Close()
}

func TestSegmentWriter_OutOfOrder(t *testing.T) {
	// Test out-of-order segment writing (2, 0, 4, 1, 3)
	writer := NewSegmentTDFWriter(1, WithZip64()) // Should expand segments dynamically
	ctx := t.Context()

	testSegments := map[int][]byte{
		0: []byte("First"),         // 5 bytes
		1: []byte("SecondPart"),    // 10 bytes
		2: []byte("Third"),         // 5 bytes
		3: []byte("FourthSection"), // 13 bytes
		4: []byte("Last"),          // 4 bytes
	}

	manifest := []byte(`{"segments": 5, "out_of_order": true}`)

	// Write order: 2, 0, 4, 1, 3
	writeOrder := []int{2, 0, 4, 1, 3}
	segmentBytes := make(map[int][]byte)

	for _, index := range writeOrder {
		data := testSegments[index]
		crc := crc32.ChecksumIEEE(data)
		bytes, err := writer.WriteSegment(ctx, index, uint64(len(data)), crc)
		require.NoError(t, err, "Failed to write segment %d out of order", index)

		if index == 0 {
			// Segment 0 should always include ZIP header, regardless of write order
			assert.NotEmpty(t, bytes, "Segment 0 should include ZIP header")
		} else {
			assert.Empty(t, bytes, "Segment %d should have no zip bytes", index)
		}

		var allBytes []byte
		allBytes = append(allBytes, bytes...)
		allBytes = append(allBytes, data...)
		segmentBytes[index] = allBytes
	}

	// Reassemble in logical order (as S3 would do)
	var allBytes []byte
	for i := 0; i < 5; i++ {
		segmentSize := len(segmentBytes[i])
		t.Logf("Adding segment %d: %d bytes", i, segmentSize)
		allBytes = append(allBytes, segmentBytes[i]...)
	}

	t.Logf("Total payload bytes before finalization: %d", len(allBytes))

	// Finalize
	finalBytes, err := writer.Finalize(ctx, manifest)
	require.NoError(t, err, "Failed to finalize out-of-order segments")

	t.Logf("Finalization bytes: %d", len(finalBytes))
	allBytes = append(allBytes, finalBytes...)

	t.Logf("Total file bytes: %d", len(allBytes))

	// Validate ZIP structure
	zipReader, err := zip.NewReader(bytes.NewReader(allBytes), int64(len(allBytes)))
	require.NoError(t, err, "Should create valid ZIP from out-of-order segments")
	assert.Len(t, zipReader.File, 2, "Should have 2 files: payload and manifest")

	// Verify payload content is in correct logical order
	payloadFile := findFileByName(zipReader, "0.payload")
	require.NotNil(t, payloadFile, "Should have payload file")

	payloadReader, err := payloadFile.Open()
	require.NoError(t, err, "Should open payload")
	defer payloadReader.Close()

	payloadContent, err := io.ReadAll(payloadReader)
	require.NoError(t, err, "Should read payload")

	// Verify content is in logical order (0,1,2,3,4) despite out-of-order writing
	expectedPayload := make([]byte, 0)
	for i := 0; i < 5; i++ {
		expectedPayload = append(expectedPayload, testSegments[i]...)
	}
	assert.Equal(t, expectedPayload, payloadContent, "Payload should be in logical order despite out-of-order writing")

	writer.Close()
}

func TestSegmentWriter_SparseIndices_InOrder(t *testing.T) {
	// Write sparse indices in order: 0,1,2,5000,5001,5002
	writer := NewSegmentTDFWriter(1)
	ctx := t.Context()

	testSegments := map[int][]byte{
		0:    []byte("A"),
		1:    []byte("BB"),
		2:    []byte("CCC"),
		5000: []byte("DDDD"),
		5001: []byte("EEEEE"),
		5002: []byte("FFFFFF"),
	}

	manifest := []byte(`{"segments": 6, "sparse": true}`)

	// Write in-order sparse indices
	order := []int{0, 1, 2, 5000, 5001, 5002}
	segmentBytes := make(map[int][]byte)
	for _, index := range order {
		data := testSegments[index]
		crc := crc32.ChecksumIEEE(data)
		bytes, err := writer.WriteSegment(ctx, index, uint64(len(data)), crc)
		require.NoError(t, err, "write segment %d failed", index)
		if index == 0 {
			assert.NotEmpty(t, bytes, "segment 0 should include ZIP header")
		} else {
			assert.Empty(t, bytes, "segment %d should have no zip bytes", index)
		}
		var totalBytes []byte
		totalBytes = append(totalBytes, bytes...)
		totalBytes = append(totalBytes, data...)
		segmentBytes[index] = totalBytes
	}

	// Assemble full file: concatenate segment bytes in ascending index order
	var allBytes []byte
	for _, index := range order {
		allBytes = append(allBytes, segmentBytes[index]...)
	}

	// Finalize and append trailer bytes
	finalBytes, err := writer.Finalize(ctx, manifest)
	require.NoError(t, err, "finalize failed")
	allBytes = append(allBytes, finalBytes...)

	// Validate resulting ZIP
	zipReader, err := zip.NewReader(bytes.NewReader(allBytes), int64(len(allBytes)))
	require.NoError(t, err, "zip should open")
	assert.Len(t, zipReader.File, 2, "two entries: payload and manifest")

	payloadFile := findFileByName(zipReader, "0.payload")
	require.NotNil(t, payloadFile, "payload entry present")
	r, err := payloadFile.Open()
	require.NoError(t, err)
	defer r.Close()
	payloadContent, err := io.ReadAll(r)
	require.NoError(t, err)

	// Expected payload is dense concatenation in ascending index order
	expected := []byte{}
	for _, index := range order {
		expected = append(expected, testSegments[index]...)
	}
	assert.Equal(t, expected, payloadContent)
}

func TestSegmentWriter_SparseIndices_OutOfOrder(t *testing.T) {
	// Write sparse indices out of order, ensure finalization builds correct content
	writer := NewSegmentTDFWriter(1)
	ctx := t.Context()

	testSegments := map[int][]byte{
		0:    []byte("first"),
		1:    []byte("second"),
		2:    []byte("third"),
		5000: []byte("fourth"),
		5001: []byte("fifth"),
		5002: []byte("sixth"),
	}
	writeOrder := []int{5000, 0, 5002, 2, 5001, 1}
	finalOrder := []int{0, 1, 2, 5000, 5001, 5002}

	manifest := []byte(`{"segments": 6, "sparse": true, "out_of_order": true}`)

	segmentBytes := make(map[int][]byte)
	for _, index := range writeOrder {
		data := testSegments[index]
		crc := crc32.ChecksumIEEE(data)
		bytes, err := writer.WriteSegment(ctx, index, uint64(len(data)), crc)
		require.NoError(t, err, "write segment %d failed", index)
		var totalBytes []byte
		totalBytes = append(totalBytes, bytes...)
		totalBytes = append(totalBytes, data...)
		segmentBytes[index] = totalBytes
	}

	// Assemble full file in final (ascending) order regardless of write order
	var allBytes []byte
	for _, index := range finalOrder {
		allBytes = append(allBytes, segmentBytes[index]...)
	}

	finalBytes, err := writer.Finalize(ctx, manifest)
	require.NoError(t, err, "finalize failed")
	allBytes = append(allBytes, finalBytes...)

	zipReader, err := zip.NewReader(bytes.NewReader(allBytes), int64(len(allBytes)))
	require.NoError(t, err, "zip should open")
	assert.Len(t, zipReader.File, 2)

	payloadFile := findFileByName(zipReader, "0.payload")
	require.NotNil(t, payloadFile)
	r, err := payloadFile.Open()
	require.NoError(t, err)
	defer r.Close()
	payloadContent, err := io.ReadAll(r)
	require.NoError(t, err)

	expected := []byte{}
	for _, index := range finalOrder {
		expected = append(expected, testSegments[index]...)
	}
	assert.Equal(t, expected, payloadContent)
}

func TestSegmentWriter_DuplicateSegments(t *testing.T) {
	// Test error handling for duplicate segments
	writer := NewSegmentTDFWriter(3)
	ctx := t.Context()

	// Write segment 1 twice
	_, err := writer.WriteSegment(ctx, 1, 10, crc32.ChecksumIEEE([]byte("first write")))
	require.NoError(t, err, "First write of segment 1 should succeed")

	_, err = writer.WriteSegment(ctx, 1, 10, crc32.ChecksumIEEE([]byte("second write")))
	require.Error(t, err, "Duplicate segment should fail")
	assert.Contains(t, err.Error(), "duplicate", "Error should mention duplicate")

	writer.Close()
}

func TestSegmentWriter_InvalidSegmentIndex(t *testing.T) {
	// Test error handling for invalid segment indices
	writer := NewSegmentTDFWriter(3)
	ctx := t.Context()

	// Only negative indices should be invalid - large indices are allowed for dynamic expansion
	testCases := []struct {
		name  string
		index int
	}{
		{"negative index", -1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := writer.WriteSegment(ctx, tc.index, 10, crc32.ChecksumIEEE([]byte("test")))
			require.Error(t, err, "Negative segment index should fail")
			assert.Contains(t, err.Error(), "invalid", "Error should mention invalid")
		})
	}

	// Test that large indices are actually allowed (dynamic expansion)
	t.Run("large_index_allowed", func(t *testing.T) {
		_, err := writer.WriteSegment(ctx, 100, 10, crc32.ChecksumIEEE([]byte("large index")))
		require.NoError(t, err, "Large segment index should be allowed for dynamic expansion")
	})

	writer.Close()
}

func TestSegmentWriter_AllowsGapsOnFinalize(t *testing.T) {
	// Finalize should succeed with gaps; order is inferred by sorting present indices
	writer := NewSegmentTDFWriter(1)
	ctx := t.Context()

	// Write only segments 0, 1, 3 (2 is missing)
	_, err := writer.WriteSegment(ctx, 0, 5, crc32.ChecksumIEEE([]byte("first")))
	require.NoError(t, err)

	_, err = writer.WriteSegment(ctx, 1, 6, crc32.ChecksumIEEE([]byte("second")))
	require.NoError(t, err)

	_, err = writer.WriteSegment(ctx, 3, 5, crc32.ChecksumIEEE([]byte("fourth")))
	require.NoError(t, err)

	// Finalize should succeed (auto-dense behavior)
	finalBytes, err := writer.Finalize(ctx, []byte("manifest"))
	require.NoError(t, err, "Finalize should succeed with sparse indices")
	assert.NotEmpty(t, finalBytes, "Finalize should return trailer bytes")

	writer.Close()
}

func TestSegmentWriter_CleanupSegment(t *testing.T) {
	// Test memory cleanup functionality
	writer := NewSegmentTDFWriter(3)
	ctx := t.Context()

	testData := []byte("test data for cleanup")

	// Write a segment
	_, err := writer.WriteSegment(ctx, 1, uint64(len(testData)), crc32.ChecksumIEEE(testData))
	require.NoError(t, err)

	// Verify segment exists before cleanup
	segWriter, ok := writer.(*segmentWriter)
	require.True(t, ok, "writer should be a segmentWriter")
	_, exists := segWriter.metadata.Segments[1]
	assert.True(t, exists, "Segment should exist before cleanup")

	// Cleanup segment
	err = writer.CleanupSegment(1)
	require.NoError(t, err)

	// Verify segment is cleaned up
	_, exists = segWriter.metadata.Segments[1]
	assert.False(t, exists, "Segment should be cleaned up")

	writer.Close()
}

func TestSegmentWriter_ContextCancellation(t *testing.T) {
	// Test context cancellation handling
	writer := NewSegmentTDFWriter(3)

	// Create cancelled context
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// Try to write segment with cancelled context
	_, err := writer.WriteSegment(ctx, 0, 10, crc32.ChecksumIEEE([]byte("data")))
	require.Error(t, err, "Should fail with cancelled context")
	assert.Contains(t, err.Error(), "context", "Error should mention context")

	writer.Close()
}

func TestSegmentWriter_LargeNumberOfSegments(t *testing.T) {
	// Test with a larger number of segments
	segmentCount := 100
	writer := NewSegmentTDFWriter(segmentCount, WithMaxSegments(200))
	ctx := t.Context()

	// Generate test data
	testSegments := make([][]byte, segmentCount)
	for i := 0; i < segmentCount; i++ {
		testSegments[i] = []byte(fmt.Sprintf("Segment %d data", i))
	}

	// Write all segments in reverse order
	for i := segmentCount - 1; i >= 0; i-- {
		_, err := writer.WriteSegment(ctx, i, uint64(len(testSegments[i])), crc32.ChecksumIEEE(testSegments[i]))
		require.NoError(t, err, "Failed to write segment %d", i)
	}

	// Finalize
	finalBytes, err := writer.Finalize(ctx, []byte(`{"large_segment_test": true}`))
	require.NoError(t, err, "Should finalize large number of segments")

	writer.Close()

	// Basic validation - don't parse ZIP for performance in large test
	assert.Greater(t, len(finalBytes), 100, "Final bytes should be substantial")
}

func TestSegmentWriter_EmptySegments(t *testing.T) {
	// Test handling of empty segments
	writer := NewSegmentTDFWriter(3)
	ctx := t.Context()

	// Write segments with empty data
	_, err := writer.WriteSegment(ctx, 0, 0, 0)
	require.NoError(t, err, "Should handle empty segment 0")

	_, err = writer.WriteSegment(ctx, 1, 10, crc32.ChecksumIEEE([]byte("not empty")))
	require.NoError(t, err, "Should handle non-empty segment")

	_, err = writer.WriteSegment(ctx, 2, 0, 0)
	require.NoError(t, err, "Should handle empty segment 2")

	// Finalize
	finalBytes, err := writer.Finalize(ctx, []byte("manifest"))
	require.NoError(t, err, "Should finalize with empty segments")
	assert.NotEmpty(t, finalBytes, "Should have final bytes")

	writer.Close()
}

// Helper function to find a file by name in ZIP reader
func findFileByName(zipReader *zip.Reader, name string) *zip.File { //nolint:unparam // used with constant names in tests
	for _, file := range zipReader.File {
		if file.Name == name {
			return file
		}
	}
	return nil
}

// Benchmark tests
func BenchmarkSegmentWriter_Sequential(b *testing.B) {
	benchmarkSegmentWriter(b, "sequential", []int{0, 1, 2, 3, 4})
}

func BenchmarkSegmentWriter_OutOfOrder(b *testing.B) {
	benchmarkSegmentWriter(b, "out-of-order", []int{2, 0, 4, 1, 3})
}

func benchmarkSegmentWriter(b *testing.B, name string, writeOrder []int) {
	b.Run(name, func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			writer := NewSegmentTDFWriter(5)
			ctx := b.Context()

			testSegments := [][]byte{
				make([]byte, 1024), // 1KB segments
				make([]byte, 1024),
				make([]byte, 1024),
				make([]byte, 1024),
				make([]byte, 1024),
			}

			// Fill with test data
			for j, data := range testSegments {
				for k := range data {
					data[k] = byte(j)
				}
			}

			// Write segments in specified order
			for _, index := range writeOrder {
				data := testSegments[index]
				crc := crc32.ChecksumIEEE(data)
				_, err := writer.WriteSegment(ctx, index, uint64(len(data)), crc)
				if err != nil {
					b.Fatal(err)
				}
			}

			// Finalize
			_, err := writer.Finalize(ctx, []byte("benchmark manifest"))
			if err != nil {
				b.Fatal(err)
			}

			writer.Close()
		}
	})
}
