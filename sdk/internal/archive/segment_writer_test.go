package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
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
		segmentBytes, err := writer.WriteSegment(ctx, i, data)
		require.NoError(t, err, "Failed to write segment %d", i)
		assert.NotEmpty(t, segmentBytes, "Segment %d should have bytes", i)

		t.Logf("Sequential segment %d: %d bytes", i, len(segmentBytes))

		if i == 0 {
			// Segment 0 should be larger due to ZIP header
			assert.Greater(t, len(segmentBytes), len(data), "Segment 0 should include ZIP header")
		} else {
			// Other segments should be approximately the size of the data
			assert.Len(t, data, len(segmentBytes), "Segment %d should be raw data", i)
		}

		allBytes = append(allBytes, segmentBytes...)
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
	writer := NewSegmentTDFWriter(5, WithZip64())
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
		bytes, err := writer.WriteSegment(ctx, index, data)
		require.NoError(t, err, "Failed to write segment %d out of order", index)
		assert.NotEmpty(t, bytes, "Segment %d should have bytes", index)

		if index == 0 {
			// Segment 0 should always include ZIP header, regardless of write order
			assert.Greater(t, len(bytes), len(data), "Segment 0 should include ZIP header even when written out of order")
		}

		segmentBytes[index] = bytes
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

	// Debug: write bytes to temporary file for inspection
	if err := os.WriteFile("/tmp/debug_out_of_order.zip", allBytes, 0o644); err == nil {
		t.Logf("Debug ZIP written to /tmp/debug_out_of_order.zip")
	}

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

func TestSegmentWriter_DuplicateSegments(t *testing.T) {
	// Test error handling for duplicate segments
	writer := NewSegmentTDFWriter(3)
	ctx := t.Context()

	// Write segment 1 twice
	_, err := writer.WriteSegment(ctx, 1, []byte("first"))
	require.NoError(t, err, "First write of segment 1 should succeed")

	_, err = writer.WriteSegment(ctx, 1, []byte("duplicate"))
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
			_, err := writer.WriteSegment(ctx, tc.index, []byte("test"))
			require.Error(t, err, "Negative segment index should fail")
			assert.Contains(t, err.Error(), "invalid", "Error should mention invalid")
		})
	}

	// Test that large indices are actually allowed (dynamic expansion)
	t.Run("large_index_allowed", func(t *testing.T) {
		_, err := writer.WriteSegment(ctx, 100, []byte("test"))
		require.NoError(t, err, "Large segment index should be allowed for dynamic expansion")
	})

	writer.Close()
}

func TestSegmentWriter_IncompleteSegments(t *testing.T) {
	// Test error handling when trying to finalize with missing segments
	writer := NewSegmentTDFWriter(5)
	ctx := t.Context()

	// Write only segments 0, 1, 3 (missing 2 and 4)
	_, err := writer.WriteSegment(ctx, 0, []byte("first"))
	require.NoError(t, err)

	_, err = writer.WriteSegment(ctx, 1, []byte("second"))
	require.NoError(t, err)

	_, err = writer.WriteSegment(ctx, 3, []byte("fourth"))
	require.NoError(t, err)

	// Try to finalize - should fail
	_, err = writer.Finalize(ctx, []byte("manifest"))
	require.Error(t, err, "Finalize should fail with missing segments")
	assert.Contains(t, err.Error(), "missing", "Error should mention missing segments")

	writer.Close()
}

func TestSegmentWriter_CleanupSegment(t *testing.T) {
	// Test memory cleanup functionality
	writer := NewSegmentTDFWriter(3)
	ctx := t.Context()

	testData := []byte("test data for cleanup")

	// Write a segment
	_, err := writer.WriteSegment(ctx, 1, testData)
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
	_, err := writer.WriteSegment(ctx, 0, []byte("test"))
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

	var allBytes []byte

	// Write all segments in reverse order
	for i := segmentCount - 1; i >= 0; i-- {
		bytes, err := writer.WriteSegment(ctx, i, testSegments[i])
		require.NoError(t, err, "Failed to write segment %d", i)

		// Store in logical order for final assembly
		if i == 0 {
			allBytes = append([]byte{}, bytes...) // Segment 0 goes first
			for j := 1; j < segmentCount; j++ {
				allBytes = append(allBytes, make([]byte, 0)...) // Placeholder
			}
		} else {
			// This is simplified - in practice you'd need proper ordering
			allBytes = append(allBytes, bytes...)
		}
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
	_, err := writer.WriteSegment(ctx, 0, []byte(""))
	require.NoError(t, err, "Should handle empty segment 0")

	_, err = writer.WriteSegment(ctx, 1, []byte("non-empty"))
	require.NoError(t, err, "Should handle non-empty segment")

	_, err = writer.WriteSegment(ctx, 2, []byte(""))
	require.NoError(t, err, "Should handle empty segment 2")

	// Finalize
	finalBytes, err := writer.Finalize(ctx, []byte("manifest"))
	require.NoError(t, err, "Should finalize with empty segments")
	assert.NotEmpty(t, finalBytes, "Should have final bytes")

	writer.Close()
}

// Helper function to find a file by name in ZIP reader
func findFileByName(zipReader *zip.Reader, name string) *zip.File {
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
				_, err := writer.WriteSegment(ctx, index, testSegments[index])
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
