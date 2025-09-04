package sdk

import (
	"testing"
)

// BenchmarkStreamingWriter_Sequential tests sequential segment writing performance
func BenchmarkStreamingWriter_Sequential(b *testing.B) {
	testCases := []struct {
		name         string
		segmentCount int
		segmentSize  int
	}{
		{"10segments_1KB", 10, 1024},
		{"10segments_10KB", 10, 10240},
		{"100segments_1KB", 100, 1024},
		{"100segments_10KB", 100, 10240},
		{"1000segments_1KB", 1000, 1024},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			sdk, cleanup := setupMockKASServer(b)
			defer cleanup()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer, err := sdk.NewStreamingWriter(b.Context())
				if err != nil {
					b.Fatal(err)
				}

				// Create test segment data
				segmentData := make([]byte, tc.segmentSize)
				for j := range segmentData {
					segmentData[j] = byte(j % 256)
				}

				// Write segments sequentially
				for segIdx := 0; segIdx < tc.segmentCount; segIdx++ {
					_, err := writer.WriteSegment(b.Context(), segIdx, segmentData)
					if err != nil {
						b.Fatal(err)
					}
				}

				// Finalize
				_, err = writer.Finalize(b.Context(), []string{})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStreamingWriter_OutOfOrder tests out-of-order segment writing performance
func BenchmarkStreamingWriter_OutOfOrder(b *testing.B) {
	testCases := []struct {
		name         string
		segmentCount int
		segmentSize  int
	}{
		{"10segments_1KB", 10, 1024},
		{"100segments_1KB", 100, 1024},
		{"1000segments_1KB", 1000, 1024},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			sdk, cleanup := setupMockKASServer(b)
			defer cleanup()

			// Generate out-of-order write sequence (reverse order for worst case)
			writeOrder := make([]int, tc.segmentCount)
			for i := 0; i < tc.segmentCount; i++ {
				writeOrder[i] = tc.segmentCount - 1 - i
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer, err := sdk.NewStreamingWriter(b.Context())
				if err != nil {
					b.Fatal(err)
				}

				// Create test segment data
				segmentData := make([]byte, tc.segmentSize)
				for j := range segmentData {
					segmentData[j] = byte(j % 256)
				}

				// Write segments in reverse order (worst case for memory usage)
				for _, segIdx := range writeOrder {
					_, err := writer.WriteSegment(b.Context(), segIdx, segmentData)
					if err != nil {
						b.Fatal(err)
					}
				}

				// Finalize
				_, err = writer.Finalize(b.Context(), []string{})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStreamingWriter_VariableSegmentSizes tests performance with different segment sizes
func BenchmarkStreamingWriter_VariableSegmentSizes(b *testing.B) {
	sdk, cleanup := setupMockKASServer(b)
	defer cleanup()

	testCases := []struct {
		name    string
		sizes   []int
		pattern string
	}{
		{"mixed_small", []int{100, 500, 200, 800, 300}, "mixed small sizes"},
		{"mixed_large", []int{1024, 8192, 2048, 16384, 4096}, "mixed large sizes"},
		{"extreme_variance", []int{10, 10240, 50, 20480, 100}, "extreme size variance"},
		{"doubling_pattern", []int{512, 1024, 2048, 4096, 8192}, "doubling pattern"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer, err := sdk.NewStreamingWriter(b.Context())
				if err != nil {
					b.Fatal(err)
				}

				// Write segments with variable sizes
				for segIdx, size := range tc.sizes {
					segmentData := make([]byte, size)
					for j := range segmentData {
						segmentData[j] = byte((segIdx * j) % 256)
					}

					_, err := writer.WriteSegment(b.Context(), segIdx, segmentData)
					if err != nil {
						b.Fatal(err)
					}
				}

				// Finalize
				_, err = writer.Finalize(b.Context(), []string{})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkStreamingWriter_MemoryUsagePattern tests memory allocation patterns
func BenchmarkStreamingWriter_MemoryUsagePattern(b *testing.B) {
	sdk, cleanup := setupMockKASServer(b)
	defer cleanup()

	b.Run("memory_pressure", func(b *testing.B) {
		segmentCount := 50
		segmentSize := 2048

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			writer, err := sdk.NewStreamingWriter(b.Context())
			if err != nil {
				b.Fatal(err)
			}

			// Create reusable segment data to focus on writer allocation patterns
			segmentData := make([]byte, segmentSize)
			for j := range segmentData {
				segmentData[j] = byte(j % 256)
			}

			// Write segments in worst-case order (completely reverse)
			for segIdx := segmentCount - 1; segIdx >= 0; segIdx-- {
				_, err := writer.WriteSegment(b.Context(), segIdx, segmentData)
				if err != nil {
					b.Fatal(err)
				}
			}

			// Finalize
			_, err = writer.Finalize(b.Context(), []string{})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkStreamingWriter_AttributeFetching tests attribute resolution performance
func BenchmarkStreamingWriter_AttributeFetching(b *testing.B) {
	sdk, cleanup := setupMockKASServer(b)
	defer cleanup()

	testCases := []struct {
		name           string
		attributeCount int
	}{
		{"no_attributes", 0},
		{"single_attribute", 1},
		{"multiple_attributes", 5},
		{"many_attributes", 20},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Create test attributes
			attributes := make([]string, tc.attributeCount)
			for i := 0; i < tc.attributeCount; i++ {
				attributes[i] = "https://example.com/attr/test/value/" + string(rune('A'+i))
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer, err := sdk.NewStreamingWriter(b.Context())
				if err != nil {
					b.Fatal(err)
				}

				// Write a single test segment
				testData := make([]byte, 1024)
				_, err = writer.WriteSegment(b.Context(), 0, testData)
				if err != nil {
					b.Fatal(err)
				}

				// Finalize with attributes (this triggers attribute fetching)
				_, err = writer.Finalize(b.Context(), attributes)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
