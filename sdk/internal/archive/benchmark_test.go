package archive

import (
	"context"
	"testing"
)

// BenchmarkSegmentWriter_CRC32ContiguousProcessing tests CRC32 processing performance
func BenchmarkSegmentWriter_CRC32ContiguousProcessing(b *testing.B) {
	testCases := []struct {
		name         string
		segmentCount int
		segmentSize  int
		writeOrder   string
	}{
		{"sequential_100x1KB", 100, 1024, "sequential"},
		{"reverse_100x1KB", 100, 1024, "reverse"},
		{"random_100x1KB", 100, 1024, "random"},
		{"interleaved_100x1KB", 100, 1024, "interleaved"},
		{"worst_case_100x1KB", 100, 1024, "worst_case"},
		{"sequential_1000x1KB", 1000, 1024, "sequential"},
		{"reverse_1000x1KB", 1000, 1024, "reverse"},
		{"worst_case_1000x1KB", 1000, 1024, "worst_case"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Generate write order based on pattern
			writeOrder := generateWriteOrder(tc.segmentCount, tc.writeOrder)
			
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer := NewSegmentTDFWriter(tc.segmentCount)
				ctx := context.Background()

				// Create test segment data
				segmentData := make([]byte, tc.segmentSize)
				for j := range segmentData {
					segmentData[j] = byte(j % 256)
				}

				// Write segments in specified order
				for _, segIdx := range writeOrder {
					_, err := writer.WriteSegment(ctx, segIdx, segmentData)
					if err != nil {
						b.Fatal(err)
					}
				}

				// Finalize to trigger final CRC32 calculation
				manifest := []byte(`{"test": "benchmark"}`)
				_, err := writer.Finalize(ctx, manifest)
				if err != nil {
					b.Fatal(err)
				}

				writer.Close()
			}
		})
	}
}

// BenchmarkSegmentWriter_VariableSegmentSizes tests performance with variable segment sizes
func BenchmarkSegmentWriter_VariableSegmentSizes(b *testing.B) {
	testCases := []struct {
		name  string
		sizes []int
	}{
		{"uniform_1KB", []int{1024, 1024, 1024, 1024, 1024}},
		{"doubling", []int{512, 1024, 2048, 4096, 8192}},
		{"extreme_variance", []int{100, 10240, 200, 20480, 300}},
		{"fibonacci_like", []int{256, 512, 768, 1280, 2048}},
		{"large_mixed", []int{1024, 16384, 4096, 32768, 8192}},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer := NewSegmentTDFWriter(len(tc.sizes))
				ctx := context.Background()

				// Write segments with variable sizes
				for segIdx, size := range tc.sizes {
					segmentData := make([]byte, size)
					for j := range segmentData {
						segmentData[j] = byte((segIdx*j) % 256)
					}

					_, err := writer.WriteSegment(ctx, segIdx, segmentData)
					if err != nil {
						b.Fatal(err)
					}
				}

				// Finalize
				manifest := []byte(`{"variable_sizes": true}`)
				_, err := writer.Finalize(ctx, manifest)
				if err != nil {
					b.Fatal(err)
				}

				writer.Close()
			}
		})
	}
}

// BenchmarkSegmentWriter_MemoryPressure tests memory usage under various scenarios  
func BenchmarkSegmentWriter_MemoryPressure(b *testing.B) {
	testCases := []struct {
		name         string
		segmentCount int
		segmentSize  int
		bufferPolicy string
	}{
		{"small_segments_sequential", 1000, 512, "sequential"},
		{"small_segments_reverse", 1000, 512, "reverse"},
		{"small_segments_worst_case", 1000, 512, "worst_case"},
		{"large_segments_sequential", 100, 8192, "sequential"},
		{"large_segments_reverse", 100, 8192, "reverse"},
		{"large_segments_interleaved", 100, 8192, "interleaved"},
		{"mixed_sizes_random", 500, 0, "mixed"}, // 0 = variable sizes
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			writeOrder := generateWriteOrder(tc.segmentCount, tc.bufferPolicy)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer := NewSegmentTDFWriter(tc.segmentCount, WithMaxSegments(tc.segmentCount*2))
				ctx := context.Background()

				// Write segments with focus on memory allocation patterns
				for orderIdx, segIdx := range writeOrder {
					var segmentData []byte
					
					if tc.segmentSize == 0 { // Mixed sizes mode
						size := 512 + (segIdx%8)*512 // Sizes from 512 to 4096
						segmentData = make([]byte, size)
					} else {
						segmentData = make([]byte, tc.segmentSize)
					}

					// Fill with deterministic test data
					for j := range segmentData {
						segmentData[j] = byte((orderIdx*j) % 256)
					}

					_, err := writer.WriteSegment(ctx, segIdx, segmentData)
					if err != nil {
						b.Fatal(err)
					}
				}

				// Finalize
				manifest := []byte(`{"memory_test": true}`)
				_, err := writer.Finalize(ctx, manifest)
				if err != nil {
					b.Fatal(err)
				}

				writer.Close()
			}
		})
	}
}

// BenchmarkSegmentWriter_ZIPGeneration tests ZIP structure generation performance
func BenchmarkSegmentWriter_ZIPGeneration(b *testing.B) {
	testCases := []struct {
		name         string
		segmentCount int
		segmentSize  int
		useZip64     bool
	}{
		{"zip32_small", 10, 1024, false},
		{"zip32_large", 100, 1024, false},
		{"zip64_small", 10, 1024, true},
		{"zip64_large", 100, 1024, true},
		{"zip64_huge_segments", 5, 65536, true}, // Large segments requiring ZIP64
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			options := make([]Option, 0)
			if tc.useZip64 {
				options = append(options, WithZip64())
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer := NewSegmentTDFWriter(tc.segmentCount, options...)
				ctx := context.Background()

				// Create test segment data
				segmentData := make([]byte, tc.segmentSize)
				for j := range segmentData {
					segmentData[j] = byte(j % 256)
				}

				// Write all segments
				for segIdx := 0; segIdx < tc.segmentCount; segIdx++ {
					_, err := writer.WriteSegment(ctx, segIdx, segmentData)
					if err != nil {
						b.Fatal(err)
					}
				}

				// Focus benchmark on finalization (ZIP generation)
				manifest := []byte(`{"zip_generation_test": true}`)
				_, err := writer.Finalize(ctx, manifest)
				if err != nil {
					b.Fatal(err)
				}

				writer.Close()
			}
		})
	}
}

// generateWriteOrder creates segment write orders for different test patterns
func generateWriteOrder(count int, pattern string) []int {
	order := make([]int, count)
	
	switch pattern {
	case "sequential":
		for i := 0; i < count; i++ {
			order[i] = i
		}
	case "reverse":
		for i := 0; i < count; i++ {
			order[i] = count - 1 - i
		}
	case "interleaved":
		// Interleaved pattern: 0,2,4,6...1,3,5,7... (moderate out-of-order)
		idx := 0
		// First pass: even indices
		for i := 0; i < count; i += 2 {
			if idx < count {
				order[idx] = i
				idx++
			}
		}
		// Second pass: odd indices  
		for i := 1; i < count; i += 2 {
			if idx < count {
				order[idx] = i
				idx++
			}
		}
	case "worst_case":
		// Worst case: completely scattered pattern that maximizes memory buffering
		// Pattern: middle-out then random to stress contiguous processing
		mid := count / 2
		order[0] = mid
		left, right := mid-1, mid+1
		idx := 1
		
		// Alternate left and right from middle
		for left >= 0 || right < count {
			if left >= 0 && idx < count {
				order[idx] = left
				idx++
				left--
			}
			if right < count && idx < count {
				order[idx] = right
				idx++
				right++
			}
		}
	case "random", "mixed":
		// Generate pseudo-random but deterministic pattern for consistent benchmarks
		for i := 0; i < count; i++ {
			// Simple deterministic pseudo-random: use modular arithmetic
			order[i] = (i*17 + 7) % count
		}
		// Ensure all indices are covered
		used := make(map[int]bool)
		result := make([]int, 0, count)
		for _, idx := range order {
			if !used[idx] {
				result = append(result, idx)
				used[idx] = true
			}
		}
		// Fill in any missing indices
		for i := 0; i < count; i++ {
			if !used[i] {
				result = append(result, i)
			}
		}
		return result
	default:
		// Default to sequential
		for i := 0; i < count; i++ {
			order[i] = i
		}
	}
	
	return order
}