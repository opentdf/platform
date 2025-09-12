package archive

import (
	"testing"
)

// BenchmarkSegmentWriter_CRC32ContiguousProcessing benchmarks CRC32-related performance under
// different segment write ordering patterns. The current implementation uses CRC32-combine over
// per-segment CRCs and sizes and does not retain payload bytes between calls.
//
// Test patterns:
//   - sequential: Optimal case where segments arrive in order (enables immediate processing)
//   - reverse: Worst case where all segments must be buffered until the end
//   - random: Pseudo-random order using deterministic pattern for reproducible results
//   - interleaved: Moderate out-of-order (even indices first, then odd)
//   - worst_case: Middle-out pattern that maximizes memory buffering requirements
//
// Measures: CRC32 calculation speed, memory allocation patterns, contiguous processing effectiveness
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
				ctx := b.Context()

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

// BenchmarkSegmentWriter_VariableSegmentSizes benchmarks performance impact of variable segment sizes
// on memory allocation and CRC32 processing efficiency.
//
// This benchmark tests how the segment writer handles dynamic memory allocation when segments have
// unpredictable sizes. Variable sizes can impact both memory allocation patterns and CRC32 processing
// efficiency, as larger segments require more memory and processing time.
//
// Test patterns:
//   - uniform_1KB: Baseline with consistent 1KB segments for comparison
//   - doubling: Exponentially increasing sizes (512B → 8KB) to test scaling
//   - extreme_variance: Mixed small/large segments to stress memory allocator
//   - fibonacci_like: Fibonacci-inspired progression for gradual size increases
//   - large_mixed: Various large segments to test high memory usage patterns
//
// Measures: Memory allocation efficiency, CRC32 processing with varying data volumes, GC impact
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
				ctx := b.Context()

				// Write segments with variable sizes
				for segIdx, size := range tc.sizes {
					segmentData := make([]byte, size)
					for j := range segmentData {
						segmentData[j] = byte((segIdx * j) % 256)
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

// BenchmarkSegmentWriter_MemoryPressure benchmarks memory allocation patterns and buffering efficiency
// under various segment count and size combinations.
//
// This benchmark specifically targets memory allocation behavior to identify potential memory leaks,
// inefficient buffering strategies, and garbage collection impact. It uses WithMaxSegments(count*2)
// to allow extra buffering capacity and tests different buffer policies.
//
// Test scenarios:
//   - small_segments: High segment count (1000) with minimal individual memory (512B each)
//   - large_segments: Fewer segments (100) with larger memory footprint (8KB each)
//   - mixed_sizes: Dynamic sizes from 512B to 4KB based on segment index modulo
//
// Write patterns test memory behavior:
//   - sequential: Minimal buffering, immediate processing and cleanup
//   - reverse: Maximum buffering until all segments received
//   - interleaved: Moderate buffering with periodic cleanup opportunities
//   - worst_case: Scattered pattern maximizing memory retention
//
// Measures: Peak memory usage, allocation patterns, buffer cleanup efficiency, GC pressure
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
				ctx := b.Context()

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
						segmentData[j] = byte((orderIdx * j) % 256)
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

// BenchmarkSegmentWriter_ZIPGeneration benchmarks ZIP archive structure generation performance,
// focusing on the finalization process where the complete ZIP structure is assembled.
//
// This benchmark measures the overhead of generating ZIP format structures including local file headers,
// central directory records, and data descriptors. It compares ZIP32 vs ZIP64 performance and tests
// the final assembly process during Finalize() calls.
//
// Test scenarios:
//   - zip32_small/large: Standard ZIP format (supports files <4GB) with varying segment counts
//   - zip64_small/large: ZIP64 format (handles >4GB files) with extended headers
//   - zip64_huge_segments: Large 64KB segments that require ZIP64 format
//
// The benchmark focuses on finalization overhead including:
//   - Data descriptor generation for streaming entries
//   - Central directory assembly with file metadata
//   - ZIP64 extended information extra fields when needed
//   - Final ZIP structure validation and writing
//
// Measures: ZIP structure generation speed, ZIP32 vs ZIP64 overhead, finalization efficiency
func BenchmarkSegmentWriter_ZIPGeneration(b *testing.B) {
	testCases := []struct {
		name         string
		segmentCount int
		segmentSize  int
		zip64Mode    Zip64Mode
	}{
		{"zip32_small", 10, 1024, Zip64Never},
		{"zip32_large", 100, 1024, Zip64Never},
		{"zip64_small", 10, 1024, Zip64Always},
		{"zip64_large", 100, 1024, Zip64Always},
		{"zip64_huge_segments", 5, 65536, Zip64Auto}, // Auto triggers ZIP64 by size
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			options := []Option{WithZip64Mode(tc.zip64Mode)}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				writer := NewSegmentTDFWriter(tc.segmentCount, options...)
				ctx := b.Context()

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

// generateWriteOrder creates deterministic segment write orders for consistent benchmark testing.
//
// This function generates various write patterns to test different aspects of the segment writer's
// performance characteristics. All patterns are deterministic to ensure reproducible benchmark results.
//
// Supported patterns:
//   - "sequential": Natural order (0,1,2,3...)
//   - "reverse": Backward order (...3,2,1,0)
//   - "interleaved": Even indices first (0,2,4...), then odd (1,3,5...) - moderate out-of-order
//   - "worst_case": Middle-out pattern starting from center, alternating left/right - maximizes buffering
//   - "random"/"mixed": Pseudo-random using modular arithmetic (i*17+7)%count for deterministic chaos
//
// The patterns are designed to stress different aspects:
//   - Memory usage patterns
//   - Processing efficiency
//   - Cache locality (how segments are accessed in memory)
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
		// A scattered pattern that stresses segment bookkeeping
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
