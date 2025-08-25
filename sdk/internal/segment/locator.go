package segment

import (
	"errors"
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/opentdf/platform/sdk/tdf"
)

const (
	// DefaultCacheSize is the default LRU cache size for segment lookups
	DefaultCacheSize = 128
	// PercentageBase is used for calculating percentages
	PercentageBase = 100.0
)

var (
	ErrOffsetOutOfRange = errors.New("offset out of range")
	ErrSegmentNotFound  = errors.New("segment not found")
	ErrInvalidRange     = errors.New("invalid range specified")
)

// SegmentInfo contains metadata for a single segment
type SegmentInfo struct {
	Index            int    // Segment index
	PlaintextSize    int64  // Unencrypted size
	EncryptedSize    int64  // Encrypted size (with IV + auth tag)
	CumulativeOffset int64  // Cumulative offset in plaintext
	FileOffset       int64  // Physical offset in TDF file
	Hash             string // Integrity hash
}

// SegmentLocator provides an abstraction for finding segments by offset
// This enables support for both uniform and variable-length segments
type SegmentLocator interface {
	// FindSegmentByOffset finds the segment containing the given offset
	FindSegmentByOffset(offset int64) (*SegmentInfo, error)

	// GetSegmentRange returns segments that overlap with the given range
	GetSegmentRange(start, end int64) ([]SegmentInfo, error)

	// GetTotalSize returns the total unencrypted payload size
	GetTotalSize() int64

	// GetSegmentCount returns the number of segments
	GetSegmentCount() int
}

// UniformSegmentLocator provides O(1) lookup for uniform-sized segments
// This maintains backward compatibility and optimal performance for existing TDFs
type UniformSegmentLocator struct {
	segmentSize int64
	segments    []tdf.Segment
	totalSize   int64
	fileOffsets []int64 // Physical offsets in TDF file
}

// NewUniformSegmentLocator creates a locator for uniform segments
func NewUniformSegmentLocator(segmentSize int64, segments []tdf.Segment) *UniformSegmentLocator {
	locator := &UniformSegmentLocator{
		segmentSize: segmentSize,
		segments:    segments,
		fileOffsets: make([]int64, len(segments)),
	}

	// Calculate total size and file offsets
	var fileOffset int64
	for i, seg := range segments {
		locator.totalSize += seg.Size
		locator.fileOffsets[i] = fileOffset
		fileOffset += seg.EncryptedSize
	}

	return locator
}

func (u *UniformSegmentLocator) FindSegmentByOffset(offset int64) (*SegmentInfo, error) {
	if offset < 0 || offset >= u.totalSize {
		return nil, fmt.Errorf("%w: offset %d not in range [0, %d)", ErrOffsetOutOfRange, offset, u.totalSize)
	}

	// O(1) division-based lookup for uniform segments
	segmentIndex := int(offset / u.segmentSize)
	if segmentIndex >= len(u.segments) {
		segmentIndex = len(u.segments) - 1
	}

	seg := u.segments[segmentIndex]
	return &SegmentInfo{
		Index:            segmentIndex,
		PlaintextSize:    seg.Size,
		EncryptedSize:    seg.EncryptedSize,
		CumulativeOffset: int64(segmentIndex) * u.segmentSize,
		FileOffset:       u.fileOffsets[segmentIndex],
		Hash:             seg.Hash,
	}, nil
}

func (u *UniformSegmentLocator) GetSegmentRange(start, end int64) ([]SegmentInfo, error) {
	if start < 0 || end <= start || start >= u.totalSize {
		return nil, fmt.Errorf("%w: invalid range [%d, %d)", ErrInvalidRange, start, end)
	}

	startSegment := int(start / u.segmentSize)
	endSegment := int((end + u.segmentSize - 1) / u.segmentSize)
	if endSegment > len(u.segments) {
		endSegment = len(u.segments)
	}

	result := make([]SegmentInfo, 0, endSegment-startSegment)
	for i := startSegment; i < endSegment; i++ {
		seg := u.segments[i]
		result = append(result, SegmentInfo{
			Index:            i,
			PlaintextSize:    seg.Size,
			EncryptedSize:    seg.EncryptedSize,
			CumulativeOffset: int64(i) * u.segmentSize,
			FileOffset:       u.fileOffsets[i],
			Hash:             seg.Hash,
		})
	}

	return result, nil
}

func (u *UniformSegmentLocator) GetTotalSize() int64 {
	return u.totalSize
}

func (u *UniformSegmentLocator) GetSegmentCount() int {
	return len(u.segments)
}

// VariableSegmentLocator provides O(log n) lookup for variable-sized segments
type VariableSegmentLocator struct {
	offsetTable *SegmentOffsetTable
}

// NewVariableSegmentLocator creates a locator for variable-length segments
func NewVariableSegmentLocator(segments []tdf.Segment) *VariableSegmentLocator {
	offsetTable := &SegmentOffsetTable{
		cumulativeOffsets: make([]int64, len(segments)),
		segments:          make([]SegmentInfo, len(segments)),
		cache:             NewSegmentCache(DefaultCacheSize),
	}

	// Build cumulative offset table and segment info
	var cumOffset int64
	var fileOffset int64

	for i, seg := range segments {
		offsetTable.cumulativeOffsets[i] = cumOffset
		offsetTable.segments[i] = SegmentInfo{
			Index:            i,
			PlaintextSize:    seg.Size,
			EncryptedSize:    seg.EncryptedSize,
			CumulativeOffset: cumOffset,
			FileOffset:       fileOffset,
			Hash:             seg.Hash,
		}
		cumOffset += seg.Size
		fileOffset += seg.EncryptedSize
	}

	offsetTable.totalSize = cumOffset

	return &VariableSegmentLocator{
		offsetTable: offsetTable,
	}
}

func (v *VariableSegmentLocator) FindSegmentByOffset(offset int64) (*SegmentInfo, error) {
	return v.offsetTable.FindSegmentByOffset(offset)
}

func (v *VariableSegmentLocator) GetSegmentRange(start, end int64) ([]SegmentInfo, error) {
	return v.offsetTable.GetSegmentRange(start, end)
}

func (v *VariableSegmentLocator) GetTotalSize() int64 {
	return v.offsetTable.totalSize
}

func (v *VariableSegmentLocator) GetSegmentCount() int {
	return len(v.offsetTable.segments)
}

// SegmentOffsetTable provides binary search on cumulative offsets
type SegmentOffsetTable struct {
	cumulativeOffsets []int64
	segments          []SegmentInfo
	cache             *SegmentCache
	totalSize         int64

	// Performance metrics
	lookupCount atomic.Uint64
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64
}

// FindSegmentByOffset finds the segment containing the given offset using binary search
func (sot *SegmentOffsetTable) FindSegmentByOffset(offset int64) (*SegmentInfo, error) {
	sot.lookupCount.Add(1)

	if offset < 0 || offset >= sot.totalSize {
		return nil, fmt.Errorf("%w: offset %d not in range [0, %d)", ErrOffsetOutOfRange, offset, sot.totalSize)
	}

	// Binary search on cumulative offsets to find which segment contains the offset
	// We want the largest index i where cumulativeOffsets[i] <= offset
	segmentIndex := sort.Search(len(sot.cumulativeOffsets), func(i int) bool {
		return sot.cumulativeOffsets[i] > offset
	})
	// sort.Search returns the first index where cumulativeOffsets[i] > offset,
	// so we want the previous index (which has cumulativeOffsets[i] <= offset)
	if segmentIndex > 0 {
		segmentIndex--
	}

	if segmentIndex >= len(sot.segments) {
		return nil, fmt.Errorf("%w: calculated index %d out of bounds", ErrSegmentNotFound, segmentIndex)
	}

	// Check cache first
	if cachedSeg, found := sot.cache.Get(segmentIndex); found {
		sot.cacheHits.Add(1)
		return cachedSeg, nil
	}

	// Cache miss - get segment info and cache it
	sot.cacheMisses.Add(1)
	segInfo := &sot.segments[segmentIndex]
	sot.cache.Put(segmentIndex, segInfo)

	return segInfo, nil
}

// GetSegmentRange returns segments that overlap with the given range
func (sot *SegmentOffsetTable) GetSegmentRange(start, end int64) ([]SegmentInfo, error) {
	if start < 0 || end <= start || start >= sot.totalSize {
		return nil, fmt.Errorf("%w: invalid range [%d, %d)", ErrInvalidRange, start, end)
	}

	startSegInfo, err := sot.FindSegmentByOffset(start)
	if err != nil {
		return nil, fmt.Errorf("finding start segment: %w", err)
	}

	endOffset := end - 1 // Convert to inclusive end
	if endOffset >= sot.totalSize {
		endOffset = sot.totalSize - 1
	}

	endSegInfo, err := sot.FindSegmentByOffset(endOffset)
	if err != nil {
		return nil, fmt.Errorf("finding end segment: %w", err)
	}

	// Return range of segments
	result := make([]SegmentInfo, 0, endSegInfo.Index-startSegInfo.Index+1)
	for i := startSegInfo.Index; i <= endSegInfo.Index; i++ {
		result = append(result, sot.segments[i])
	}

	return result, nil
}

// GetMetrics returns performance metrics for monitoring
func (sot *SegmentOffsetTable) GetMetrics() SegmentMetrics {
	return SegmentMetrics{
		LookupCount: sot.lookupCount.Load(),
		CacheHits:   sot.cacheHits.Load(),
		CacheMisses: sot.cacheMisses.Load(),
		CacheSize:   sot.cache.Size(),
	}
}

// SegmentMetrics contains performance metrics
type SegmentMetrics struct {
	LookupCount uint64
	CacheHits   uint64
	CacheMisses uint64
	CacheSize   int
}

// HitRate returns the cache hit rate as a percentage
func (sm SegmentMetrics) HitRate() float64 {
	total := sm.CacheHits + sm.CacheMisses
	if total == 0 {
		return 0.0
	}
	return float64(sm.CacheHits) / float64(total) * PercentageBase
}

// IsUniformSegments checks if all segments have the same size for optimization
// For streaming TDFs with variable segment lengths, this should return false
func IsUniformSegments(segments []tdf.Segment, defaultSize int64) bool {
	if len(segments) == 0 {
		return true
	}

	// If we have only one segment, it's technically uniform
	if len(segments) == 1 {
		return true
	}

	// For multiple segments to be considered uniform:
	// 1. All non-final segments must be exactly defaultSize
	// 2. The final segment must be exactly defaultSize OR smaller (partial segment)
	// 3. If any non-final segment differs from defaultSize, it's variable-length
	for i, seg := range segments {
		if i == len(segments)-1 {
			// Last segment may be smaller but not larger than defaultSize
			if seg.Size > defaultSize {
				return false
			}
		} else {
			// All non-final segments must be exactly defaultSize for uniformity
			if seg.Size != defaultSize {
				return false
			}
		}
	}

	return true
}
