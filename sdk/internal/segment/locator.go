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
type Info struct {
	Index            int    // Segment index
	PlaintextSize    int64  // Unencrypted size
	EncryptedSize    int64  // Encrypted size (with IV + auth tag)
	CumulativeOffset int64  // Cumulative offset in plaintext
	FileOffset       int64  // Physical offset in TDF file
	Hash             string // Integrity hash
}

// SegmentLocator provides an abstraction for finding segments by offset
// This enables support for both uniform and variable-length segments
type Locator interface {
	// FindSegmentByOffset finds the segment containing the given offset
	FindSegmentByOffset(offset int64) (*Info, error)

	// GetSegmentRange returns segments that overlap with the given range
	GetSegmentRange(start, end int64) ([]Info, error)

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

func (u *UniformSegmentLocator) FindSegmentByOffset(offset int64) (*Info, error) {
	if offset < 0 || offset >= u.totalSize {
		return nil, fmt.Errorf("%w: offset %d not in range [0, %d)", ErrOffsetOutOfRange, offset, u.totalSize)
	}

	// O(1) division-based lookup for uniform segments
	segmentIndex := int(offset / u.segmentSize)
	if segmentIndex >= len(u.segments) {
		segmentIndex = len(u.segments) - 1
	}

	seg := u.segments[segmentIndex]
	return &Info{
		Index:            segmentIndex,
		PlaintextSize:    seg.Size,
		EncryptedSize:    seg.EncryptedSize,
		CumulativeOffset: int64(segmentIndex) * u.segmentSize,
		FileOffset:       u.fileOffsets[segmentIndex],
		Hash:             seg.Hash,
	}, nil
}

func (u *UniformSegmentLocator) GetSegmentRange(start, end int64) ([]Info, error) {
	if start < 0 || end <= start || start >= u.totalSize {
		return nil, fmt.Errorf("%w: invalid range [%d, %d)", ErrInvalidRange, start, end)
	}

	startSegment := int(start / u.segmentSize)
	endSegment := int((end + u.segmentSize - 1) / u.segmentSize)
	if endSegment > len(u.segments) {
		endSegment = len(u.segments)
	}

	result := make([]Info, 0, endSegment-startSegment)
	for i := startSegment; i < endSegment; i++ {
		seg := u.segments[i]
		result = append(result, Info{
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
	offsetTable *OffsetTable
}

// NewVariableSegmentLocator creates a locator for variable-length segments
func NewVariableSegmentLocator(segments []tdf.Segment) *VariableSegmentLocator {
	offsetTable := &OffsetTable{
		cumulativeOffsets: make([]int64, len(segments)),
		segments:          make([]Info, len(segments)),
		cache:             NewSegmentCache(DefaultCacheSize),
	}

	// Build cumulative offset table and segment info
	var cumOffset int64
	var fileOffset int64

	for i, seg := range segments {
		offsetTable.cumulativeOffsets[i] = cumOffset
		offsetTable.segments[i] = Info{
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

func (v *VariableSegmentLocator) FindSegmentByOffset(offset int64) (*Info, error) {
	return v.offsetTable.FindSegmentByOffset(offset)
}

func (v *VariableSegmentLocator) GetSegmentRange(start, end int64) ([]Info, error) {
	return v.offsetTable.GetSegmentRange(start, end)
}

func (v *VariableSegmentLocator) GetTotalSize() int64 {
	return v.offsetTable.totalSize
}

func (v *VariableSegmentLocator) GetSegmentCount() int {
	return len(v.offsetTable.segments)
}

// OffsetTable provides binary search on cumulative offsets
type OffsetTable struct {
	cumulativeOffsets []int64
	segments          []Info
	cache             *Cache
	totalSize         int64

	// Performance metrics
	lookupCount atomic.Uint64
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64
}

// FindSegmentByOffset finds the segment containing the given offset using binary search
func (ot *OffsetTable) FindSegmentByOffset(offset int64) (*Info, error) {
	ot.lookupCount.Add(1)

	if offset < 0 || offset >= ot.totalSize {
		return nil, fmt.Errorf("%w: offset %d not in range [0, %d)", ErrOffsetOutOfRange, offset, ot.totalSize)
	}

	// Binary search on cumulative offsets to find which segment contains the offset
	// We want the largest index i where cumulativeOffsets[i] <= offset
	segmentIndex := sort.Search(len(ot.cumulativeOffsets), func(i int) bool {
		return ot.cumulativeOffsets[i] > offset
	})
	// sort.Search returns the first index where cumulativeOffsets[i] > offset,
	// so we want the previous index (which has cumulativeOffsets[i] <= offset)
	if segmentIndex > 0 {
		segmentIndex--
	}

	if segmentIndex >= len(ot.segments) {
		return nil, fmt.Errorf("%w: calculated index %d out of bounds", ErrSegmentNotFound, segmentIndex)
	}

	// Check cache first
	if cachedSeg, found := ot.cache.Get(segmentIndex); found {
		ot.cacheHits.Add(1)
		return cachedSeg, nil
	}

	// Cache miss - get segment info and cache it
	ot.cacheMisses.Add(1)
	segInfo := &ot.segments[segmentIndex]
	ot.cache.Put(segmentIndex, segInfo)

	return segInfo, nil
}

// GetSegmentRange returns segments that overlap with the given range
func (ot *OffsetTable) GetSegmentRange(start, end int64) ([]Info, error) {
	if start < 0 || end <= start || start >= ot.totalSize {
		return nil, fmt.Errorf("%w: invalid range [%d, %d)", ErrInvalidRange, start, end)
	}

	startSegInfo, err := ot.FindSegmentByOffset(start)
	if err != nil {
		return nil, fmt.Errorf("finding start segment: %w", err)
	}

	endOffset := end - 1 // Convert to inclusive end
	if endOffset >= ot.totalSize {
		endOffset = ot.totalSize - 1
	}

	endSegInfo, err := ot.FindSegmentByOffset(endOffset)
	if err != nil {
		return nil, fmt.Errorf("finding end segment: %w", err)
	}

	// Return range of segments
	result := make([]Info, 0, endSegInfo.Index-startSegInfo.Index+1)
	for i := startSegInfo.Index; i <= endSegInfo.Index; i++ {
		result = append(result, ot.segments[i])
	}

	return result, nil
}

// GetMetrics returns performance metrics for monitoring
func (ot *OffsetTable) GetMetrics() Metrics {
	return Metrics{
		LookupCount: ot.lookupCount.Load(),
		CacheHits:   ot.cacheHits.Load(),
		CacheMisses: ot.cacheMisses.Load(),
		CacheSize:   ot.cache.Size(),
	}
}

// Metrics contains performance metrics
type Metrics struct {
	LookupCount uint64
	CacheHits   uint64
	CacheMisses uint64
	CacheSize   int
}

// HitRate returns the cache hit rate as a percentage
func (sm Metrics) HitRate() float64 {
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
