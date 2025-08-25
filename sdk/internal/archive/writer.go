package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// ArchiveWriter is the base interface for all archive writers
type ArchiveWriter interface {
	io.Closer
}

// SegmentWriter handles out-of-order segments with deterministic output
type SegmentWriter interface {
	ArchiveWriter
	WriteSegment(ctx context.Context, index int, data []byte) ([]byte, error)
	Finalize(ctx context.Context, manifest []byte) ([]byte, error)
	CleanupSegment(index int) // Free memory after S3 upload
}

// ArchiveError provides detailed error information for archive operations
type ArchiveError struct {
	Op   string // Operation that failed
	Type string // Writer type: "sequential", "streaming", "segment"
	Err  error  // Underlying error
}

func (e *ArchiveError) Error() string {
	return fmt.Sprintf("archive %s %s: %v", e.Type, e.Op, e.Err)
}

func (e *ArchiveError) Unwrap() error {
	return e.Err
}

// Common errors
var (
	ErrWriterClosed     = errors.New("archive writer closed")
	ErrInvalidSegment   = errors.New("invalid segment index")
	ErrOutOfOrder       = errors.New("segment out of order")
	ErrDuplicateSegment = errors.New("duplicate segment already written")
	ErrSegmentMissing   = errors.New("segment missing")
	ErrInvalidSize      = errors.New("invalid size")
)

// Config holds configuration options for writers
type Config struct {
	EnableZip64   bool
	BufferSize    int
	MaxSegments   int
	EnableLogging bool
}

// Option is a functional option for configuring writers
type Option func(*Config)

// WithZip64 enables ZIP64 format support for large files
func WithZip64() Option {
	return func(c *Config) {
		c.EnableZip64 = true
	}
}

// WithBufferSize sets the internal buffer size
func WithBufferSize(size int) Option {
	return func(c *Config) {
		if size > 0 {
			c.BufferSize = size
		}
	}
}

// WithMaxSegments sets the maximum number of segments for SegmentWriter
func WithMaxSegments(max int) Option {
	return func(c *Config) {
		if max > 0 {
			c.MaxSegments = max
		}
	}
}

// WithLogging enables debug logging
func WithLogging() Option {
	return func(c *Config) {
		c.EnableLogging = true
	}
}

// defaultConfig returns default configuration
func defaultConfig() *Config {
	return &Config{
		EnableZip64:   false,
		BufferSize:    64 * 1024, // 64KB
		MaxSegments:   10000,     // Reasonable default
		EnableLogging: false,
	}
}

// applyOptions applies functional options to config
func applyOptions(opts []Option) *Config {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// baseWriter provides common functionality for all writer implementations
type baseWriter struct {
	closed     bool
	mu         sync.RWMutex
	bufferPool *sync.Pool
	config     *Config
}

// newBaseWriter creates a new base writer with the given configuration
func newBaseWriter(cfg *Config) *baseWriter {
	return &baseWriter{
		config: cfg,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 0, cfg.BufferSize)
			},
		},
	}
}

// checkClosed returns an error if the writer is closed
func (bw *baseWriter) checkClosed() error {
	bw.mu.RLock()
	defer bw.mu.RUnlock()
	if bw.closed {
		return ErrWriterClosed
	}
	return nil
}

// Close marks the writer as closed
func (bw *baseWriter) Close() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	bw.closed = true
	return nil
}

// getBuffer gets a buffer from the pool
func (bw *baseWriter) getBuffer() []byte {
	return bw.bufferPool.Get().([]byte)[:0]
}

// putBuffer returns a buffer to the pool
func (bw *baseWriter) putBuffer(buf []byte) {
	if cap(buf) <= bw.config.BufferSize*2 { // Prevent excessive growth
		bw.bufferPool.Put(buf)
	}
}
