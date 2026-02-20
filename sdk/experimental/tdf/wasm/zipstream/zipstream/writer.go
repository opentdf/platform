// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package zipstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	defaultMaxSegments = 10000 // Reasonable default for max segments
)

// Writer is the base interface for all archive writers
type Writer interface {
	io.Closer
}

// SegmentWriter handles out-of-order segments with deterministic output
type SegmentWriter interface {
	Writer
	WriteSegment(ctx context.Context, index int, size uint64, crc32 uint32) ([]byte, error)
	Finalize(ctx context.Context, manifest []byte) ([]byte, error)
	// CleanupSegment removes the presence marker for a segment index.
	// Calling this before Finalize will cause IsComplete() to fail for that index.
	CleanupSegment(index int) error
}

// Error provides detailed error information for archive operations
type Error struct {
	Op   string // Operation that failed
	Type string // Writer type: "sequential", "streaming", "segment"
	Err  error  // Underlying error
}

func (e *Error) Error() string {
	return fmt.Sprintf("archive %s %s: %v", e.Type, e.Op, e.Err)
}

func (e *Error) Unwrap() error {
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
	ErrZip64Required    = errors.New("ZIP64 required but disabled (Zip64Never)")
)

// Config holds configuration options for writers
type Config struct {
	Zip64         Zip64Mode
	MaxSegments   int
	EnableLogging bool
}

// Option is a functional option for configuring writers
type Option func(*Config)

// Zip64Mode controls when ZIP64 structures are used.
type Zip64Mode int

const (
	Zip64Auto   Zip64Mode = iota // Use ZIP64 only when needed
	Zip64Always                  // Force ZIP64 even for small archives
	Zip64Never                   // Forbid ZIP64; error if limits exceeded
)

// WithZip64 enables ZIP64 format support for large files
// WithZip64 forces ZIP64 mode; kept for backward compatibility.
// Equivalent to WithZip64Mode(Zip64Always).
func WithZip64() Option { return WithZip64Mode(Zip64Always) }

// WithZip64Mode sets the ZIP64 mode (Auto/Always/Never).
func WithZip64Mode(mode Zip64Mode) Option {
	return func(c *Config) { c.Zip64 = mode }
}

// WithMaxSegments sets the maximum number of segments for SegmentWriter
func WithMaxSegments(maxSegments int) Option {
	return func(c *Config) {
		if maxSegments > 0 {
			c.MaxSegments = maxSegments
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
		Zip64:         Zip64Auto,
		MaxSegments:   defaultMaxSegments,
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
	closed bool
	mu     sync.RWMutex
	config *Config
}

// newBaseWriter creates a new base writer with the given configuration
func newBaseWriter(cfg *Config) *baseWriter {
	return &baseWriter{
		config: cfg,
	}
}

// Close marks the writer as closed
func (bw *baseWriter) Close() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	bw.closed = true
	return nil
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
