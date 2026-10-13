package server

import (
	"compress/gzip"
	"fmt"
	"io"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectgzip"
	"connectrpc.com/connect/v2/connecthttp"
)

const (
	// defaultMaxRecvMsgSizeBytes matches the receive limit grpc-go servers apply by default.
	defaultMaxRecvMsgSizeBytes = 4 * 1024 * 1024
	gzipCompressionName        = "gzip"
)

// externalConnectHandlerOptions returns the handler options applied ahead of the
// shared interceptors on every external Connect handler. A service that needs a
// larger limit must append both connect.WithReadMaxBytes and a gzip decompressor
// bounded at its own limit, because later handler options replace earlier ones.
func externalConnectHandlerOptions(c Config) []connect.HandlerOption {
	return readLimitHandlerOptions(c.GRPC.MaxRecvMsgSizeBytes)
}

// readLimitHandlerOptions caps each request message at maxBytes, both as read
// from the wire and after gzip decompression. Non-positive values use the default
// so a zero-value configuration never leaves the server unlimited.
func readLimitHandlerOptions(maxBytes int) []connect.HandlerOption {
	if maxBytes <= 0 {
		maxBytes = defaultMaxRecvMsgSizeBytes
	}
	limit := int64(maxBytes)
	return []connect.HandlerOption{
		connect.WithReadMaxBytes(maxBytes),
		connect.WithCompression(
			gzipCompressionName,
			func() connect.Decompressor { return &boundedGzipDecompressor{limit: limit} },
			func() connect.Compressor { return gzip.NewWriter(io.Discard) },
		),
	}
}

// boundedGzipDecompressor stops producing output once a message exceeds limit.
// Connect reads the rest of an oversized message to report its size, so the
// decompressor itself ends decompression at the limit.
type boundedGzipDecompressor struct {
	gzip.Reader

	limit int64
	read  int64
}

// Read passes through at most limit+1 bytes, enough for Connect to detect an
// oversized message, then fails so Connect stops decompressing.
func (d *boundedGzipDecompressor) Read(p []byte) (int, error) {
	remaining := d.limit + 1 - d.read
	if remaining <= 0 {
		return 0, connect.NewError(connect.CodeResourceExhausted, fmt.Errorf("decompressed message exceeds %d bytes", d.limit))
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := d.Reader.Read(p)
	d.read += int64(n)
	return n, err
}

// Reset prepares the decompressor for a new message.
func (d *boundedGzipDecompressor) Reset(r io.Reader) error {
	d.read = 0
	return d.Reader.Reset(r)
}

// ReadLimitMountOptions caps each request message of a connect-go v2 mount at
// maxBytes, both as read from the wire and after gzip decompression.
// Non-positive values use the default. Options applied later replace these, so
// a mount that raises the limit must use ReadLimitMountOptions again with the
// larger value to keep gzip bounded.
func ReadLimitMountOptions(maxBytes int) []connecthttp.Option {
	if maxBytes <= 0 {
		maxBytes = defaultMaxRecvMsgSizeBytes
	}
	return []connecthttp.Option{
		connecthttp.WithReadMaxBytes(maxBytes),
		connecthttp.WithCompressors(boundedGzipCompressor{Compressor: connectgzip.New(), limit: int64(maxBytes)}),
	}
}

// boundedGzipCompressor is gzip for connect-go v2 with decompression stopped
// once a message exceeds limit. connect-go v2 also reads the rest of an
// oversized message to report its size.
type boundedGzipCompressor struct {
	*connectgzip.Compressor

	limit int64
}

func (c boundedGzipCompressor) Decompress(src io.Reader) (io.ReadCloser, error) {
	reader, err := c.Compressor.Decompress(src)
	if err != nil {
		return nil, err
	}
	return &boundedReadCloser{ReadCloser: reader, limit: c.limit}, nil
}

// boundedReadCloser passes through at most limit+1 bytes, enough for Connect to
// detect an oversized message, then fails.
type boundedReadCloser struct {
	io.ReadCloser

	limit int64
	read  int64
}

func (r *boundedReadCloser) Read(p []byte) (int, error) {
	remaining := r.limit + 1 - r.read
	if remaining <= 0 {
		return 0, connectv2.Errorf(connectv2.CodeResourceExhausted, "decompressed message exceeds %d bytes", r.limit)
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.ReadCloser.Read(p)
	r.read += int64(n)
	return n, err
}
