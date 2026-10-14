package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

var errRangeNotSupported = errors.New("server did not honor the HTTP range request")

// HTTPRangeReader is an io.ReadSeeker over an HTTP(S) resource. Each Read issues
// a single range request, so only the bytes actually read are fetched.
//
// ponytail: one request per Read (about 15 small requests to open a TDF); add a
// tail buffer for the zip directory and manifest if request count matters.
type HTTPRangeReader struct {
	ctx    context.Context //nolint:containedctx // io.Reader has no context parameter
	client *http.Client
	url    string
	size   int64
	offset int64
}

// NewHTTPRangeReader returns an io.ReadSeeker for url. The server must support
// range requests (respond 206 Partial Content). A nil client uses
// http.DefaultClient.
func NewHTTPRangeReader(ctx context.Context, client *http.Client, url string) (*HTTPRangeReader, error) {
	if client == nil {
		client = http.DefaultClient
	}
	r := &HTTPRangeReader{ctx: ctx, client: client, url: url}

	// Probe one byte to learn the total size and confirm range support.
	var probe [1]byte
	size, err := r.fetch(probe[:], 0)
	if err != nil {
		return nil, err
	}
	r.size = size
	return r, nil
}

// Size returns the total size of the remote resource in bytes.
func (r *HTTPRangeReader) Size() int64 {
	return r.size
}

func (r *HTTPRangeReader) Read(p []byte) (int, error) {
	if r.offset >= r.size {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if remaining := r.size - r.offset; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	if _, err := r.fetch(p, r.offset); err != nil {
		return 0, err
	}
	r.offset += int64(len(p))
	return len(p), nil
}

func (r *HTTPRangeReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.offset + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, errors.New("HTTPRangeReader.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("HTTPRangeReader.Seek: negative position")
	}
	r.offset = abs
	return abs, nil
}

// fetch fills p with the bytes at offset and returns the total resource size
// reported by the server.
func (r *HTTPRangeReader) fetch(p []byte, offset int64) (int64, error) {
	end := offset + int64(len(p)) - 1
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return 0, fmt.Errorf("http.NewRequestWithContext failed: %w", err)
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, end))

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("range request failed: %w", err)
	}
	defer resp.Body.Close()

	// A 200 means the server ignored Range and is sending the whole resource.
	if resp.StatusCode != http.StatusPartialContent {
		return 0, fmt.Errorf("%w: status %d for bytes %d-%d", errRangeNotSupported, resp.StatusCode, offset, end)
	}
	var gotStart, gotEnd, size int64
	if _, err := fmt.Sscanf(resp.Header.Get("Content-Range"), "bytes %d-%d/%d", &gotStart, &gotEnd, &size); err != nil {
		return 0, fmt.Errorf("%w: invalid Content-Range %q", errRangeNotSupported, resp.Header.Get("Content-Range"))
	}
	if gotStart != offset || gotEnd != end {
		return 0, fmt.Errorf("%w: requested bytes %d-%d, got %d-%d", errRangeNotSupported, offset, end, gotStart, gotEnd)
	}
	if _, err := io.ReadFull(resp.Body, p); err != nil {
		return 0, fmt.Errorf("reading range response failed: %w", err)
	}
	return size, nil
}

// LoadTDFFromURL loads a TDF served over HTTP(S) using range requests, fetching
// only the zip directory, the manifest and the segments that are read.
//
// Requests use the SDK's unauthenticated HTTP client (TLS settings applied, no
// redirects); platform credentials are never sent to the TDF host.
func (s SDK) LoadTDFFromURL(ctx context.Context, url string, opts ...TDFReaderOption) (*Reader, error) {
	r, err := NewHTTPRangeReader(ctx, s.httpClient, url)
	if err != nil {
		return nil, err
	}
	return s.LoadTDF(r, opts...) //nolint:contextcheck // LoadTDF takes no context; ctx still bounds every range request
}
