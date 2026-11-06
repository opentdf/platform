package sdk

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"
)

// countingResponseWriter counts response body bytes sent by the test server.
type countingResponseWriter struct {
	http.ResponseWriter
	n *atomic.Int64
}

func (w countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.n.Add(int64(n))
	return n, err
}

func (s *TDFSuite) Test_LoadTDFFromURL() {
	const segSize = minSegmentSize
	plaintext := bytes.Repeat([]byte(payload), 4000) // 248,000 bytes, ~16 segments
	var tdf bytes.Buffer
	_, err := s.sdk.CreateTDF(&tdf, bytes.NewReader(plaintext),
		WithKasInformation(KASInfo{URL: s.kasTestURLLookup["http://localhost:65432/"]}),
		WithSegmentSize(segSize),
	)
	s.Require().NoError(err)

	var served atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(countingResponseWriter{w, &served}, r, "", time.Time{}, bytes.NewReader(tdf.Bytes()))
	}))
	defer server.Close()

	r, err := s.sdk.LoadTDFFromURL(context.Background(), server.URL)
	s.Require().NoError(err)

	// A read straddling one segment boundary fetches exactly those two segments.
	served.Store(0)
	offset := int64(6*segSize - 50)
	got := make([]byte, 100)
	n, err := r.ReadAt(got, offset)
	s.Require().NoError(err)
	s.Equal(100, n)
	s.Equal(plaintext[offset:offset+100], got)
	const gcmOverhead = 12 + 16 // nonce + tag per segment
	s.Equal(int64(2*(segSize+gcmOverhead)), served.Load())

	// Full read through the range reader matches the plaintext.
	var out bytes.Buffer
	_, err = r.Seek(0, io.SeekStart)
	s.Require().NoError(err)
	_, err = r.WriteTo(&out)
	s.Require().NoError(err)
	s.Equal(plaintext, out.Bytes())
}

func (s *TDFSuite) Test_LoadTDFFromURL_RangeNotSupported() {
	// Ignores Range and always sends the full body with 200.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not a tdf, and not a partial response"))
	}))
	defer server.Close()

	_, err := s.sdk.LoadTDFFromURL(context.Background(), server.URL)
	s.Require().ErrorIs(err, ErrRangeNotSupported)
}

func (s *TDFSuite) Test_HTTPRangeReader_ErrorStatus() {
	for _, status := range []int{http.StatusNotFound, http.StatusFound, http.StatusForbidden} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if status == http.StatusFound {
				w.Header().Set("Location", "/elsewhere")
			}
			w.WriteHeader(status)
		}))
		_, err := NewHTTPRangeReader(context.Background(), s.sdk.httpClient, server.URL)
		server.Close()
		s.Require().Error(err, "status %d", status)
		s.Require().NotErrorIs(err, ErrRangeNotSupported, "status %d", status)
		if status == http.StatusFound {
			s.Contains(err.Error(), "redirects are not followed")
		}
	}
}

func (s *TDFSuite) Test_HTTPRangeReader_SizeChanged() {
	var grown atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := "0123456789"
		if grown.Load() {
			data += "abc"
		}
		http.ServeContent(w, r, "", time.Time{}, strings.NewReader(data))
	}))
	defer server.Close()

	r, err := NewHTTPRangeReader(context.Background(), nil, server.URL)
	s.Require().NoError(err)

	grown.Store(true) // resource changes after the probe
	_, err = r.Read(make([]byte, 4))
	s.Require().ErrorContains(err, "size changed from 10 to 13")
}

func (s *TDFSuite) Test_HTTPRangeReader_Seek() {
	data := []byte("0123456789")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
	}))
	defer server.Close()

	r, err := NewHTTPRangeReader(context.Background(), nil, server.URL)
	s.Require().NoError(err)
	s.Equal(int64(len(data)), r.Size())

	pos, err := r.Seek(-3, io.SeekEnd)
	s.Require().NoError(err)
	s.Equal(int64(7), pos)

	// Reads are clamped at end of resource, then report EOF.
	buf := make([]byte, 8)
	n, err := r.Read(buf)
	s.Require().NoError(err)
	s.Equal("789", string(buf[:n]))
	_, err = r.Read(buf)
	s.Require().ErrorIs(err, io.EOF)

	_, err = r.Seek(-1, io.SeekStart)
	s.Require().Error(err)
}
