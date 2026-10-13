package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/opentdf/platform/service/internal/server/memhttp"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/emptypb"
)

const readLimitTestProcedure = "/test.v1.TestService/Method"

func TestReadLimitHandlerOptions_ConnectProtocol(t *testing.T) {
	const limit = 1024

	tests := []struct {
		name       string
		size       int
		gzip       bool
		wantStatus int
	}{
		{name: "at limit", size: limit, wantStatus: http.StatusOK},
		{name: "one byte over limit", size: limit + 1, wantStatus: http.StatusTooManyRequests},
		{name: "gzip at limit", size: limit, gzip: true, wantStatus: http.StatusOK},
		{name: "gzip one byte over limit", size: limit + 1, gzip: true, wantStatus: http.StatusTooManyRequests},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, calls := newReadLimitTestHandler(readLimitHandlerOptions(limit)...)

			rr := serveConnectUnary(t, handler, paddedProtoMessage(t, tt.size), tt.gzip)

			assert.Equal(t, tt.wantStatus, rr.Code, rr.Body.String())
			wantCalls := int32(0)
			if tt.wantStatus == http.StatusOK {
				wantCalls = 1
			}
			assert.Equal(t, wantCalls, calls.Load())
		})
	}
}

func TestReadLimitHandlerOptions_GzipStopsDecompressionAtLimit(t *testing.T) {
	const (
		limit        = 16 * 1024
		expandedSize = 8 * 1024 * 1024
	)
	compressed := gzipCompress(t, make([]byte, expandedSize))
	require.Less(t, len(compressed), limit, "compressed body must pass the wire limit so decompression is exercised")

	handler, calls := newReadLimitTestHandler(readLimitHandlerOptions(limit)...)
	req := httptest.NewRequest(http.MethodPost, readLimitTestProcedure, bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Connect-Protocol-Version", "1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Equal(t, int32(0), calls.Load())
	// Connect reports the full decompressed size only after draining the whole
	// stream; the bounded decompressor ends the drain at the limit instead.
	assert.Contains(t, rr.Body.String(), "unable to determine message size")
	assert.NotContains(t, rr.Body.String(), strconv.Itoa(expandedSize))
}

func TestReadLimitHandlerOptions_GRPCProtocol(t *testing.T) {
	const limit = 1024

	handler, _ := newReadLimitTestHandler(readLimitHandlerOptions(limit)...)
	mux := http.NewServeMux()
	mux.Handle(readLimitTestProcedure, handler)
	srv := memhttp.New(mux)
	t.Cleanup(func() { _ = srv.Close() })

	client := connect.NewClient[emptypb.Empty, emptypb.Empty](
		srv.Client(),
		srv.Listener.Addr().String()+readLimitTestProcedure,
		connect.WithGRPC(),
	)

	_, err := client.CallUnary(t.Context(), connect.NewRequest(paddedEmpty(t, limit)))
	require.NoError(t, err)

	_, err = client.CallUnary(t.Context(), connect.NewRequest(paddedEmpty(t, limit+1)))
	require.Error(t, err)
	assert.Equal(t, connect.CodeResourceExhausted, connect.CodeOf(err))
}

func TestReadLimitHandlerOptions_ServiceOverride(t *testing.T) {
	const (
		platformLimit = 1024
		serviceLimit  = 4096
		size          = 2048
	)
	platformOptions := externalConnectHandlerOptions(Config{GRPC: GRPCConfig{MaxRecvMsgSizeBytes: platformLimit}})

	t.Run("read limit and gzip override raise both limits", func(t *testing.T) {
		opts := slices.Concat(platformOptions, readLimitHandlerOptions(serviceLimit))
		handler, _ := newReadLimitTestHandler(opts...)

		assert.Equal(t, http.StatusOK, serveConnectUnary(t, handler, paddedProtoMessage(t, size), false).Code)
		assert.Equal(t, http.StatusOK, serveConnectUnary(t, handler, paddedProtoMessage(t, size), true).Code)
	})

	t.Run("read limit override alone keeps the platform gzip bound", func(t *testing.T) {
		opts := append(slices.Clone(platformOptions), connect.WithReadMaxBytes(serviceLimit))
		handler, _ := newReadLimitTestHandler(opts...)

		assert.Equal(t, http.StatusOK, serveConnectUnary(t, handler, paddedProtoMessage(t, size), false).Code)
		assert.Equal(t, http.StatusTooManyRequests, serveConnectUnary(t, handler, paddedProtoMessage(t, size), true).Code)
	})
}

func TestReadLimitHandlerOptions_NonPositiveUsesDefault(t *testing.T) {
	for _, maxBytes := range []int{0, -1} {
		t.Run(strconv.Itoa(maxBytes), func(t *testing.T) {
			handler, _ := newReadLimitTestHandler(readLimitHandlerOptions(maxBytes)...)

			atLimit := serveConnectUnary(t, handler, paddedProtoMessage(t, defaultMaxRecvMsgSizeBytes), false)
			assert.Equal(t, http.StatusOK, atLimit.Code)
			overLimit := serveConnectUnary(t, handler, paddedProtoMessage(t, defaultMaxRecvMsgSizeBytes+1), false)
			assert.Equal(t, http.StatusTooManyRequests, overLimit.Code)
		})
	}
}

func TestGRPCConfig_MaxRecvMsgSizeDefault(t *testing.T) {
	var cfg GRPCConfig
	require.NoError(t, defaults.Set(&cfg))

	assert.Equal(t, 4194304, cfg.MaxRecvMsgSizeBytes)
}

func TestNewOpenTDFServer_ReadLimitAppliesToExternalHandlersOnly(t *testing.T) {
	const limit = 1024

	server, err := NewOpenTDFServer(Config{
		GRPC: GRPCConfig{MaxRecvMsgSizeBytes: limit},
	}, logger.CreateTestLogger(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.ConnectRPCInProcess.srv.Close() })

	external, _ := newReadLimitTestHandler(server.ConnectRPC.Interceptors...)
	assert.Equal(t, http.StatusTooManyRequests, serveConnectUnary(t, external, paddedProtoMessage(t, limit+1), false).Code)
	assert.Equal(t, http.StatusOK, serveConnectUnary(t, external, paddedProtoMessage(t, limit), false).Code)

	ipc, _ := newReadLimitTestHandler(server.ConnectRPCInProcess.Interceptors...)
	assert.Equal(t, http.StatusOK, serveConnectUnary(t, ipc, paddedProtoMessage(t, limit+1), false).Code)
}

func TestRegisterReflectionHandlers_ApplyReadLimit(t *testing.T) {
	const limit = 64

	server, err := NewOpenTDFServer(Config{
		GRPC: GRPCConfig{ReflectionEnabled: true, MaxRecvMsgSizeBytes: limit},
	}, logger.CreateTestLogger(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.ConnectRPCInProcess.srv.Close() })
	server.registerReflectionHandlers()

	srv := memhttp.New(server.ConnectRPC.Mux)
	t.Cleanup(func() { _ = srv.Close() })

	// list_services (field 7) with an empty host is a valid reflection request.
	listServices := protowire.AppendString(protowire.AppendTag(nil, 7, protowire.BytesType), "")

	for _, path := range []string{
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
	} {
		t.Run(path, func(t *testing.T) {
			overLimit := postConnectStream(t, srv, path, paddedProtoMessage(t, limit+1))
			assert.Contains(t, overLimit, "resource_exhausted")

			valid := postConnectStream(t, srv, path, listServices)
			assert.NotContains(t, valid, "resource_exhausted")
		})
	}
}

// newReadLimitTestHandler returns a unary handler built with opts and a counter
// of how many requests reached it.
func newReadLimitTestHandler(opts ...connect.HandlerOption) (http.Handler, *atomic.Int32) {
	calls := &atomic.Int32{}
	handler := connect.NewUnaryHandler(
		readLimitTestProcedure,
		func(_ context.Context, _ *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
			calls.Add(1)
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
		opts...,
	)
	return handler, calls
}

// serveConnectUnary sends body as a binary Connect unary request.
func serveConnectUnary(t *testing.T, handler http.Handler, body []byte, compress bool) *httptest.ResponseRecorder {
	t.Helper()
	return serveConnectUnaryTo(t, handler, readLimitTestProcedure, body, compress)
}

// serveConnectUnaryTo sends body as a binary Connect unary request to procedure.
func serveConnectUnaryTo(t *testing.T, handler http.Handler, procedure string, body []byte, compress bool) *httptest.ResponseRecorder {
	t.Helper()

	if compress {
		body = gzipCompress(t, body)
	}
	req := httptest.NewRequest(http.MethodPost, procedure, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	if compress {
		req.Header.Set("Content-Encoding", "gzip")
	}

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// postConnectStream sends one Connect streaming envelope and returns the response body.
func postConnectStream(t *testing.T, srv *memhttp.Server, path string, message []byte) string {
	t.Helper()

	envelope := make([]byte, 5, 5+len(message))
	binary.BigEndian.PutUint32(envelope[1:], uint32(len(message)))
	envelope = append(envelope, message...)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.Listener.Addr().String()+path, bytes.NewReader(envelope))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/connect+proto")

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(responseBody)
}

// paddedProtoMessage returns a protobuf message of exactly size bytes made of a
// single unknown bytes field, which any message type accepts.
func paddedProtoMessage(t *testing.T, size int) []byte {
	t.Helper()

	for payload := size - 1; payload >= 0; payload-- {
		if 1+protowire.SizeVarint(uint64(payload))+payload == size {
			msg := protowire.AppendTag(nil, 1, protowire.BytesType)
			return protowire.AppendBytes(msg, make([]byte, payload))
		}
	}
	require.FailNow(t, "cannot build padded message", "size %d", size)
	return nil
}

// paddedEmpty returns an Empty message that serializes to exactly size bytes.
func paddedEmpty(t *testing.T, size int) *emptypb.Empty {
	t.Helper()

	msg := &emptypb.Empty{}
	msg.ProtoReflect().SetUnknown(protoreflect.RawFields(paddedProtoMessage(t, size)))
	return msg
}

func gzipCompress(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	_, err := writer.Write(data)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return buf.Bytes()
}
