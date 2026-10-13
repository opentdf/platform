package server

import (
	"context"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"

	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/emptypb"
)

const readLimitTestOtherProcedure = "/test.v1.TestService/Other"

// newReadLimitV2TestHandler mounts a connect-go v2 server with two unary
// procedures and counts how many requests reach them.
func newReadLimitV2TestHandler(opts ...connecthttp.Option) (http.Handler, *atomic.Int32) {
	calls := &atomic.Int32{}
	handler := func(_ context.Context, _ connectv2.Spec, stream connectv2.ServerStream) error {
		var req emptypb.Empty
		if err := stream.Receive(&req); err != nil {
			return err
		}
		calls.Add(1)
		return stream.Send(&emptypb.Empty{})
	}
	server := connectv2.NewServer()
	server.Register(
		connectv2.Method{Spec: connectv2.Spec{Procedure: readLimitTestProcedure, StreamType: connectv2.StreamTypeUnary}, Handler: handler},
		connectv2.Method{Spec: connectv2.Spec{Procedure: readLimitTestOtherProcedure, StreamType: connectv2.StreamTypeUnary}, Handler: handler},
	)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server, opts...)
	return mux, calls
}

func TestReadLimitMountOptions_ConnectProtocol(t *testing.T) {
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
			handler, calls := newReadLimitV2TestHandler(ReadLimitMountOptions(limit)...)

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

func TestReadLimitMountOptions_GzipStopsDecompressionAtLimit(t *testing.T) {
	const (
		limit        = 16 * 1024
		expandedSize = 8 * 1024 * 1024
	)
	handler, calls := newReadLimitV2TestHandler(ReadLimitMountOptions(limit)...)

	rr := serveConnectUnary(t, handler, make([]byte, expandedSize), true)

	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Equal(t, int32(0), calls.Load())
	// connect-go v2 reports the full decompressed size only after draining the
	// whole stream; the bounded decompressor ends the drain at the limit.
	assert.NotContains(t, rr.Body.String(), strconv.Itoa(expandedSize))

	t.Run("unbounded gzip drains the whole message", func(t *testing.T) {
		unbounded, _ := newReadLimitV2TestHandler(connecthttp.WithReadMaxBytes(limit))

		unboundedRR := serveConnectUnary(t, unbounded, make([]byte, expandedSize), true)

		assert.Equal(t, http.StatusTooManyRequests, unboundedRR.Code)
		assert.Contains(t, unboundedRR.Body.String(), strconv.Itoa(expandedSize))
	})
}

func TestReadLimitMountOptions_LaterOptionsOverride(t *testing.T) {
	const (
		limit  = 1024
		raised = 4 * 1024
	)
	opts := append(ReadLimitMountOptions(limit), connecthttp.WithConditionalOptions(func(spec connectv2.Spec) []connecthttp.Option {
		if spec.Procedure == readLimitTestOtherProcedure {
			return ReadLimitMountOptions(raised)
		}
		return nil
	}))
	handler, _ := newReadLimitV2TestHandler(opts...)

	serve := func(procedure string, size int, compress bool) int {
		body := paddedProtoMessage(t, size)
		rr := serveConnectUnaryTo(t, handler, procedure, body, compress)
		return rr.Code
	}

	assert.Equal(t, http.StatusTooManyRequests, serve(readLimitTestProcedure, limit+1, false))
	assert.Equal(t, http.StatusOK, serve(readLimitTestOtherProcedure, raised, false))
	assert.Equal(t, http.StatusOK, serve(readLimitTestOtherProcedure, raised, true))
	assert.Equal(t, http.StatusTooManyRequests, serve(readLimitTestOtherProcedure, raised+1, true))
}

func TestReadLimitMountOptions_DefaultsNonPositiveLimits(t *testing.T) {
	for _, maxBytes := range []int{0, -1} {
		handler, _ := newReadLimitV2TestHandler(ReadLimitMountOptions(maxBytes)...)

		assert.Equal(t, http.StatusOK, serveConnectUnary(t, handler, paddedProtoMessage(t, defaultMaxRecvMsgSizeBytes), false).Code)
		assert.Equal(t, http.StatusTooManyRequests, serveConnectUnary(t, handler, paddedProtoMessage(t, defaultMaxRecvMsgSizeBytes+1), false).Code)
	}
}
