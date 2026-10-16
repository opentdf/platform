// Package connectcompat bridges connect-go v1 and v2 for services that serve
// on v2 while calling other services through v1 clients, such as the SDK.
package connectcompat

import (
	"context"
	"errors"
	"net/http"
	"slices"

	connectv1 "connectrpc.com/connect"
	"connectrpc.com/connect/v2"
)

// CodeOf returns the code of the first connect-go v2 or v1 error in err's
// chain, or connect.CodeUnknown when there is none. connect.CodeOf does not
// recognize v1 errors, which v2 handlers receive from v1 clients.
func CodeOf(err error) connect.Code {
	if e, ok := errors.AsType[*connect.Error](err); ok && e != nil {
		return e.Code()
	}
	if e, ok := errors.AsType[*connectv1.Error](err); ok && e != nil {
		return connect.Code(e.Code())
	}
	return connect.CodeUnknown
}

// ServerInterceptor sends handler errors to clients the way connect-go v1
// handlers did. connect-go v2 sends a locally created *connect.Error as written
// but sends any other error, including v1 errors and errors received from a
// remote v2 service, as a bare code with no message.
func ServerInterceptor() connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			return ToV2Error(ctx, next(ctx, spec, stream))
		}
	}
}

// ToV2Error returns err as an error that a connect-go v2 server sends with the
// code, message, and details a v1 handler would have sent. Metadata on a v1
// error becomes response headers of the call in ctx. A nil error and a locally
// created v2 error are returned unchanged.
func ToV2Error(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if e, ok := errors.AsType[*connect.Error](err); ok && e != nil {
		if !e.IsRemote() {
			return err
		}
		local := connect.NewError(e.Code(), e.Message()).WithCause(err)
		for _, detail := range e.Details() {
			local = local.WithDetail(detail)
		}
		return local
	}
	if e, ok := errors.AsType[*connectv1.Error](err); ok && e != nil {
		local := connect.NewError(connect.Code(e.Code()), e.Message()).WithCause(err)
		for _, detail := range e.Details() {
			local = local.WithDetail(&connect.ErrorDetail{Type: detail.Type(), Value: detail.Bytes()})
		}
		if info, found := connect.CallInfoForServerContext(ctx); found {
			for key, values := range e.Meta() {
				info.ResponseHeader().SetValues(key, slices.Clone(values))
			}
		}
		return local
	}
	code := connect.CodeUnknown
	switch {
	case errors.Is(err, context.Canceled):
		code = connect.CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		code = connect.CodeDeadlineExceeded
	}
	return connect.NewError(code, err.Error()).WithCause(err)
}

// HTTPHeader copies a connect-go v2 header into an http.Header.
func HTTPHeader(header *connect.Header) http.Header {
	out := make(http.Header)
	if header == nil {
		return out
	}
	for key, values := range header.All() {
		out[key] = slices.Clone(values)
	}
	return out
}

// RequestHeader returns a copy of the request headers of the server call in
// ctx, or an empty header when ctx carries no call.
func RequestHeader(ctx context.Context) http.Header {
	info, ok := connect.CallInfoForServerContext(ctx)
	if !ok {
		return make(http.Header)
	}
	return HTTPHeader(info.RequestHeader())
}
