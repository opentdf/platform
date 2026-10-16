package serviceregistry

import (
	"errors"
	"maps"

	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/opentdf/platform/service/internal/server"
)

var (
	// ErrNoConnectRPCHandler reports a service that registers no Connect handler.
	ErrNoConnectRPCHandler = errors.New("service did not register a connect-rpc handler")
	// ErrInvalidConnectRPCRegistration reports a Connect registration that cannot
	// be mounted. The platform fails to start when a service returns it.
	ErrInvalidConnectRPCRegistration = server.ErrInvalidConnectRPCRegistration
	// ErrMissingInterceptorForm reports an extra interceptor without a form for
	// the connect-go version of a service. The platform fails to start when a
	// service returns it.
	ErrMissingInterceptorForm = server.ErrMissingInterceptorForm
)

// ConnectReadLimitOptions returns connect-go v2 mount options that cap each
// request message at maxBytes, as read and after gzip decompression, for use
// in ConnectRPCMountOptions. Non-positive values use the platform default of
// 4 MiB. The platform applies server.grpc.maxRecvMsgSize to external services
// before service options.
func ConnectReadLimitOptions(maxBytes int) []connecthttp.Option {
	return server.ReadLimitMountOptions(maxBytes)
}

// ConnectProcedureReadLimits returns a connect-go v2 mount option that sets the
// read limit of individual procedures, keyed by procedure path such as
// "/pkg.Service/Method". It applies after other options, so procedures listed
// here override service and platform limits.
func ConnectProcedureReadLimits(limits map[string]int) connecthttp.Option {
	limits = maps.Clone(limits)
	return connecthttp.WithConditionalOptions(func(spec connectv2.Spec) []connecthttp.Option {
		if maxBytes, ok := limits[spec.Procedure]; ok {
			return server.ReadLimitMountOptions(maxBytes)
		}
		return nil
	})
}
