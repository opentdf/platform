package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"connectrpc.com/connect"
	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
)

var (
	// ErrInvalidConnectRPCRegistration reports a service registration that
	// cannot be mounted, such as one that sets both a connect-go v1 and a v2
	// handler or one whose procedures are already mounted.
	ErrInvalidConnectRPCRegistration = errors.New("invalid connect-rpc registration")
	// ErrMissingInterceptorForm reports an extra interceptor that has no form for
	// the connect-go version of a service being registered.
	ErrMissingInterceptorForm = errors.New("extra connect interceptor has no form for this connect-go version")
)

// ExtraInterceptor is a programmatic server interceptor in its connect-go v1
// and v2 forms. The platform serves services on both versions, and each
// service runs only the form for its version, so an interceptor that should
// cover every service needs both forms.
type ExtraInterceptor struct {
	// Name identifies the interceptor in startup errors.
	Name string
	// V1 runs on services registered with a connect-go v1 handler.
	V1 connect.Interceptor
	// V2 runs on services registered with a connect-go v2 server.
	V2 connectv2.ServerInterceptor
}

// AddExtraInterceptors appends extras after the platform interceptors. When an
// extra lacks the form for a connect-go version, services on that version can
// no longer be registered, and services mounted from the interceptor lists
// directly fail every call, so the interceptor is never silently skipped.
func (c *ConnectRPC) AddExtraInterceptors(extras ...ExtraInterceptor) {
	var v1s []connect.Interceptor
	var v2s []connectv2.ServerInterceptor
	var missingV1, missingV2 []string
	for _, extra := range extras {
		if extra.V1 != nil {
			v1s = append(v1s, extra.V1)
		} else {
			missingV1 = append(missingV1, extra.Name)
		}
		if extra.V2 != nil {
			v2s = append(v2s, extra.V2)
		} else {
			missingV2 = append(missingV2, extra.Name)
		}
	}
	if len(missingV1) > 0 {
		v1s = append(v1s, missingFormGuardV1(missingV1))
		c.missingV1 = append(c.missingV1, missingV1...)
	}
	if len(missingV2) > 0 {
		v2s = append(v2s, missingFormGuardV2(missingV2))
		c.missingV2 = append(c.missingV2, missingV2...)
	}
	if len(v1s) > 0 {
		c.Interceptors = append(c.Interceptors, connect.WithInterceptors(v1s...))
	}
	c.ServerInterceptors = append(c.ServerInterceptors, v2s...)
}

// RegisterConnectV1 mounts a connect-go v1 handler built with the server's
// handler options.
func (c *ConnectRPC) RegisterConnectV1(service string, newHandler func(...connect.HandlerOption) (string, http.Handler)) error {
	if len(c.missingV1) > 0 {
		return fmt.Errorf("%w: %s uses connect-go v1 but interceptors %s have no v1 form", ErrMissingInterceptorForm, service, strings.Join(c.missingV1, ", "))
	}
	path, handler := newHandler(c.Interceptors...)
	c.Mux.Handle(path, handler)
	c.ServiceReflection = append(c.ServiceReflection, service)
	return nil
}

// RegisterConnectV2 registers a service on its own connect-go v2 server with
// the server interceptors and mounts it with the server's mount options
// followed by opts.
func (c *ConnectRPC) RegisterConnectV2(service string, register func(*connectv2.Server), opts ...connecthttp.Option) (err error) {
	if len(c.missingV2) > 0 {
		return fmt.Errorf("%w: %s uses connect-go v2 but interceptors %s have no v2 form", ErrMissingInterceptorForm, service, strings.Join(c.missingV2, ", "))
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %s: %v", ErrInvalidConnectRPCRegistration, service, r)
		}
	}()
	srv := connectv2.NewServer(c.ServerInterceptors...)
	register(srv)
	connecthttp.Mount(c.Mux, srv, append(slices.Clone(c.MountOptions), opts...)...)
	c.ServiceReflection = append(c.ServiceReflection, service)
	return nil
}

func missingFormError(version string, names []string) string {
	return fmt.Sprintf("connect interceptors %s have no connect-go %s form", strings.Join(names, ", "), version)
}

func missingFormGuardV1(names []string) connect.Interceptor {
	message := missingFormError("v1", names)
	return guardInterceptor{err: func() error { return connect.NewError(connect.CodeInternal, errors.New(message)) }}
}

func missingFormGuardV2(names []string) connectv2.ServerInterceptor {
	message := missingFormError("v2", names)
	return func(connectv2.ServerFunc) connectv2.ServerFunc {
		return func(context.Context, connectv2.Spec, connectv2.ServerStream) error {
			return connectv2.NewError(connectv2.CodeInternal, message)
		}
	}
}

// guardInterceptor fails every server call.
type guardInterceptor struct {
	err func() error
}

func (g guardInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			return next(ctx, req)
		}
		return nil, g.err()
	}
}

func (g guardInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (g guardInterceptor) WrapStreamingHandler(connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(context.Context, connect.StreamingHandlerConn) error {
		return g.err()
	}
}
