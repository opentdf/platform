package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	connectv2 "connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/opentdf/platform/service/internal/connectcompat"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// ConnectAuthNInterceptorV2 authenticates connect-go v2 calls with the same
// checks as ConnectAuthNInterceptor. v2 runs server interceptors before the
// request body is read, so the check uses only the request headers and covers
// unary, streaming, and bidi RPCs.
func (a Authentication) ConnectAuthNInterceptorV2() connectv2.ServerInterceptor {
	return func(next connectv2.ServerFunc) connectv2.ServerFunc {
		return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
			method := http.MethodPost
			if info, ok := connecthttp.ServerInfoForContext(ctx); ok && info.HTTPMethod() != "" {
				method = info.HTTPMethod()
			}
			authedCtx, cerr := a.authenticateConnect(ctx, spec.Procedure, method, connectcompat.RequestHeader(ctx))
			if cerr != nil {
				return connectcompat.ToV2Error(ctx, cerr)
			}
			// Response headers set before next reach the client on success and on error.
			if publicRoute, _ := ctxAuth.PublicRouteFromContext(authedCtx); !publicRoute && a.dpopNonceManager.requireNonce {
				if info, ok := connectv2.CallInfoForServerContext(ctx); ok {
					info.ResponseHeader().Set("DPoP-Nonce", a.dpopNonceManager.getCurrentNonce())
				}
			}
			return next(authedCtx, spec, stream)
		}
	}
}

// ConnectAuthZInterceptorV2 authorizes connect-go v2 calls with the same policy
// as ConnectAuthZInterceptor. Unary procedures with a registered resource
// resolver receive the request message first so the resolver can read it, and
// the handler receives that message unchanged. Every other call is authorized
// from the procedure alone, before the body is read.
func (a Authentication) ConnectAuthZInterceptorV2() connectv2.ServerInterceptor {
	return func(next connectv2.ServerFunc) connectv2.ServerFunc {
		return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
			if publicRoute, ok := ctxAuth.PublicRouteFromContext(ctx); ok && publicRoute {
				return next(ctx, spec, stream)
			}

			token := ctxAuth.GetAccessTokenFromContext(ctx, a.logger)
			if token == nil {
				return connectv2.NewError(connectv2.CodeUnauthenticated, "missing access token in context")
			}

			roleReq, err := roleRequestForConnectProcedure(a.oidcConfiguration.Issuer, spec.Procedure)
			if err != nil {
				return connectv2.NewError(connectv2.CodeInvalidArgument, err.Error()).WithCause(err)
			}

			log := a.logger
			if spec.StreamType != connectv2.StreamTypeUnary || !a.hasResourceResolver(spec.Procedure) {
				handlerCtx, cerr := a.finalizeAuthzDecision(ctx, log, token, a.authorizeProcedure(ctx, log, token, spec.Procedure, roleReq.Action))
				if cerr != nil {
					return connectcompat.ToV2Error(ctx, cerr)
				}
				return next(handlerCtx, spec, stream)
			}

			// connect-go v2 runs interceptors before it reads the body, so
			// receive the request here for the resolver.
			msg, err := newRequestMessage(spec)
			if err != nil {
				log.WarnContext(ctx, "authz resolver request type unavailable",
					slog.String("procedure", spec.Procedure),
					slog.Any("error", err),
				)
				return connectv2.NewError(connectv2.CodePermissionDenied, "authorization context resolution failed")
			}
			if err := stream.Receive(msg); err != nil {
				return err
			}
			handlerCtx, cerr := a.finalizeAuthzDecision(ctx, log, token, a.authorize(ctx, log, token, spec.Procedure, msg, roleReq.Action))
			if cerr != nil {
				return connectcompat.ToV2Error(ctx, cerr)
			}
			return next(handlerCtx, spec, &receivedFirstStream{ServerStream: stream, first: msg})
		}
	}
}

// IPCServerInterceptorV2 is IPCUnaryServerInterceptor for connect-go v2 calls
// on the in-process server.
func (a Authentication) IPCServerInterceptorV2() connectv2.ServerInterceptor {
	return func(next connectv2.ServerFunc) connectv2.ServerFunc {
		return func(ctx context.Context, spec connectv2.Spec, stream connectv2.ServerStream) error {
			nextCtx, err := a.ipcServerContext(ctx, spec.Procedure, connectcompat.RequestHeader(ctx))
			if err != nil {
				return connectcompat.ToV2Error(ctx, err)
			}
			return next(nextCtx, spec, stream)
		}
	}
}

// hasResourceResolver reports whether authorizing procedure needs its request
// message, matching the conditions under which resolveResourceContext runs a
// resolver.
func (a *Authentication) hasResourceResolver(procedure string) bool {
	if a.authzResolverRegistry == nil || a.authorizer == nil || !a.authorizer.SupportsResourceAuthorization() {
		return false
	}
	_, ok := a.authzResolverRegistry.Get(procedure)
	return ok
}

// newRequestMessage allocates the request message type of spec's method.
func newRequestMessage(spec connectv2.Spec) (proto.Message, error) {
	method, ok := spec.Schema.(protoreflect.MethodDescriptor)
	if !ok {
		return nil, errors.New("procedure has no method descriptor")
	}
	messageType, err := protoregistry.GlobalTypes.FindMessageByName(method.Input().FullName())
	if err != nil {
		return nil, fmt.Errorf("find request type %s: %w", method.Input().FullName(), err)
	}
	return messageType.New().Interface(), nil
}

// receivedFirstStream replays a request message that an interceptor already
// received, then reads the rest of the stream.
type receivedFirstStream struct {
	connectv2.ServerStream

	first proto.Message
}

func (s *receivedFirstStream) Receive(msg any) error {
	if s.first == nil {
		return s.ServerStream.Receive(msg)
	}
	dst, ok := msg.(proto.Message)
	if !ok {
		return connectv2.Errorf(connectv2.CodeInternal, "receive into %T: not a protobuf message", msg)
	}
	proto.Reset(dst)
	proto.Merge(dst, s.first)
	s.first = nil
	return nil
}
