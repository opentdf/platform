package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"connectrpc.com/connect"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
)

// UnaryServerInterceptor is a grpc interceptor that verifies the token in the metadata
func (a Authentication) ConnectUnaryServerInterceptor() connect.UnaryInterceptorFunc {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// if the token is already in the context, skip the interceptor
			if ctxAuth.GetAccessTokenFromContext(ctx, nil) != nil {
				return next(ctx, req)
			}

			ri := receiverInfo{
				u: []string{req.Spec().Procedure},
				m: []string{http.MethodPost},
			}

			ri.u = append(ri.u, a.lookupGatewayPaths(ctx, req.Spec().Procedure, req.Header())...)

			// Interceptor Logic
			// Allow health checks and other public routes to pass through
			if slices.ContainsFunc(a.publicRoutes, a.isPublicRoute(req.Spec().Procedure)) { //nolint:contextcheck // There is no way to pass a context here
				return next(ctx, req)
			}

			token, tokenRaw, err := a.parseTokenFromHeader(req.Header())
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			key, err := a.checkToken(ctx, token, tokenRaw, ri, req.Header()["Dpop"])
			if err != nil && !errors.Is(err, ErrNoDPoPSkipCheck) {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			// Fetch userinfo, only exchange token if needed
			userInfoRaw, err := a.GetUserInfoWithExchange(ctx, token.Issuer(), token.Subject(), tokenRaw)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			nextCtx := ctxAuth.ContextWithAuthNInfo(ctx, key, token, tokenRaw, userInfoRaw)

			// parse the rpc method
			p := strings.Split(req.Spec().Procedure, "/")
			resource := p[1] + "/" + p[2]
			action := getAction(p[2])
			if !a.enforcer.Enforce(token, userInfoRaw, resource, action) {
				a.logger.Warn("permission denied", slog.String("azp", token.Subject()))
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("permission denied"))
			}

			return next(nextCtx, req)
		})
	})
}
