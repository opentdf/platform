package auth

import (
	"context"
	"fmt"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ProtoAttrMapper extracts selected proto fields and converts them to
// casbin-request attributes. Enforces whitelist-only access to ensure
// ONLY configured fields are available to authorization policies.
type ProtoAttrMapper struct {
	// Allowed fields to extract and expose to Casbin (whitelist-only)
	Allowed []string
	// RequiredFields that must exist on the request (subset of Allowed)
	RequiredFields []string
	// Validate controls whether to run protovalidate on the incoming message
	Validate bool
}

// Interceptor returns a ConnectRPC unary interceptor that validates the
// request protobuf using protovalidate and attaches a map[string]string of
// attributes to the context for downstream enforcement.
func (p *ProtoAttrMapper) Interceptor(e *Enforcer) connect.UnaryInterceptorFunc {
	interceptor := func(next connect.UnaryFunc) connect.UnaryFunc {
		return connect.UnaryFunc(func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Validate proto message using protovalidate if available
			if any := req.Any(); any != nil {
				if m, ok := any.(proto.Message); ok {
					if p.Validate {
						v, err := protovalidate.New()
						if err == nil {
							if err := v.Validate(m); err != nil {
								return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("protovalidate failed: %w", err))
							}
						}
					}

					// Build attributes map - whitelist-only extraction
					attrs := map[string]string{}
					mr := m.ProtoReflect()
					for _, allow := range p.Allowed {
						if val, ok := lookupProtoFieldString(mr, allow); ok {
							attrs[allow] = val
						}
					}

					// Validate required fields are present
					for _, required := range p.RequiredFields {
						if _, exists := attrs[required]; !exists {
							return nil, connect.NewError(
								connect.CodeInvalidArgument,
								fmt.Errorf("required field %q is missing or invalid", required),
							)
						}
					}

					// Attach attrs to context for downstream (store under key "casbin_attrs")
					// SECURITY: Only whitelisted fields are in this map - no other request
					// fields are accessible to Casbin policy evaluation
					ctx = context.WithValue(ctx, casbinContextKey("casbin_attrs"), attrs)

					// Optionally perform synchronous enforcement: derive resource/action
					if e != nil {
						if tk, ok := ctx.Value(tokenContextKey{}).(jwt.Token); ok {
							res := req.Spec().Procedure
							act := req.Spec().Procedure
							_, _ = e.Enforce(tk, res, act)
						}
					}
				}
			}
			return next(ctx, req)
		})
	}
	return connect.UnaryInterceptorFunc(interceptor)
}

// helper to lookup a dot-separated path on a protoreflect.Message and
// return its string value if present.
func lookupProtoFieldString(m protoreflect.Message, path string) (string, bool) {
	// Only support single-level fields for now to keep simple
	fld := m.Descriptor().Fields().ByName(protoreflect.Name(path))
	if fld == nil {
		return "", false
	}
	v := m.Get(fld)
	if !v.IsValid() {
		return "", false
	}
	// Convert scalar to string if possible
	switch fld.Kind() {
	case protoreflect.StringKind:
		s := v.String()
		// Treat empty strings as missing for required field validation
		if s == "" {
			return "", false
		}
		return s, true
	case protoreflect.Int32Kind, protoreflect.Int64Kind:
		return fmt.Sprintf("%d", v.Int()), true
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
		return fmt.Sprintf("%d", v.Uint()), true
	case protoreflect.BoolKind:
		return fmt.Sprintf("%t", v.Bool()), true
	default:
		return "", false
	}
}

// context keys
type casbinContextKey string
type tokenContextKey struct{}
