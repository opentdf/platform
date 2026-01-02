package auth

import (
	"context"
	"fmt"
	"strconv"

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
	// validator is initialized once and reused across all requests
	validator protovalidate.Validator
}

// NewProtoAttrMapper creates a new ProtoAttrMapper with the given configuration.
// If Validate is true, it initializes the protovalidate validator and panics on failure
// to prevent the service from running in a misconfigured state.
func NewProtoAttrMapper(allowed []string, requiredFields []string, validate bool) *ProtoAttrMapper {
	p := &ProtoAttrMapper{
		Allowed:        allowed,
		RequiredFields: requiredFields,
		Validate:       validate,
	}

	if validate {
		v, err := protovalidate.New()
		if err != nil {
			panic(fmt.Sprintf("failed to initialize protovalidate validator: %v", err))
		}
		p.validator = v
	}

	return p
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
					if p.Validate && p.validator != nil {
						if err := p.validator.Validate(m); err != nil {
							return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("protovalidate failed: %w", err))
						}
					}

					// Build attributes map - whitelist-only extraction
					attrs := map[string]string{}
					mr := m.ProtoReflect()
					for _, allow := range p.Allowed {
						if val, valOK := lookupProtoFieldString(mr, allow); valOK {
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
						if tk, tkOK := ctx.Value(tokenContextKey{}).(jwt.Token); tkOK {
							res := req.Spec().Procedure
							act := req.Spec().Procedure
							if allowed, err := e.Enforce(tk, res, act); !allowed {
								if err == nil {
									err = fmt.Errorf("permission denied for %s", req.Spec().Procedure)
								}
								return nil, connect.NewError(connect.CodePermissionDenied, err)
							}
						}
					}
				}
			}
			return next(ctx, req)
		})
	}
	return connect.UnaryInterceptorFunc(interceptor)
}

// helper to lookup a field on a protoreflect.Message and
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
	switch fld.Kind() { //nolint:exhaustive // only handle supported types
	case protoreflect.StringKind:
		s := v.String()
		// Treat empty strings as missing for required field validation
		if s == "" {
			return "", false
		}
		return s, true
	case protoreflect.Int32Kind, protoreflect.Int64Kind:
		return strconv.FormatInt(v.Int(), 10), true
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
		return strconv.FormatUint(v.Uint(), 10), true
	case protoreflect.BoolKind:
		return strconv.FormatBool(v.Bool()), true
	default:
		// Unsupported field types (enums, bytes, messages, etc.) are not extracted
		return "", false
	}
}

// context keys
type (
	casbinContextKey string
	tokenContextKey  struct{}
)

// GetCasbinAttrsFromContext retrieves the extracted proto attributes from the context.
// Returns the attributes map and true if present, or nil and false if not found.
func GetCasbinAttrsFromContext(ctx context.Context) (map[string]string, bool) {
	v := ctx.Value(casbinContextKey("casbin_attrs"))
	if v == nil {
		return nil, false
	}
	attrs, ok := v.(map[string]string)
	return attrs, ok
}
