package kasregistry

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	kasr "github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/internal/auth/authz"
)

const (
	authzDimensionKasURI = "kas_uri"
	// resolverCacheKeyKasKey is the key used to cache a resolved KAS key in the authz resolver context.
	resolverCacheKeyKasKey = "kas_key"
)

var (
	errUnexpectedGetKeyAuthzRequestType = errors.New("unexpected GetKey authz request type")
	errResolvedKasURIEmpty              = errors.New("resolved KAS URI is empty")
	errKeyIdentifierRequired            = errors.New("key identifier is required")
	errKeyIDRequired                    = errors.New("key id is required")
	errUnsupportedGetKeyIdentifier      = errors.New("unsupported GetKey identifier")
	errResolveKasKeyForAuthz            = errors.New("failed to resolve KAS key for authz")
)

func (s KeyAccessServerRegistry) getKeyAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()

	msg, ok := req.Any().(*kasr.GetKeyRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("%w: %T", errUnexpectedGetKeyAuthzRequestType, req.Any())
	}

	kasURI, err := s.resolveGetKeyKasURI(ctx, msg, &resolverCtx)
	if err != nil {
		return resolverCtx, err
	}
	if kasURI == "" {
		return resolverCtx, errResolvedKasURIEmpty
	}

	res := resolverCtx.NewResource()
	res.AddDimension(authzDimensionKasURI, kasURI)

	return resolverCtx, nil
}

func (s KeyAccessServerRegistry) resolveGetKeyKasURI(ctx context.Context, msg *kasr.GetKeyRequest, resolverCtx *authz.ResolverContext) (string, error) {
	switch identifier := msg.GetIdentifier().(type) {
	case *kasr.GetKeyRequest_Key:
		keyIdentifier := identifier.Key
		if keyIdentifier == nil {
			return "", errKeyIdentifierRequired
		}
		if uri := keyIdentifier.GetUri(); uri != "" {
			return uri, nil
		}
	case *kasr.GetKeyRequest_Id:
		if identifier.Id == "" {
			return "", errKeyIDRequired
		}
	default:
		return "", errUnsupportedGetKeyIdentifier
	}

	key, err := s.dbClient.GetKey(ctx, msg.GetIdentifier())
	if err != nil {
		return "", fmt.Errorf("%w: %w", errResolveKasKeyForAuthz, err)
	}

	resolverCtx.SetResolvedData(resolverCacheKeyKasKey, key)
	return key.GetKasUri(), nil
}
