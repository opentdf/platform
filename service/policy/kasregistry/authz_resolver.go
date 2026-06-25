package kasregistry

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	kasr "github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/internal/auth/authz"
)

const (
	authzDimensionKasURI = "kas_uri"
	// resolverCacheKeyKasKey is the key used to cache a resolved KAS key in the authz resolver context.
	resolverCacheKeyKasKey = "kas_key"
	// resolverCacheKeyListKeysResponse is the key used to cache the authorized ListKeys response.
	resolverCacheKeyListKeysResponse = "list_keys_response"
)

var (
	errUnexpectedGetKeyAuthzRequestType   = errors.New("unexpected GetKey authz request type")
	errUnexpectedListKeysAuthzRequestType = errors.New("unexpected ListKeys authz request type")
	errResolvedKasURIEmpty                = errors.New("resolved KAS URI is empty")
	errKeyIdentifierRequired              = errors.New("key identifier is required")
	errKeyIDRequired                      = errors.New("key id is required")
	errUnsupportedGetKeyIdentifier        = errors.New("unsupported GetKey identifier")
	errResolveKasKeyForAuthz              = errors.New("failed to resolve KAS key for authz")
	errResolvedKasKeyNil                  = errors.New("resolved KAS key is nil")
	errResolveListKeysForAuthz            = errors.New("failed to resolve ListKeys for authz")
	errResolvedListKeysResponseNil        = errors.New("resolved ListKeys response is nil")
)

type keyAuthzDBClient interface {
	GetKey(context.Context, any) (*policy.KasKey, error)
	ListKeys(context.Context, *kasr.ListKeysRequest) (*kasr.ListKeysResponse, error)
}

func (s *KeyAccessServerRegistry) getKeyAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	return s.resolveGetKeyAuthzContext(ctx, req)
}

func (s *KeyAccessServerRegistry) listKeysAuthzResolver(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	return s.resolveListKeysAuthzContext(ctx, req, s.dbClient)
}

func (s *KeyAccessServerRegistry) resolveGetKeyAuthzContext(ctx context.Context, req connect.AnyRequest) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()

	msg, ok := req.Any().(*kasr.GetKeyRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("%w: %T", errUnexpectedGetKeyAuthzRequestType, req.Any())
	}

	kasURI, err := resolveGetKeyKasURI(ctx, msg, &resolverCtx, s.dbClient)
	if err != nil {
		return resolverCtx, err
	}

	res := resolverCtx.NewResource()
	res.AddDimension(authzDimensionKasURI, kasURI)

	return resolverCtx, nil
}

func (s *KeyAccessServerRegistry) resolveListKeysAuthzContext(ctx context.Context, req connect.AnyRequest, dbClient keyAuthzDBClient) (authz.ResolverContext, error) {
	resolverCtx := authz.NewResolverContext()

	msg, ok := req.Any().(*kasr.ListKeysRequest)
	if !ok {
		return resolverCtx, fmt.Errorf("%w: %T", errUnexpectedListKeysAuthzRequestType, req.Any())
	}

	if err := resolveListKeysAuthzResources(ctx, msg, &resolverCtx, dbClient); err != nil {
		return resolverCtx, err
	}

	return resolverCtx, nil
}

func resolveGetKeyKasURI(ctx context.Context, msg *kasr.GetKeyRequest, resolverCtx *authz.ResolverContext, dbClient keyAuthzDBClient) (string, error) {
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

	key, err := dbClient.GetKey(ctx, msg.GetIdentifier())
	if err != nil {
		return "", fmt.Errorf("%w: %w", errResolveKasKeyForAuthz, err)
	}
	if key == nil {
		return "", fmt.Errorf("%w: %w", errResolveKasKeyForAuthz, errResolvedKasKeyNil)
	}
	if key.GetKasUri() == "" {
		return "", errResolvedKasURIEmpty
	}

	resolverCtx.SetResolvedData(resolverCacheKeyKasKey, key)
	return key.GetKasUri(), nil
}

func resolveListKeysAuthzResources(ctx context.Context, msg *kasr.ListKeysRequest, resolverCtx *authz.ResolverContext, dbClient keyAuthzDBClient) error {
	// TODO: Replace this ListKeys call with a smaller query that returns only the distinct KAS URIs present for the request filters.
	resp, err := dbClient.ListKeys(ctx, msg)
	if err != nil {
		return fmt.Errorf("%w: %w", errResolveListKeysForAuthz, err)
	}
	if resp == nil {
		return fmt.Errorf("%w: %w", errResolveListKeysForAuthz, errResolvedListKeysResponseNil)
	}

	resolverCtx.SetResolvedData(resolverCacheKeyListKeysResponse, resp)
	return resolveListKeysReturnedKeyURIs(resolverCtx, resp.GetKasKeys())
}

func resolveListKeysReturnedKeyURIs(resolverCtx *authz.ResolverContext, keys []*policy.KasKey) error {
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		kasURI := key.GetKasUri()
		if kasURI == "" {
			return errResolvedKasURIEmpty
		}
		if _, ok := seen[kasURI]; ok {
			continue
		}
		seen[kasURI] = struct{}{}
		addKasURIResource(resolverCtx, kasURI)
	}
	return nil
}

func addKasURIResource(resolverCtx *authz.ResolverContext, kasURI string) {
	res := resolverCtx.NewResource()
	res.AddDimension(authzDimensionKasURI, kasURI)
}
