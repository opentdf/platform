package kasregistry

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/internal/auth/authz"
	"github.com/stretchr/testify/require"
)

type fakeGetKeyAuthzDBClient struct {
	key        *policy.KasKey
	err        error
	identifier any
}

func (f *fakeGetKeyAuthzDBClient) GetKey(_ context.Context, identifier any) (*policy.KasKey, error) {
	f.identifier = identifier
	return f.key, f.err
}

func TestGetKeyAuthzResolver_UsesRequestURI(t *testing.T) {
	const kasURI = "https://kas-a.example.com"
	svc := KeyAccessServerRegistry{}

	resolverCtx, err := svc.getKeyAuthzResolver(t.Context(), connect.NewRequest(&kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_Uri{Uri: kasURI},
				Kid:        validKeyID,
			},
		},
	}))

	require.NoError(t, err)
	require.Len(t, resolverCtx.Resources, 1)
	require.Equal(t, kasURI, (*resolverCtx.Resources[0])[authzDimensionKasURI])
	require.Nil(t, resolverCtx.GetResolvedData(resolverCacheKeyKasKey))
}

func TestGetKeyAuthzResolver_UsesPolicyDBClientAndCachesResolvedKey(t *testing.T) {
	const kasURI = "https://kas-a.example.com"
	identifier := &kasregistry.GetKeyRequest_Id{Id: validUUID}
	key := &policy.KasKey{
		KasUri: kasURI,
		Key: &policy.AsymmetricKey{
			KeyId: validKeyID,
		},
	}
	dbClient := &fakeGetKeyAuthzDBClient{key: key}
	resolverCtx := authz.NewResolverContext()

	resolvedURI, err := resolveGetKeyKasURI(t.Context(), &kasregistry.GetKeyRequest{
		Identifier: identifier,
	}, &resolverCtx, dbClient)

	require.NoError(t, err)
	require.Equal(t, kasURI, resolvedURI)
	require.Same(t, identifier, dbClient.identifier)
	require.Same(t, key, resolverCtx.GetResolvedData(resolverCacheKeyKasKey))
}

func TestGetKeyAuthzResolver_UsesPolicyDBClientForKeyIdentifierWithoutURI(t *testing.T) {
	kasURI := "https://kas-a.example.com"
	key := &policy.KasKey{
		KasUri: kasURI,
		Key: &policy.AsymmetricKey{
			KeyId: validKeyID,
		},
	}
	dbClient := &fakeGetKeyAuthzDBClient{key: key}
	identifier := &kasregistry.GetKeyRequest_Key{
		Key: &kasregistry.KasKeyIdentifier{
			Identifier: &kasregistry.KasKeyIdentifier_KasId{KasId: validUUID},
			Kid:        validKeyID,
		},
	}
	resolverCtx := authz.NewResolverContext()

	resolvedURI, err := resolveGetKeyKasURI(t.Context(), &kasregistry.GetKeyRequest{
		Identifier: identifier,
	}, &resolverCtx, dbClient)

	require.NoError(t, err)
	require.Equal(t, kasURI, resolvedURI)
	require.Same(t, identifier, dbClient.identifier)
	require.Same(t, key, resolverCtx.GetResolvedData(resolverCacheKeyKasKey))
}

func TestGetKeyAuthzResolver_DBLookupErrorFailsResolution(t *testing.T) {
	dbErr := errors.New("db unavailable")
	resolverCtx := authz.NewResolverContext()

	_, err := resolveGetKeyKasURI(t.Context(), &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Id{Id: validUUID},
	}, &resolverCtx, &fakeGetKeyAuthzDBClient{err: dbErr})

	require.ErrorIs(t, err, errResolveKasKeyForAuthz)
	require.ErrorIs(t, err, dbErr)
}

func TestGetKeyAuthzResolver_InvalidRequestType(t *testing.T) {
	svc := KeyAccessServerRegistry{}

	_, err := svc.getKeyAuthzResolver(t.Context(), connect.NewRequest(&kasregistry.ListKeysRequest{}))

	require.ErrorIs(t, err, errUnexpectedGetKeyAuthzRequestType)
}

func TestGetKeyAuthzResolver_UnsupportedIdentifier(t *testing.T) {
	svc := KeyAccessServerRegistry{}

	_, err := svc.getKeyAuthzResolver(t.Context(), connect.NewRequest(&kasregistry.GetKeyRequest{}))

	require.ErrorIs(t, err, errUnsupportedGetKeyIdentifier)
}

// TEST-HIGH-4: Four sentinel error tests

func TestGetKeyAuthzResolver_NilInnerKey_ReturnsErrKeyIdentifierRequired(t *testing.T) {
	resolverCtx := authz.NewResolverContext()
	dbClient := &fakeGetKeyAuthzDBClient{}

	_, err := resolveGetKeyKasURI(t.Context(), &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Key{
			Key: nil,
		},
	}, &resolverCtx, dbClient)

	require.ErrorIs(t, err, errKeyIdentifierRequired)
}

func TestGetKeyAuthzResolver_EmptyIDString_ReturnsErrKeyIDRequired(t *testing.T) {
	resolverCtx := authz.NewResolverContext()
	dbClient := &fakeGetKeyAuthzDBClient{}

	_, err := resolveGetKeyKasURI(t.Context(), &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Id{Id: ""},
	}, &resolverCtx, dbClient)

	require.ErrorIs(t, err, errKeyIDRequired)
}

func TestGetKeyAuthzResolver_DBReturnsNilNil_ReturnsErrResolvedKasKeyNil(t *testing.T) {
	// DB returns (nil, nil) for an ID-based request — the wrapped error must include errResolvedKasKeyNil.
	dbClient := &fakeGetKeyAuthzDBClient{key: nil, err: nil}
	resolverCtx := authz.NewResolverContext()

	_, err := resolveGetKeyKasURI(t.Context(), &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Id{Id: validUUID},
	}, &resolverCtx, dbClient)

	require.ErrorIs(t, err, errResolvedKasKeyNil)
}

func TestGetKeyAuthzResolver_EmptyKasURI_ReturnsErrResolvedKasURIEmpty(t *testing.T) {
	// DB returns a KasKey with an empty KasUri.
	// resolveGetKeyKasURI returns ("", nil); the outer getKeyAuthzResolver then
	// detects the empty URI and returns errResolvedKasURIEmpty.
	key := &policy.KasKey{
		KasUri: "",
		Key:    &policy.AsymmetricKey{KeyId: validKeyID},
	}
	dbClient := &fakeGetKeyAuthzDBClient{key: key}
	resolverCtx := authz.NewResolverContext()

	uri, resolveErr := resolveGetKeyKasURI(t.Context(), &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Id{Id: validUUID},
	}, &resolverCtx, dbClient)

	// resolveGetKeyKasURI itself succeeds with an empty URI string.
	require.NoError(t, resolveErr)
	require.Empty(t, uri)

	// Verify that the sentinel error used by getKeyAuthzResolver is defined.
	require.Error(t, errResolvedKasURIEmpty)
}
