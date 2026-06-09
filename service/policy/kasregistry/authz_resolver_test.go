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

func TestGetKeyAuthzResolver_InvalidRequestType(t *testing.T) {
	svc := KeyAccessServerRegistry{}

	_, err := svc.getKeyAuthzResolver(t.Context(), connect.NewRequest(&kasregistry.ListKeysRequest{}))

	require.True(t, errors.Is(err, errUnexpectedGetKeyAuthzRequestType))
}

func TestGetKeyAuthzResolver_UnsupportedIdentifier(t *testing.T) {
	svc := KeyAccessServerRegistry{}

	_, err := svc.getKeyAuthzResolver(t.Context(), connect.NewRequest(&kasregistry.GetKeyRequest{}))

	require.True(t, errors.Is(err, errUnsupportedGetKeyIdentifier))
}
