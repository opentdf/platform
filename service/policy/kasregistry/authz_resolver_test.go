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
	key          *policy.KasKey
	listKeysResp *kasregistry.ListKeysResponse
	err          error
	identifier   any
	listKeysReq  *kasregistry.ListKeysRequest
}

func (f *fakeGetKeyAuthzDBClient) GetKey(_ context.Context, identifier any) (*policy.KasKey, error) {
	f.identifier = identifier
	return f.key, f.err
}

func (f *fakeGetKeyAuthzDBClient) ListKeys(_ context.Context, req *kasregistry.ListKeysRequest) (*kasregistry.ListKeysResponse, error) {
	f.listKeysReq = req
	return f.listKeysResp, f.err
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
	key := &policy.KasKey{
		KasUri: "",
		Key:    &policy.AsymmetricKey{KeyId: validKeyID},
	}
	resolverCtx := authz.NewResolverContext()

	_, err := resolveGetKeyKasURI(t.Context(), &kasregistry.GetKeyRequest{
		Identifier: &kasregistry.GetKeyRequest_Id{Id: validUUID},
	}, &resolverCtx, &fakeGetKeyAuthzDBClient{key: key})

	require.ErrorIs(t, err, errResolvedKasURIEmpty)
}

func TestListKeysAuthzResolver_KasURIFilterUsesReturnedKeyURIs(t *testing.T) {
	const kasURI = "https://kas-a.example.com"
	resp := &kasregistry.ListKeysResponse{
		KasKeys: []*policy.KasKey{
			{KasUri: kasURI, Key: &policy.AsymmetricKey{KeyId: validKeyID}},
		},
	}
	dbClient := &fakeGetKeyAuthzDBClient{listKeysResp: resp}
	req := &kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{KasUri: kasURI},
	}
	resolverCtx := authz.NewResolverContext()

	err := resolveListKeysAuthzResources(t.Context(), req, &resolverCtx, dbClient)

	require.NoError(t, err)
	require.Len(t, resolverCtx.Resources, 1)
	require.Equal(t, kasURI, (*resolverCtx.Resources[0])[authzDimensionKasURI])
	require.Same(t, req, dbClient.listKeysReq)
}

func TestListKeysAuthzResolver_KasIDFilterUsesReturnedKeyURIs(t *testing.T) {
	const kasURI = "https://kas-a.example.com"
	dbClient := &fakeGetKeyAuthzDBClient{
		listKeysResp: &kasregistry.ListKeysResponse{
			KasKeys: []*policy.KasKey{
				{KasUri: kasURI, Key: &policy.AsymmetricKey{KeyId: validKeyID}},
			},
		},
	}
	req := &kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasId{KasId: validUUID},
	}
	resolverCtx := authz.NewResolverContext()

	err := resolveListKeysAuthzResources(t.Context(), req, &resolverCtx, dbClient)

	require.NoError(t, err)
	require.Len(t, resolverCtx.Resources, 1)
	require.Equal(t, kasURI, (*resolverCtx.Resources[0])[authzDimensionKasURI])
	require.Same(t, req, dbClient.listKeysReq)
}

func TestListKeysAuthzResolver_KasNameFilterUsesReturnedKeyURIs(t *testing.T) {
	const kasURI = "https://kas-a.example.com"
	dbClient := &fakeGetKeyAuthzDBClient{
		listKeysResp: &kasregistry.ListKeysResponse{
			KasKeys: []*policy.KasKey{
				{KasUri: kasURI, Key: &policy.AsymmetricKey{KeyId: validKeyID}},
			},
		},
	}
	req := &kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasName{KasName: "kas-a"},
	}
	resolverCtx := authz.NewResolverContext()

	err := resolveListKeysAuthzResources(t.Context(), req, &resolverCtx, dbClient)

	require.NoError(t, err)
	require.Len(t, resolverCtx.Resources, 1)
	require.Equal(t, kasURI, (*resolverCtx.Resources[0])[authzDimensionKasURI])
	require.Same(t, req, dbClient.listKeysReq)
}

func TestListKeysAuthzResolver_UnfilteredListUsesReturnedKeyURIs(t *testing.T) {
	const (
		kasURIA = "https://kas-a.example.com"
		kasURIB = "https://kas-b.example.com"
	)
	dbClient := &fakeGetKeyAuthzDBClient{
		listKeysResp: &kasregistry.ListKeysResponse{
			KasKeys: []*policy.KasKey{
				{KasUri: kasURIA, Key: &policy.AsymmetricKey{KeyId: "a-1"}},
				{KasUri: kasURIA, Key: &policy.AsymmetricKey{KeyId: "a-2"}},
				{KasUri: kasURIB, Key: &policy.AsymmetricKey{KeyId: "b-1"}},
			},
		},
	}
	resolverCtx := authz.NewResolverContext()

	err := resolveListKeysAuthzResources(t.Context(), &kasregistry.ListKeysRequest{}, &resolverCtx, dbClient)

	require.NoError(t, err)
	require.Len(t, resolverCtx.Resources, 2)
	require.Equal(t, kasURIA, (*resolverCtx.Resources[0])[authzDimensionKasURI])
	require.Equal(t, kasURIB, (*resolverCtx.Resources[1])[authzDimensionKasURI])
}

func TestListKeysAuthzResolver_EmptyUnfilteredListUsesWildcard(t *testing.T) {
	dbClient := &fakeGetKeyAuthzDBClient{listKeysResp: &kasregistry.ListKeysResponse{}}
	resolverCtx := authz.NewResolverContext()

	err := resolveListKeysAuthzResources(t.Context(), &kasregistry.ListKeysRequest{}, &resolverCtx, dbClient)

	require.NoError(t, err)
	require.Empty(t, resolverCtx.Resources)
}

func TestListKeysAuthzResolver_DBLookupErrorFailsResolution(t *testing.T) {
	dbErr := errors.New("db unavailable")
	resolverCtx := authz.NewResolverContext()

	err := resolveListKeysAuthzResources(t.Context(), &kasregistry.ListKeysRequest{}, &resolverCtx, &fakeGetKeyAuthzDBClient{err: dbErr})

	require.ErrorIs(t, err, errResolveListKeysForAuthz)
	require.ErrorIs(t, err, dbErr)
	require.Empty(t, resolverCtx.Resources)
}

func TestListKeysAuthzResolver_InvalidRequestType(t *testing.T) {
	svc := KeyAccessServerRegistry{}

	_, err := svc.listKeysAuthzResolver(t.Context(), connect.NewRequest(&kasregistry.GetKeyRequest{}))

	require.ErrorIs(t, err, errUnexpectedListKeysAuthzRequestType)
}

func TestListKeysAuthzResolver_DBReturnsNilNil_ReturnsErrResolvedListKeysResponseNil(t *testing.T) {
	resolverCtx := authz.NewResolverContext()

	err := resolveListKeysAuthzResources(t.Context(), &kasregistry.ListKeysRequest{}, &resolverCtx, &fakeGetKeyAuthzDBClient{})

	require.ErrorIs(t, err, errResolvedListKeysResponseNil)
}

func TestListKeysAuthzResolver_EmptyKasURI_ReturnsErrResolvedKasURIEmpty(t *testing.T) {
	dbClient := &fakeGetKeyAuthzDBClient{
		listKeysResp: &kasregistry.ListKeysResponse{
			KasKeys: []*policy.KasKey{{Key: &policy.AsymmetricKey{KeyId: validKeyID}}},
		},
	}
	resolverCtx := authz.NewResolverContext()

	err := resolveListKeysAuthzResources(t.Context(), &kasregistry.ListKeysRequest{}, &resolverCtx, dbClient)

	require.ErrorIs(t, err, errResolvedKasURIEmpty)
}
