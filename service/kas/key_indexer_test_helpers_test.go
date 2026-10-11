package kas

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/service/trust"
	"github.com/stretchr/testify/require"
)

const emptyKASURI = "https://empty-kas.example.com"

var (
	errRegistryKeyNotFound = connect.NewError(connect.CodeNotFound, errors.New("key not found"))
	errRegistryDenied      = connect.NewError(connect.CodePermissionDenied, errors.New("denied"))
	errRegistryUnavailable = connect.NewError(connect.CodeUnavailable, errors.New("unavailable"))
	errRegistryInternal    = connect.NewError(connect.CodeInternal, errors.New("database error"))
	errRegistryScoped      = errors.New("scoped failed")
	errRegistryDefault     = errors.New("default failed")
)

type keyIndexFixtures struct {
	requestShared, requestLegacy, requestNonLegacy *policy.KasKey
	defaultShared, defaultLegacy, defaultNonLegacy *policy.KasKey
	keysByURI                                      map[string][]*policy.KasKey
}

func newKeyIndexFixtures() keyIndexFixtures {
	// Distinct details for the shared KID let assertions verify its source registration.
	f := keyIndexFixtures{
		requestShared:    newRegistryKey("shared", requestKASURI, true),
		requestLegacy:    newRegistryKey("request-legacy", requestKASURI, true),
		requestNonLegacy: newRegistryKey("request-nonlegacy", requestKASURI, false),
		defaultShared:    newRegistryKey("shared", defaultKASURI, true),
		defaultLegacy:    newRegistryKey("default-legacy", defaultKASURI, true),
		defaultNonLegacy: newRegistryKey("default-nonlegacy", defaultKASURI, false),
	}
	f.keysByURI = map[string][]*policy.KasKey{
		requestKASURI: {f.requestShared, f.requestLegacy, f.requestNonLegacy},
		defaultKASURI: {f.defaultShared, f.defaultLegacy, f.defaultNonLegacy},
	}
	return f
}

func newRegistryKey(id, uri string, legacy bool) *policy.KasKey {
	return &policy.KasKey{Key: &policy.AsymmetricKey{
		KeyId: id, Legacy: legacy, ProviderConfig: &policy.KeyProviderConfig{Name: uri},
	}}
}

type testKeyRegistry struct {
	MockKeyAccessServerRegistryClient
	keysByURI    map[string][]*policy.KasKey
	errorsByURI  map[string]error
	getRequests  []*kasregistry.GetKeyRequest
	listRequests []*kasregistry.ListKeysRequest
}

func (m *testKeyRegistry) GetKey(_ context.Context, req *kasregistry.GetKeyRequest) (*kasregistry.GetKeyResponse, error) {
	m.getRequests = append(m.getRequests, req)
	uri := req.GetKey().GetUri()
	if err := m.errorsByURI[uri]; err != nil {
		return nil, err
	}
	for _, key := range m.keysByURI[uri] {
		if key.GetKey().GetKeyId() == req.GetKey().GetKid() {
			return &kasregistry.GetKeyResponse{KasKey: key}, nil
		}
	}
	return nil, errRegistryKeyNotFound
}

func (m *testKeyRegistry) ListKeys(_ context.Context, req *kasregistry.ListKeysRequest) (*kasregistry.ListKeysResponse, error) {
	m.listRequests = append(m.listRequests, req)
	if err := m.errorsByURI[req.GetKasUri()]; err != nil {
		return nil, err
	}
	response := &kasregistry.ListKeysResponse{}
	for _, key := range m.keysByURI[req.GetKasUri()] {
		if req.Legacy == nil || key.GetKey().GetLegacy() == req.GetLegacy() {
			response.KasKeys = append(response.KasKeys, key)
		}
	}
	return response, nil
}

func (m *testKeyRegistry) assertGetRequests(t *testing.T, kid trust.KeyIdentifier, uris []string) {
	t.Helper()
	require.Len(t, m.getRequests, len(uris))
	for i, req := range m.getRequests {
		require.Equal(t, uris[i], req.GetKey().GetUri())
		require.Equal(t, string(kid), req.GetKey().GetKid())
	}
}

func (m *testKeyRegistry) assertListRequests(t *testing.T, legacy bool, uris []string) {
	t.Helper()
	require.Len(t, m.listRequests, len(uris))
	for i, req := range m.listRequests {
		require.Equal(t, uris[i], req.GetKasUri())
		if legacy {
			require.NotNil(t, req.Legacy)
			require.True(t, req.GetLegacy())
		} else {
			require.Nil(t, req.Legacy)
		}
	}
}

func assertRegistryKeys(t *testing.T, want []*policy.KasKey, got []trust.KeyDetails) {
	t.Helper()
	require.Len(t, got, len(want))
	for i, key := range got {
		adapter, ok := key.(*KeyAdapter)
		require.True(t, ok)
		require.Same(t, want[i], adapter.key, "key %d must come from the expected registration", i)
	}
}
