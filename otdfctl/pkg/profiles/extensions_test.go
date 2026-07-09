package profiles

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type acmeCreds struct {
	APIKey string `json:"apiKey"`
	Region string `json:"region"`
	Expiry int64  `json:"expiry"`
}

type widgetConfig struct {
	Enabled bool     `json:"enabled"`
	Tags    []string `json:"tags"`
}

func newTestMemoryStore(t *testing.T) *OtdfctlProfileStore {
	t.Helper()
	store, err := NewOtdfctlProfileStore(ProfileDriverMemory, &ProfileConfig{
		Name:     "test-profile",
		Endpoint: "http://localhost:8080",
	}, true)
	require.NoError(t, err)
	require.NotNil(t, store)
	return store
}

func TestExtension_RoundTrip(t *testing.T) {
	store := newTestMemoryStore(t)

	want := acmeCreds{APIKey: "secret", Region: "us-east", Expiry: 1_700_000_000}
	require.NoError(t, SetExtension(store, "acme", want))

	got, ok, err := GetExtension[acmeCreds](store, "acme")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, want, got)
	// int64 must survive the store's JSON round-trip without float64 coercion.
	assert.Equal(t, int64(1_700_000_000), got.Expiry)
}

func TestExtension_HeterogeneousTypesCoexist(t *testing.T) {
	store := newTestMemoryStore(t)

	require.NoError(t, SetExtension(store, "acme", acmeCreds{APIKey: "k"}))
	require.NoError(t, SetExtension(store, "widget", widgetConfig{Enabled: true, Tags: []string{"a", "b"}}))

	acme, ok, err := GetExtension[acmeCreds](store, "acme")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "k", acme.APIKey)

	widget, ok, err := GetExtension[widgetConfig](store, "widget")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, widgetConfig{Enabled: true, Tags: []string{"a", "b"}}, widget)
}

func TestExtension_MissingReturnsZeroValue(t *testing.T) {
	store := newTestMemoryStore(t)

	got, ok, err := GetExtension[acmeCreds](store, "missing")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, acmeCreds{}, got)
}

func TestExtension_DecodeErrorSurfaces(t *testing.T) {
	store := newTestMemoryStore(t)

	// Store an object, then attempt to decode it into an incompatible type.
	require.NoError(t, SetExtension(store, "acme", acmeCreds{APIKey: "k"}))

	_, ok, err := GetExtension[[]string](store, "acme")
	assert.True(t, ok)
	require.Error(t, err)
}

func TestExtension_HasAndDelete(t *testing.T) {
	store := newTestMemoryStore(t)

	assert.False(t, store.HasExtension("acme"))
	// Deleting an absent extension is a no-op.
	require.NoError(t, store.DeleteExtension("acme"))

	require.NoError(t, SetExtension(store, "acme", acmeCreds{APIKey: "k"}))
	assert.True(t, store.HasExtension("acme"))

	require.NoError(t, store.DeleteExtension("acme"))
	assert.False(t, store.HasExtension("acme"))
}

func TestExtension_Names(t *testing.T) {
	store := newTestMemoryStore(t)

	assert.Nil(t, store.ExtensionNames())

	require.NoError(t, SetExtension(store, "widget", widgetConfig{}))
	require.NoError(t, SetExtension(store, "acme", acmeCreds{}))

	assert.Equal(t, []string{"acme", "widget"}, store.ExtensionNames())
}

func TestExtension_OmittedFromJSONWhenEmpty(t *testing.T) {
	b, err := json.Marshal(ProfileConfig{Name: "p", Endpoint: "http://localhost:8080"})
	require.NoError(t, err)
	assert.NotContains(t, string(b), `"extensions"`)
}
