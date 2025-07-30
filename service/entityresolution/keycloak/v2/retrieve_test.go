package keycloak

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cacheTime = 2 * time.Second

func newTestCache(t *testing.T) (*cache.Manager, *cache.Cache) {
	// Use a short expiration for test
	cacheManager, err := cache.NewCacheManager(1000)
	require.NoError(t, err, "Failed to create cache manager")
	c, err := cacheManager.NewCache("test", logger.CreateTestLogger(), cache.Options{
		Expiration: cacheTime,
	})
	require.NoError(t, err, "Failed to create test cache")
	return cacheManager, c
}

func TestRetrieveClients_CacheIntegration(t *testing.T) {
	clientID := "myclient"
	realm := "tdf"
	cacheKey := fmt.Sprintf("%s::client::%s", realm, clientID)
	clientsResp := []*gocloak.Client{{ID: gocloak.StringP(clientID)}}

	var called int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// slog.Info("Server called", "path", r.URL.Path, "query", r.URL.RawQuery)
		called++
		assert.Equal(t, "/admin/realms/tdf/clients", r.URL.Path)
		assert.Contains(t, r.URL.RawQuery, "clientId=myclient")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(clientsResp)
	}))
	defer server.Close()

	kc := &Connector{
		token:  &gocloak.JWT{AccessToken: "dummy"},
		client: gocloak.NewClient(server.URL),
	}
	l := logger.CreateTestLogger()
	cm, c := newTestCache(t)
	defer cm.Close() // Ensure cache manager is closed after test

	// First call: cache miss, should hit server
	got, err := retrieveClients(t.Context(), l, clientID, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, clientsResp, got)
	assert.Equal(t, 1, called)

	// Wait
	time.Sleep(200 * time.Millisecond)

	// Second call: cache hit, should NOT hit server
	called = 0
	got2, err := retrieveClients(t.Context(), l, clientID, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, clientsResp, got2)
	assert.Equal(t, 0, called, "server should not be called on cache hit")

	// Optionally, check cache directly
	val, err := c.Get(t.Context(), cacheKey)
	require.NoError(t, err)
	assert.Equal(t, clientsResp, val)

	// Wait for cache expiration
	time.Sleep(cacheTime)
	// After expiration, cache should be empty
	_, err = c.Get(t.Context(), cacheKey)
	require.Error(t, err, "Cache should be empty after expiration")
}

func TestRetrieveUsers_CacheIntegration(t *testing.T) {
	email := "foo@bar.com"
	realm := "tdf"
	cacheKey := fmt.Sprintf("%s::user::%s", realm, email)
	usersResp := []*gocloak.User{{Email: gocloak.StringP(email)}}

	var called int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		assert.Equal(t, "/admin/realms/tdf/users", r.URL.Path)
		assert.Contains(t, r.URL.RawQuery, "email=foo%40bar.com")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(usersResp)
	}))
	defer server.Close()

	kc := &Connector{
		token:  &gocloak.JWT{AccessToken: "dummy"},
		client: gocloak.NewClient(server.URL),
	}
	l := logger.CreateTestLogger()
	cm, c := newTestCache(t)
	defer cm.Close() // Ensure cache manager is closed after test

	// First call: cache miss, should hit server
	params := gocloak.GetUsersParams{Email: &email}
	got, err := retrieveUsers(t.Context(), l, params, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, usersResp, got)
	assert.Equal(t, 1, called)

	// Wait
	time.Sleep(200 * time.Millisecond)

	called = 0
	// Second call: cache hit, should NOT hit server
	got2, err := retrieveUsers(t.Context(), l, params, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, usersResp, got2)
	assert.Equal(t, 0, called)

	// Optionally, check cache directly
	val, err := c.Get(t.Context(), cacheKey)
	require.NoError(t, err)
	assert.Equal(t, usersResp, val)

	// Wait for cache expiration
	time.Sleep(cacheTime)
	// After expiration, cache should be empty
	_, err = c.Get(t.Context(), cacheKey)
	require.Error(t, err, "Cache should be empty after expiration")
}

func TestRetrieveGroupsByEmail_CacheIntegration(t *testing.T) {
	groupEmail := "group@bar.com"
	realm := "tdf"
	cacheKey := fmt.Sprintf("%s::group::%s", realm, groupEmail)
	groupsResp := []*gocloak.Group{{ID: gocloak.StringP("gid")}}

	var called int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		assert.Equal(t, "/admin/realms/tdf/groups", r.URL.Path)
		assert.Contains(t, r.URL.RawQuery, "search=group%40bar.com")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(groupsResp)
	}))
	defer server.Close()

	kc := &Connector{
		token:  &gocloak.JWT{AccessToken: "dummy"},
		client: gocloak.NewClient(server.URL),
	}
	l := logger.CreateTestLogger()
	cm, c := newTestCache(t)
	defer cm.Close() // Ensure cache manager is closed after test

	// First call: cache miss, should hit server
	got, err := retrieveGroupsByEmail(t.Context(), l, groupEmail, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, groupsResp, got)
	assert.Equal(t, 1, called)

	// Wait
	time.Sleep(200 * time.Millisecond)

	// Second call: cache hit, should NOT hit server
	called = 0
	got2, err := retrieveGroupsByEmail(t.Context(), l, groupEmail, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, groupsResp, got2)
	assert.Equal(t, 0, called)

	// Optionally, check cache directly
	val, err := c.Get(t.Context(), cacheKey)
	require.NoError(t, err)
	assert.Equal(t, groupsResp, val)

	// Wait for cache expiration
	time.Sleep(cacheTime)
	// After expiration, cache should be empty
	_, err = c.Get(t.Context(), cacheKey)
	require.Error(t, err, "Cache should be empty after expiration")
}

func TestRetrieveGroupByID_CacheIntegration(t *testing.T) {
	groupID := "gid"
	realm := "tdf"
	cacheKey := fmt.Sprintf("%s::group::%s", realm, groupID)
	groupResp := &gocloak.Group{ID: gocloak.StringP(groupID)}

	var called int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		assert.Equal(t, "/admin/realms/tdf/groups/gid", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(groupResp)
	}))
	defer server.Close()

	kc := &Connector{
		token:  &gocloak.JWT{AccessToken: "dummy"},
		client: gocloak.NewClient(server.URL),
	}
	l := logger.CreateTestLogger()
	cm, c := newTestCache(t)
	defer cm.Close() // Ensure cache manager is closed after test

	// First call: cache miss, should hit server
	got, err := retrieveGroupByID(t.Context(), l, groupID, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, groupResp, got)
	assert.Equal(t, 1, called)

	// Wait
	time.Sleep(200 * time.Millisecond)

	// Second call: cache hit, should NOT hit server
	called = 0
	got2, err := retrieveGroupByID(t.Context(), l, groupID, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, groupResp, got2)
	assert.Equal(t, 0, called)

	// Optionally, check cache directly
	val, err := c.Get(t.Context(), cacheKey)
	require.NoError(t, err)
	assert.Equal(t, groupResp, val)

	// Wait for cache expiration
	time.Sleep(cacheTime)
	// After expiration, cache should be empty
	_, err = c.Get(t.Context(), cacheKey)
	require.Error(t, err, "Cache should be empty after expiration")
}

func TestRetrieveGroupMembers_CacheIntegration(t *testing.T) {
	groupID := "gid"
	realm := "tdf"
	cacheKey := fmt.Sprintf("%s::group::%s::members", realm, groupID)
	membersResp := []*gocloak.User{{ID: gocloak.StringP("uid")}}

	var called int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		assert.Equal(t, "/admin/realms/tdf/groups/gid/members", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(membersResp)
	}))
	defer server.Close()

	kc := &Connector{
		token:  &gocloak.JWT{AccessToken: "dummy"},
		client: gocloak.NewClient(server.URL),
	}
	l := logger.CreateTestLogger()
	cm, c := newTestCache(t)
	defer cm.Close() // Ensure cache manager is closed after test

	// First call: cache miss, should hit server
	got, err := retrieveGroupMembers(t.Context(), l, groupID, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, membersResp, got)
	assert.Equal(t, 1, called)

	// Wait
	time.Sleep(200 * time.Millisecond)

	// Second call: cache hit, should NOT hit server
	called = 0
	got2, err := retrieveGroupMembers(t.Context(), l, groupID, realm, c, kc)
	require.NoError(t, err)
	assert.Equal(t, membersResp, got2)
	assert.Equal(t, 0, called)

	// Optionally, check cache directly
	val, err := c.Get(t.Context(), cacheKey)
	require.NoError(t, err)
	assert.Equal(t, membersResp, val)

	// Wait for cache expiration
	time.Sleep(cacheTime)
	// After expiration, cache should be empty
	_, err = c.Get(t.Context(), cacheKey)
	require.Error(t, err, "Cache should be empty after expiration")
}
