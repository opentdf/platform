package keycloak

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Nerzal/gocloak/v13"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
)

// Cache Key formats
// Client: {realm}::client::{clientid}
// User: {realm}::user::{emailaddress or username}
// Group: {realm}::group::{emailaddress or id}
// Group members: {realm}::group::{groupid}::members

func retrieveClients(ctx context.Context, logger *logger.Logger, clientID string, realm string, svcCache *cache.Cache, connector *Connector) ([]*gocloak.Client, error) {
	cacheKey := fmt.Sprintf("%s::client::%s", realm, clientID)
	retrievalFunc := func() ([]*gocloak.Client, error) {
		return connector.client.GetClients(ctx, connector.token.AccessToken, realm, gocloak.GetClientsParams{
			ClientID: &clientID,
		})
	}
	clients, err := retrieveWithKey[[]*gocloak.Client](ctx, cacheKey, svcCache, logger, retrievalFunc)
	if err != nil {
		return nil, err
	}
	return clients, nil
}

func retrieveUsers(ctx context.Context, logger *logger.Logger, getUserParams gocloak.GetUsersParams, realm string, svcCache *cache.Cache, connector *Connector) ([]*gocloak.User, error) {
	var cacheKey string
	switch {
	case getUserParams.Email != nil:
		cacheKey = fmt.Sprintf("%s::user::%s", realm, *getUserParams.Email)
	case getUserParams.Username != nil:
		cacheKey = fmt.Sprintf("%s::user::%s", realm, *getUserParams.Username)
	default:
		return nil, errors.New("either email or username must be provided")
	}

	retrievalFunc := func() ([]*gocloak.User, error) {
		return connector.client.GetUsers(ctx, connector.token.AccessToken, realm, getUserParams)
	}
	return retrieveWithKey[[]*gocloak.User](ctx, cacheKey, svcCache, logger, retrievalFunc)
}

func retrieveGroupsByEmail(ctx context.Context, logger *logger.Logger, groupEmail string, realm string, svcCache *cache.Cache, connector *Connector) ([]*gocloak.Group, error) {
	cacheKey := fmt.Sprintf("%s::group::%s", realm, groupEmail)
	retrievalFunc := func() ([]*gocloak.Group, error) {
		return connector.client.GetGroups(
			ctx,
			connector.token.AccessToken,
			realm,
			gocloak.GetGroupsParams{Search: func() *string { t := groupEmail; return &t }()},
		)
	}
	return retrieveWithKey[[]*gocloak.Group](ctx, cacheKey, svcCache, logger, retrievalFunc)
}

func retrieveGroupByID(ctx context.Context, logger *logger.Logger, groupID string, realm string, svcCache *cache.Cache, connector *Connector) (*gocloak.Group, error) {
	cacheKey := fmt.Sprintf("%s::group::%s", realm, groupID)
	retrievalFunc := func() (*gocloak.Group, error) {
		return connector.client.GetGroup(ctx, connector.token.AccessToken, realm, groupID)
	}
	return retrieveWithKey[*gocloak.Group](ctx, cacheKey, svcCache, logger, retrievalFunc)
}

func retrieveGroupMembers(ctx context.Context, logger *logger.Logger, groupID string, realm string, svcCache *cache.Cache, connector *Connector) ([]*gocloak.User, error) {
	cacheKey := fmt.Sprintf("%s::group::%s::members", realm, groupID)
	retrievalFunc := func() ([]*gocloak.User, error) {
		return connector.client.GetGroupMembers(ctx, connector.token.AccessToken, realm, groupID, gocloak.GetGroupsParams{})
	}
	return retrieveWithKey[[]*gocloak.User](ctx, cacheKey, svcCache, logger, retrievalFunc)
}

func retrieveWithKey[T any](ctx context.Context, cacheKey string, svcCache *cache.Cache, logger *logger.Logger, retrieveFunc func() (T, error)) (T, error) {
	if svcCache != nil {
		cachedData, err := svcCache.Get(ctx, cacheKey)
		if err == nil {
			if retrieved, ok := cachedData.(T); ok {
				return retrieved, nil
			}
			logger.Error("cache data type assertion failed")
		} else if !errors.Is(err, cache.ErrCacheMiss) {
			var zero T
			return zero, err
		}
	}
	retrieved, err := retrieveFunc()
	if svcCache != nil && err == nil {
		cacheErr := svcCache.Set(ctx, cacheKey, retrieved, []string{})
		if cacheErr != nil {
			logger.Error("error setting cache", slog.String("error", cacheErr.Error()))
		}
	}
	return retrieved, err
}
