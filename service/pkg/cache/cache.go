package cache

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	ristretto_store "github.com/eko/gocache/store/ristretto/v4"
	"github.com/opentdf/platform/service/logger"
)

type Manager struct {
	cache *cache.Cache[interface{}]
}

// Cache is a cache implementation using gocache
type Cache struct {
	manager      *Manager
	serviceName  string
	cacheOptions Options
	logger       *logger.Logger
}

type Options struct {
	Expiration time.Duration
	Cost       int64
}

// NewCache creates a new Cache instance using Ristretto as the backend.
func NewCacheManager(maxCost int64) (*Manager, error) {
	numCounters, bufferItems := EstimateRistrettoConfigParams(maxCost)
	store, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: numCounters, // number of keys to track frequency of (10x max items)
		MaxCost:     maxCost,     // maximum cost of cache (e.g., 1<<20 for 1MB)
		BufferItems: bufferItems, // number of keys per Get buffer.
	})
	if err != nil {
		return nil, err
	}
	ristrettoStore := ristretto_store.NewRistretto(store)
	c := cache.New[interface{}](ristrettoStore)
	return &Manager{
		cache: c,
	}, nil
}

// NewCache creates a new Cache instance with the given service name and options.
// The purpose of this function is to create a new cache for a specific service.
// Because caching can be expensive we want to make sure there are some strict controls with
// how it is used.
func (c *Manager) NewCache(serviceName string, logger *logger.Logger, options Options) (*Cache, error) {
	if logger == nil {
		return nil, errors.New("logger cannot be nil")
	}
	cache := &Cache{
		manager:      c,
		serviceName:  serviceName,
		cacheOptions: options,
	}
	cache.logger = logger.
		With("subsystem", "cache").
		With("serviceTag", cache.getServiceTag()).
		With("expiration", options.Expiration.String()).
		With("cost", strconv.FormatInt(options.Cost, 10))
	cache.logger.Info("created cache")
	return cache, nil
}

func (c *Cache) Get(ctx context.Context, key string) (interface{}, error) {
	val, err := c.manager.cache.Get(ctx, c.getKey(key))
	if err != nil {
		// All errors are a cache miss in the gocache library.
		c.logger.Debug("cache miss", "key", key, "error", err)
		return nil, err
	}
	c.logger.Debug("cache hit", "key", key)
	return val, nil
}

func (c *Cache) Set(ctx context.Context, key string, object interface{}, tags []string) error {
	tags = append(tags, c.getServiceTag())
	opts := []store.Option{
		store.WithTags(tags),
		store.WithExpiration(c.cacheOptions.Expiration),
		store.WithCost(c.cacheOptions.Cost),
	}

	err := c.manager.cache.Set(ctx, c.getKey(key), object, opts...)
	if err != nil {
		c.logger.Error("set error", "key", key, "error", err)
		return err
	}
	c.logger.Debug("set cache", "key", key)
	return nil
}

func (c *Cache) Invalidate(ctx context.Context) error {
	err := c.manager.cache.Invalidate(ctx, store.WithInvalidateTags([]string{c.getServiceTag()}))
	if err != nil {
		c.logger.Error("invalidate error", "error", err)
		return err
	}
	c.logger.Info("invalidate cache")
	return nil
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	err := c.manager.cache.Delete(ctx, c.getKey(key))
	if err != nil {
		c.logger.Error("delete error", "key", key, "error", err)
		return err
	}
	c.logger.Info("delete cache", "key", key)
	return nil
}

func (c *Cache) getKey(key string) string {
	return c.serviceName + ":" + key
}

func (c *Cache) getServiceTag() string {
	return "svc:" + c.serviceName
}
