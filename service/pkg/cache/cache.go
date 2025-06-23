package cache

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	ristretto_store "github.com/eko/gocache/store/ristretto/v4"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrCacheMiss = errors.New("cache miss")
	//nolint:mnd // 1MB, used for testing purposes
	testMaxCost = int64(1024 * 1024)
)

// Manager is a cache manager for any value.
type Manager struct {
	cache           *cache.Cache[any]
	underlyingStore *ristretto.Cache
}

// Cache is a cache implementation using gocache for any value type.
type Cache struct {
	manager      *Manager
	serviceName  string
	cacheOptions Options
	logger       *logger.Logger
}

type Options struct {
	Expiration time.Duration
	// Cost       int64 // TODO
}

// NewCacheManager creates a new cache manager using Ristretto as the backend.
func NewCacheManager(maxCost int64) (*Manager, error) {
	numCounters, bufferItems, err := EstimateRistrettoConfigParams(maxCost)
	if err != nil {
		return nil, err
	}
	config := &ristretto.Config{
		NumCounters: numCounters, // number of keys to track frequency of (10x max items)
		MaxCost:     maxCost,     // maximum cost of cache (e.g., 1<<20 for 1MB)
		BufferItems: bufferItems, // number of keys per Get buffer.
	}
	store, err := ristretto.NewCache(config)
	if err != nil {
		return nil, err
	}
	ristrettoStore := ristretto_store.NewRistretto(store)
	return &Manager{
		cache:           cache.New[any](ristrettoStore),
		underlyingStore: store,
	}, nil
}

// NewCache creates a new Cache client instance with the given service name and options.
// The purpose of this function is to create a new cache for a specific service.
// Because caching can be expensive we want to make sure there are some strict controls with
// how it is used.
func (c *Manager) NewCache(serviceName string, log *logger.Logger, options Options) (*Cache, error) {
	if log == nil {
		return nil, errors.New("logger cannot be nil")
	}
	cache := &Cache{
		manager:      c,
		serviceName:  serviceName,
		cacheOptions: options,
	}
	cache.logger = log.
		With("subsystem", "cache").
		With("service_tag", cache.getServiceTag())

	if options.Expiration > 0 {
		cache.logger = cache.logger.
			With("expiration", options.Expiration.String())
	}
	cache.logger.Info("created cache")
	return cache, nil
}

func (c *Manager) Close() {
	if c.underlyingStore != nil {
		c.underlyingStore.Close()
	}
}

// Get retrieves a value from the cache
func (c *Cache) Get(ctx context.Context, key string) (any, error) {
	val, err := c.manager.cache.Get(ctx, c.getKey(key))
	if err != nil {
		// All errors are a cache miss in the gocache library.
		c.logger.TraceContext(ctx,
			"cache miss",
			slog.Any("key", key),
			slog.Any("error", err),
		)
		return nil, ErrCacheMiss
	}
	c.logger.TraceContext(ctx,
		"cache hit",
		slog.Any("key", key),
	)
	return val, nil
}

// Set stores a value of type T in the cache.
func (c *Cache) Set(ctx context.Context, key string, object any, tags []string) error {
	tags = append(tags, c.getServiceTag())
	opts := []store.Option{store.WithTags(tags)}
	if c.cacheOptions.Expiration > 0 {
		opts = append(opts, store.WithExpiration(c.cacheOptions.Expiration))
	}

	err := c.manager.cache.Set(ctx, c.getKey(key), object, opts...)
	if err != nil {
		c.logger.ErrorContext(ctx, "set error",
			slog.Any("key", key),
			slog.Any("error", err),
		)
		return err
	}
	c.logger.TraceContext(ctx, "set cache", slog.Any("key", key))
	return nil
}

func (c *Cache) Invalidate(ctx context.Context) error {
	return c.manager.cache.Invalidate(ctx, store.WithInvalidateTags([]string{c.getServiceTag()}))
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	return c.manager.cache.Delete(ctx, c.getKey(key))
}

func (c *Cache) getKey(key string) string {
	return c.serviceName + ":" + key
}

func (c *Cache) getServiceTag() string {
	return "svc:" + c.serviceName
}

// TestCacheClient creates a test cache client with predefined options.
func TestCacheClient(expiration time.Duration) (*Cache, error) {
	numCounters, bufferItems, err := EstimateRistrettoConfigParams(testMaxCost)
	if err != nil {
		return nil, err
	}
	config := &ristretto.Config{
		NumCounters: numCounters,
		MaxCost:     testMaxCost,
		BufferItems: bufferItems,
	}
	store, err := ristretto.NewCache(config)
	if err != nil {
		return nil, err
	}
	cacheStore := ristretto_store.NewRistretto(store)
	manager := &Manager{
		cache: cache.New[any](cacheStore),
	}
	return &Cache{
		manager:      manager,
		serviceName:  "testService",
		cacheOptions: Options{Expiration: expiration},
		logger:       logger.CreateTestLogger(),
	}, nil
}
