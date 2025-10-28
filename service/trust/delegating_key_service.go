package trust

import (
	"context"
	"crypto/elliptic"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/cache"
)

type KeyManagerFactoryOptions struct {
	Logger *logger.Logger
	Cache  *cache.Cache
	Config *policy.KeyProviderConfig
}

type keyManagerDesignation struct {
	Manager, Name string
}

func (kmd keyManagerDesignation) String() string {
	return fmt.Sprintf("%s#%s", kmd.Manager, kmd.Name)
}

type loadedManager struct {
	keyManagerDesignation
	*policy.KeyProviderConfig
	KeyManager
}

// KeyManagerFactory defines the signature for functions that can create KeyManager instances.
// KeyManagerFactoryCtx is preferred.
type KeyManagerFactory func(opts *KeyManagerFactoryOptions) (KeyManager, error)

// KeyManagerFactoryCtx defines the signature for functions that can create KeyManager instances.
type KeyManagerFactoryCtx func(ctx context.Context, opts *KeyManagerFactoryOptions) (KeyManager, error)

// DelegatingKeyService is a key service that multiplexes between key managers based on the key's mode.
type DelegatingKeyService struct {
	// Lookup key manager by mode for a given key identifier
	index KeyIndex

	// Lazily create key managers based on their manager
	managerFactories map[string]KeyManagerFactoryCtx

	// Cache of key managers to avoid creating them multiple times
	managers map[keyManagerDesignation]loadedManager

	defaultMode keyManagerDesignation

	defaultKeyManager KeyManager

	l *logger.Logger

	c *cache.Cache

	// Mutex to protect access to the manager cache
	mutex sync.Mutex
}

func NewDelegatingKeyService(index KeyIndex, l *logger.Logger, c *cache.Cache) *DelegatingKeyService {
	return &DelegatingKeyService{
		index:            index,
		managerFactories: make(map[string]KeyManagerFactoryCtx),
		managers:         make(map[keyManagerDesignation]loadedManager),
		l:                l,
		c:                c,
	}
}

func (d *DelegatingKeyService) RegisterKeyManagerCtx(name string, factory KeyManagerFactoryCtx) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.managerFactories[name] = factory
}

func (d *DelegatingKeyService) SetDefaultMode(manager, name string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.defaultMode = keyManagerDesignation{Manager: manager, Name: name}
}

// Implementing KeyIndex methods
func (d *DelegatingKeyService) FindKeyByAlgorithm(ctx context.Context, algorithm string, includeLegacy bool) (KeyDetails, error) {
	return d.index.FindKeyByAlgorithm(ctx, algorithm, includeLegacy)
}

func (d *DelegatingKeyService) FindKeyByID(ctx context.Context, id KeyIdentifier) (KeyDetails, error) {
	return d.index.FindKeyByID(ctx, id)
}

func (d *DelegatingKeyService) ListKeys(ctx context.Context) ([]KeyDetails, error) {
	return d.index.ListKeys(ctx)
}

func (d *DelegatingKeyService) ListKeysWith(ctx context.Context, opts ListKeyOptions) ([]KeyDetails, error) {
	return d.index.ListKeysWith(ctx, opts)
}

// Implementing KeyManager methods
func (d *DelegatingKeyService) Name() string {
	return "DelegatingKeyService"
}

func (d *DelegatingKeyService) Decrypt(ctx context.Context, keyID KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (ocrypto.ProtectedKey, error) {
	keyDetails, err := d.index.FindKeyByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("unable to find key by ID '%s' within index %s: %w", keyID, d.index, err)
	}

	pcfg := keyDetails.ProviderConfig()
	manager, err := d.getKeyManager(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("unable to get key manager for system '%s': %w", keyDetails.System(), err)
	}

	return manager.Decrypt(ctx, keyDetails, ciphertext, ephemeralPublicKey)
}

func (d *DelegatingKeyService) DeriveKey(ctx context.Context, keyID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ProtectedKey, error) {
	keyDetails, err := d.index.FindKeyByID(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("unable to find key by ID '%s' in index %s: %w", keyID, d.index, err)
	}

	manager, err := d.getKeyManager(ctx, keyDetails.ProviderConfig())
	if err != nil {
		return nil, fmt.Errorf("unable to get key manager for system '%s': %w", keyDetails.System(), err)
	}

	return manager.DeriveKey(ctx, keyDetails, ephemeralPublicKeyBytes, curve)
}

func (d *DelegatingKeyService) GenerateECSessionKey(ctx context.Context, ephemeralPublicKey string) (Encapsulator, error) {
	// Assuming a default manager for session key generation
	manager, err := d._defKM(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get default key manager: %w", err)
	}

	return manager.GenerateECSessionKey(ctx, ephemeralPublicKey)
}

func (d *DelegatingKeyService) Close() {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	for _, manager := range d.managers {
		manager.Close()
	}
	d.defaultKeyManager = nil
}

// _defKM retrieves or initializes the default KeyManager.
// It uses the `defaultMode` field to determine which manager is the default.
func (d *DelegatingKeyService) _defKM(ctx context.Context) (KeyManager, error) {
	d.mutex.Lock()
	// Check if defaultKeyManager is already cached
	if d.defaultKeyManager == nil {
		// Default manager not cached, need to initialize it.
		// Get the defaultMode name while still holding the lock.
		defaultModeName := d.defaultMode
		d.mutex.Unlock() // Unlock before calling getKeyManager to avoid re-entrant lock on the same goroutine.

		if defaultModeName.Manager == "" {
			return nil, errors.New("no default key manager mode configured")
		}

		// Get the manager instance for the defaultModeName.
		// This call to getKeyManager will handle its own locking and,
		// due to the check `if name == currentDefaultMode` in getKeyManager,
		// will error out if `defaultModeName` itself is not found, preventing recursion.
		cfg := policy.KeyProviderConfig{
			Manager: defaultModeName.Manager,
			Name:    defaultModeName.Name,
		}
		manager, err := d.getKeyManager(ctx, &cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to get default key manager for mode '%s': %w", defaultModeName, err)
		}

		// Cache the retrieved default manager.
		d.mutex.Lock()
		d.defaultKeyManager = manager
		d.mutex.Unlock()
		return manager, nil
	}

	// Default manager was already cached
	managerToReturn := d.defaultKeyManager
	d.mutex.Unlock()
	return managerToReturn, nil
}

func (d *DelegatingKeyService) getKeyManager(ctx context.Context, cfg *policy.KeyProviderConfig) (KeyManager, error) {
	d.mutex.Lock()

	// Check For Manager First
	designation := keyManagerDesignation{
		Manager: cfg.GetManager(),
		Name:    cfg.GetName(),
	}
	if manager, exists := d.managers[designation]; exists {
		d.mutex.Unlock()
		return manager.KeyManager, nil
	}

	// Check Factory
	factory, factoryExists := d.managerFactories[designation.Manager]
	// Read defaultMode under lock for comparison.
	currentDefaultMode := d.defaultMode
	allManagers := slices.Collect(maps.Keys(d.managerFactories))
	d.mutex.Unlock()

	if factoryExists {
		options := &KeyManagerFactoryOptions{
			Logger: d.l.With("key-manager", designation.String()),
			Cache:  d.c,
			Config: cfg,
		}
		managerFromFactory, err := factory(ctx, options)
		if err != nil {
			return nil, fmt.Errorf("factory for key manager '%s' failed: %w", designation, err)
		}
		// If err is nil (checked above) but managerFromFactory is still nil,
		// the factory implementation is problematic.
		if managerFromFactory == nil {
			return nil, fmt.Errorf("factory for key manager '%s' returned nil manager without an error", designation)
		}

		d.mutex.Lock()
		d.managers[designation] = loadedManager{designation, cfg, managerFromFactory}
		d.mutex.Unlock()
		return managerFromFactory, nil
	}
	// Factory for 'name' not found.
	// If 'name' was the defaultMode, _defKM will error if its factory is also missing.
	// If 'name' was not the defaultMode, we fall back to the default manager.
	d.l.Debug("key manager factory not found for name, attempting to use/load default",
		slog.Any("key_managers", allManagers),
		slog.Any("requested_name", designation),
		slog.Any("configured_default_mode", currentDefaultMode),
	)
	return d._defKM(ctx) // _defKM handles erroring if the default manager itself cannot be loaded.
}
