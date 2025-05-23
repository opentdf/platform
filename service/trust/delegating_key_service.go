package trust

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"sync"

	"github.com/opentdf/platform/service/logger"
)

type KeyManagerFactory func() (KeyManager, error)

// DelegatingKeyService is a key service that multiplexes between key managers based on the key's mode.
type DelegatingKeyService struct {
	// Lookup key manager by mode for a given key identifier
	index KeyIndex

	// Lazily create key managers based on their mode
	managerFactories map[string]KeyManagerFactory

	// Cache of key managers to avoid creating them multiple times
	managers map[string]KeyManager

	defaultMode string

	defaultKeyManager KeyManager

	l *logger.Logger

	// Mutex to protect access to the manager cache
	mutex sync.Mutex
}

func NewDelegatingKeyService(index KeyIndex, l *logger.Logger) *DelegatingKeyService {
	return &DelegatingKeyService{
		index:            index,
		managerFactories: make(map[string]KeyManagerFactory),
		managers:         make(map[string]KeyManager),
		l:                l,
	}
}

func (d *DelegatingKeyService) RegisterKeyManager(name string, factory KeyManagerFactory) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.managerFactories[name] = factory
}

func (d *DelegatingKeyService) SetDefaultMode(name string) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.defaultMode = name
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

// Implementing KeyManager methods
func (d *DelegatingKeyService) Name() string {
	return "DelegatingKeyService"
}

func (d *DelegatingKeyService) Decrypt(ctx context.Context, keyID KeyIdentifier, ciphertext []byte, ephemeralPublicKey []byte) (ProtectedKey, error) {
	keyDetails, err := d.index.FindKeyByID(ctx, keyID)
	if err != nil {
		return nil, err
	}

	manager, err := d.getKeyManager(keyDetails.System())
	if err != nil {
		return nil, err
	}

	return manager.Decrypt(ctx, keyDetails, ciphertext, ephemeralPublicKey)
}

func (d *DelegatingKeyService) DeriveKey(ctx context.Context, keyID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ProtectedKey, error) {
	keyDetails, err := d.index.FindKeyByID(ctx, keyID)
	if err != nil {
		return nil, err
	}

	manager, err := d.getKeyManager(keyDetails.System())
	if err != nil {
		return nil, err
	}

	return manager.DeriveKey(ctx, keyDetails, ephemeralPublicKeyBytes, curve)
}

func (d *DelegatingKeyService) GenerateECSessionKey(ctx context.Context, ephemeralPublicKey string) (Encapsulator, error) {
	// Assuming a default manager for session key generation
	manager, err := d._defKM()
	if err != nil {
		return nil, err
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
func (d *DelegatingKeyService) _defKM() (KeyManager, error) {
	d.mutex.Lock()
	// Check if defaultKeyManager is already cached
	if d.defaultKeyManager == nil {
		// Default manager not cached, need to initialize it.
		// Get the defaultMode name while still holding the lock.
		defaultModeName := d.defaultMode
		d.mutex.Unlock() // Unlock before calling getKeyManager to avoid re-entrant lock on the same goroutine.

		if defaultModeName == "" {
			return nil, fmt.Errorf("no default key manager mode configured")
		}

		// Get the manager instance for the defaultModeName.
		// This call to getKeyManager will handle its own locking and,
		// due to the check `if name == currentDefaultMode` in getKeyManager,
		// will error out if `defaultModeName` itself is not found, preventing recursion.
		manager, err := d.getKeyManager(defaultModeName)
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

func (d *DelegatingKeyService) getKeyManager(name string) (KeyManager, error) {
	d.mutex.Lock()

	// Check For Manager First
	if manager, exists := d.managers[name]; exists {
		d.mutex.Unlock()
		return manager, nil
	}

	// Check Factory
	factory, factoryExists := d.managerFactories[name]
	// Read defaultMode under lock for comparison.
	currentDefaultMode := d.defaultMode
	d.mutex.Unlock()

	if factoryExists {
		managerFromFactory, err := factory()
		if err != nil {
			return nil, fmt.Errorf("factory for key manager '%s' failed: %w", name, err)
		}

		d.mutex.Lock()
		d.managers[name] = managerFromFactory // Cache the newly created manager
		d.mutex.Unlock()
		return managerFromFactory, nil
	}

	if name == currentDefaultMode && name != "" {
		return nil, fmt.Errorf("configured default key manager '%s' not found (no factory/cache entry)", name)
	}

	d.l.Debug("Key manager not found by name, falling back to default", "requestedName", name, "configuredDefaultName", currentDefaultMode)
	return d._defKM()
}
