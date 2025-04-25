package trust

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"sync"
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

	// Mutex to protect access to the manager cache
	mutex sync.Mutex
}

func NewDelegatingKeyService(index KeyIndex) *DelegatingKeyService {
	return &DelegatingKeyService{
		index:            index,
		managerFactories: make(map[string]KeyManagerFactory),
		managers:         make(map[string]KeyManager),
	}
}

func (d *DelegatingKeyService) RegisterKeyManager(name string, factory KeyManagerFactory) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.managerFactories[name] = factory
}

func (d *DelegatingKeyService) getKeyManager(name string) (KeyManager, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if manager, exists := d.managers[name]; exists {
		return manager, nil
	}

	factory, exists := d.managerFactories[name]
	if !exists {
		return nil, fmt.Errorf("no key manager registered with name: %s", name)
	}

	manager, err := factory()
	if err != nil {
		return nil, err
	}

	d.managers[name] = manager
	return manager, nil
}

func (d *DelegatingKeyService) getDefaultKeyManager() (KeyManager, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.defaultKeyManager == nil {
		manager, err := d.getKeyManager(d.defaultMode)
		if err != nil {
			return nil, err
		}
		d.defaultKeyManager = manager
	}
	return d.defaultKeyManager, nil
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

	manager, err := d.getKeyManager(keyDetails.Mode())
	if err != nil {
		return nil, err
	}

	return manager.Decrypt(ctx, keyID, ciphertext, ephemeralPublicKey)
}

func (d *DelegatingKeyService) DeriveKey(ctx context.Context, kasKID KeyIdentifier, ephemeralPublicKeyBytes []byte, curve elliptic.Curve) (ProtectedKey, error) {
	keyDetails, err := d.index.FindKeyByID(ctx, kasKID)
	if err != nil {
		return nil, err
	}

	manager, err := d.getKeyManager(keyDetails.Mode())
	if err != nil {
		return nil, err
	}

	return manager.DeriveKey(ctx, kasKID, ephemeralPublicKeyBytes, curve)
}

func (d *DelegatingKeyService) GenerateECSessionKey(ctx context.Context, ephemeralPublicKey string) (Encapsulator, error) {
	// Assuming a default manager for session key generation
	manager, err := d.getDefaultKeyManager()
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
}
