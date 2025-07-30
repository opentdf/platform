package keymanagement

import (
	"fmt"
	"sync"
)

// ManagerType represents a registered key manager type
type ManagerType struct {
	Name        string
	Description string
	Enabled     bool
}

// ManagerRegistry manages registered key manager types
type ManagerRegistry struct {
	registeredManagers map[string]ManagerType
	mutex              sync.RWMutex
}

// NewManagerRegistry creates a new manager registry
func NewManagerRegistry() *ManagerRegistry {
	return &ManagerRegistry{
		registeredManagers: make(map[string]ManagerType),
	}
}

// RegisterManager registers a new key manager type
func (mr *ManagerRegistry) RegisterManager(name, description string) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	if _, exists := mr.registeredManagers[name]; exists {
		return fmt.Errorf("manager type '%s' is already registered", name)
	}

	mr.registeredManagers[name] = ManagerType{
		Name:        name,
		Description: description,
		Enabled:     true,
	}

	return nil
}

// IsManagerRegistered checks if a manager type is registered and enabled
func (mr *ManagerRegistry) IsManagerRegistered(name string) bool {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	manager, exists := mr.registeredManagers[name]
	return exists && manager.Enabled
}

// GetRegisteredManagers returns all registered manager types
func (mr *ManagerRegistry) GetRegisteredManagers() []ManagerType {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	managers := make([]ManagerType, 0, len(mr.registeredManagers))
	for _, manager := range mr.registeredManagers {
		if manager.Enabled {
			managers = append(managers, manager)
		}
	}

	return managers
}

// GetManagerNames returns a slice of registered manager names
func (mr *ManagerRegistry) GetManagerNames() []string {
	mr.mutex.RLock()
	defer mr.mutex.RUnlock()

	names := make([]string, 0, len(mr.registeredManagers))
	for name, manager := range mr.registeredManagers {
		if manager.Enabled {
			names = append(names, name)
		}
	}

	return names
}

// DisableManager disables a registered manager type
func (mr *ManagerRegistry) DisableManager(name string) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	manager, exists := mr.registeredManagers[name]
	if !exists {
		return fmt.Errorf("manager type '%s' is not registered", name)
	}

	manager.Enabled = false
	mr.registeredManagers[name] = manager

	return nil
}

// EnableManager enables a registered manager type
func (mr *ManagerRegistry) EnableManager(name string) error {
	mr.mutex.Lock()
	defer mr.mutex.Unlock()

	manager, exists := mr.registeredManagers[name]
	if !exists {
		return fmt.Errorf("manager type '%s' is not registered", name)
	}

	manager.Enabled = true
	mr.registeredManagers[name] = manager

	return nil
}

// Global manager registry instance
var globalManagerRegistry *ManagerRegistry
var registryOnce sync.Once

// GetGlobalManagerRegistry returns the singleton manager registry
func GetGlobalManagerRegistry() *ManagerRegistry {
	registryOnce.Do(func() {
		globalManagerRegistry = NewManagerRegistry()
		// Register default manager types
		registerDefaultManagers()
	})
	return globalManagerRegistry
}

// registerDefaultManagers registers the default key manager types
func registerDefaultManagers() {
	registry := globalManagerRegistry

	// Register common key manager types
	_ = registry.RegisterManager("local", "Local key manager for development and testing")
	_ = registry.RegisterManager("aws", "AWS Key Management Service (KMS)")
	_ = registry.RegisterManager("gcp", "Google Cloud Key Management Service")
	_ = registry.RegisterManager("azure", "Azure Key Vault")
	_ = registry.RegisterManager("hashicorp-vault", "HashiCorp Vault")
	_ = registry.RegisterManager("hsm", "Hardware Security Module")
}