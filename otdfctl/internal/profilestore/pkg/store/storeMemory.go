package store

import (
	"encoding/json"
)

type memoryStore struct {
	namespace string
	key       string

	memory *map[string]interface{}
}

// NewMemoryStore creates a new in-memory store
// JSON is used to serialize the data to ensure the interface is consistent with other store implementations
var NewMemoryStore NewStoreInterface = func(serviceNamespace, key string, _ ...DriverOpt) (StoreInterface, error) {
	if err := ValidateNamespaceKey(serviceNamespace, key); err != nil {
		return nil, err
	}

	memory := make(map[string]interface{})
	return &memoryStore{
		namespace: serviceNamespace,
		key:       key,
		memory:    &memory,
	}, nil
}

func (k *memoryStore) Exists() bool {
	m := *k.memory
	_, ok := m[k.key]
	return ok
}

func (k *memoryStore) Get() ([]byte, error) {
	m := *k.memory
	v, ok := m[k.key]
	if !ok {
		return nil, nil
	}

	return json.Marshal(v)
}

func (k *memoryStore) Set(value interface{}) error {
	m := *k.memory
	m[k.key] = value
	// maybe write back to k.memory
	// k.memory = &m
	return nil
}

func (k *memoryStore) Delete() error {
	m := *k.memory
	delete(m, k.key)
	// maybe write back to k.memory
	return nil
}
