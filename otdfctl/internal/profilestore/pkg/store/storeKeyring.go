package store

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/zalando/go-keyring"
)

type keyringStore struct {
	namespace string
	key       string
}

var NewKeyringStore NewStoreInterface = func(serviceNamespace, key string, _ ...DriverOpt) (Interface, error) {
	if err := ValidateNamespaceKey(serviceNamespace, key); err != nil {
		return nil, err
	}
	return &keyringStore{
		namespace: serviceNamespace,
		key:       key,
	}, nil
}

func (k *keyringStore) Exists() bool {
	s, err := keyring.Get(k.namespace, k.key)
	return err == nil && s != ""
}

// ExistsWithError is used by create-only registration; unlike legacy Exists,
// a successful empty record is present and only ErrNotFound means absence.
func (k *keyringStore) ExistsWithError() (bool, error) {
	_, err := keyring.Get(k.namespace, k.key)
	if errors.Is(err, keyring.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (k *keyringStore) Get() ([]byte, error) {
	s, err := keyring.Get(k.namespace, k.key)
	if err != nil {
		return nil, err
	}
	return []byte(s), err
}

func (k *keyringStore) Set(value interface{}) error {
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(value); err != nil {
		return err
	}
	return keyring.Set(k.namespace, k.key, b.String())
}

func (k *keyringStore) Delete() error {
	return keyring.Delete(k.namespace, k.key)
}
