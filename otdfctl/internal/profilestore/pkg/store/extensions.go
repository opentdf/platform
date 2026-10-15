package store

import (
	"encoding/json"
	"errors"
	"fmt"
)

var ErrInvalidExtensions = errors.New("invalid extensions")

// DecodeObject validates a stored JSON object and its optional namespaced payloads.
// Raw values are never decoded into consumer types by the storage engine.
func DecodeObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("stored configuration must be an object")
	}
	if _, err := Extensions(object); err != nil {
		return nil, err
	}
	return object, nil
}

// Extensions returns an independent copy. A missing member returns an empty map.
func Extensions(object map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	raw, ok := object["extensions"]
	if !ok {
		return map[string]json.RawMessage{}, nil
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, fmt.Errorf("%w: expected a namespaced object", ErrInvalidExtensions)
	}
	for name := range values {
		if name == "" {
			return nil, fmt.Errorf("%w: empty namespace", ErrInvalidExtensions)
		}
	}
	return values, nil
}

// PutExtension returns a copy with one namespace changed, without mutating
// the original object. A nil payload is not a deletion or JSON null.
func PutExtension(object map[string]json.RawMessage, namespace string, payload json.RawMessage) (map[string]json.RawMessage, error) {
	if namespace == "" || len(payload) == 0 || !json.Valid(payload) {
		return nil, ErrInvalidExtensions
	}
	values, err := Extensions(object)
	if err != nil {
		return nil, err
	}
	if values == nil {
		values = make(map[string]json.RawMessage)
	}
	values[namespace] = append(json.RawMessage(nil), payload...)
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	result := make(map[string]json.RawMessage, len(object))
	for key, value := range object {
		result[key] = value
	}
	result["extensions"] = encoded
	return result, nil
}

func Extension(object map[string]json.RawMessage, namespace string) (json.RawMessage, bool, error) {
	values, err := Extensions(object)
	if err != nil {
		return nil, false, err
	}
	value, ok := values[namespace]
	return append(json.RawMessage(nil), value...), ok, nil
}
