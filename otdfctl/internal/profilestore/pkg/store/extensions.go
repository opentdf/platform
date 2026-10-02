package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
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

// MergeCore overlays only the fields owned by the core configuration, retaining
// all other stored JSON members (including opaque extension payloads).
func MergeCore(object map[string]json.RawMessage, core any) (map[string]json.RawMessage, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	merged := make(map[string]json.RawMessage, len(object)+len(fields))
	for key, value := range object {
		merged[key] = value
	}
	if err := mergeStructFields(merged, fields, reflect.TypeOf(core)); err != nil {
		return nil, err
	}
	return merged, nil
}

// mergeStructFields replaces core-owned members (including omitted members),
// but retains unknown members at every nested struct boundary.
func mergeStructFields(target, fields map[string]json.RawMessage, typ reflect.Type) error {
	if typ == nil {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		for key, value := range fields {
			target[key] = value
		}
		return nil
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		value, present := fields[name]
		if !present {
			delete(target, name)
			continue
		}
		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct {
			var err error
			value, err = mergeNestedStruct(target[name], value, fieldType)
			if err != nil {
				return err
			}
		}
		target[name] = value
	}
	return nil
}

func mergeNestedStruct(old, updated json.RawMessage, typ reflect.Type) (json.RawMessage, error) {
	var oldFields, newFields map[string]json.RawMessage
	if json.Unmarshal(old, &oldFields) == nil && oldFields != nil && json.Unmarshal(updated, &newFields) == nil && newFields != nil {
		if err := mergeStructFields(oldFields, newFields, typ); err != nil {
			return nil, err
		}
		return json.Marshal(oldFields)
	}
	return updated, nil
}

// UnknownFields copies top-level members not owned by core, excluding the
// separately namespaced extensions member.
func UnknownFields(object map[string]json.RawMessage, core any) map[string]json.RawMessage {
	fields := make(map[string]json.RawMessage, len(object))
	for key, value := range object {
		if key != "extensions" {
			fields[key] = value
		}
	}
	owned := reflect.TypeOf(core)
	for owned.Kind() == reflect.Pointer {
		owned = owned.Elem()
	}
	for i := range owned.NumField() {
		field := owned.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" {
			name = field.Name
		}
		delete(fields, name)
	}
	return fields
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
	result := make(map[string]json.RawMessage, len(object)+1)
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
