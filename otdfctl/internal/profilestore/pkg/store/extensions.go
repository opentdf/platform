package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
)

var (
	ErrInvalidExtensions = errors.New("invalid extensions")
	ErrOpaqueConflict    = errors.New("conflicting opaque configuration")
)

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
	merged := make(map[string]json.RawMessage, len(object))
	for key, value := range object {
		merged[key] = value
	}
	if err := mergeStructFields(merged, fields, reflect.TypeOf(core)); err != nil {
		return nil, err
	}
	return merged, nil
}

// mergeStructFields canonicalizes the case-insensitive core keys accepted by
// encoding/json, including omitted members. Unknown nested members are retained;
// differing opaque values across aliases are rejected rather than choosing one.
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
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" && field.Anonymous && embeddedStruct(field.Type) != nil {
			if err := mergeStructFields(target, fields, field.Type); err != nil {
				return err
			}
			continue
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		value, present := fields[name]
		for key, old := range target {
			if !strings.EqualFold(key, name) {
				continue
			}
			if present && embeddedStruct(field.Type) != nil {
				var err error
				value, err = mergeNestedStruct(old, value, field.Type)
				if err != nil {
					return err
				}
			}
			delete(target, key)
		}
		if present {
			target[name] = value
		}
	}
	return nil
}

func mergeNestedStruct(old, updated json.RawMessage, typ reflect.Type) (json.RawMessage, error) {
	var oldFields, newFields map[string]json.RawMessage
	if json.Unmarshal(old, &oldFields) == nil && oldFields != nil && json.Unmarshal(updated, &newFields) == nil && newFields != nil {
		if err := mergeUnknownObjectFields(oldFields, newFields, typ, ""); err != nil {
			return nil, err
		}
		return json.Marshal(newFields)
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
	deleteOwnedFields(fields, reflect.TypeOf(core))
	return fields
}

func embeddedStruct(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Struct {
		return typ
	}
	return nil
}

func deleteOwnedFields(fields map[string]json.RawMessage, typ reflect.Type) {
	if typ == nil || embeddedStruct(typ) == nil {
		return
	}
	typ = embeddedStruct(typ)
	for i := range typ.NumField() {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" && field.Anonymous && embeddedStruct(field.Type) != nil {
			deleteOwnedFields(fields, field.Type)
			continue
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		for key := range fields {
			if strings.EqualFold(key, name) {
				delete(fields, key)
			}
		}
	}
}

// CheckOpaqueConflicts rejects a migration that would overwrite destination-owned opaque values.
func CheckOpaqueConflicts(source, destination map[string]json.RawMessage, core any) error {
	for key, value := range UnknownFields(source, core) {
		if existing, ok := destination[key]; ok && !sameJSON(value, existing) {
			return fmt.Errorf("%w: field %q", ErrOpaqueConflict, key)
		}
	}
	sourceExtensions, err := Extensions(source)
	if err != nil {
		return err
	}
	destinationExtensions, err := Extensions(destination)
	if err != nil {
		return err
	}
	for namespace, value := range sourceExtensions {
		if existing, ok := destinationExtensions[namespace]; ok && !sameJSON(value, existing) {
			return fmt.Errorf("%w: extension %q", ErrOpaqueConflict, namespace)
		}
	}
	_, err = MergeUnknownNested(source, destination, core)
	return err
}

// MergeUnknownNested transfers unknown members at core struct boundaries without
// replacing destination-owned core values. It rejects differing opaque members.
func MergeUnknownNested(source, destination map[string]json.RawMessage, core any) (map[string]json.RawMessage, error) {
	merged := make(map[string]json.RawMessage, len(destination))
	for key, value := range destination {
		merged[key] = value
	}
	if err := mergeUnknownStructFields(source, merged, reflect.TypeOf(core), ""); err != nil {
		return nil, err
	}
	return merged, nil
}

func mergeUnknownStructFields(source, destination map[string]json.RawMessage, typ reflect.Type, path string) error {
	typ = embeddedStruct(typ)
	if typ == nil {
		return nil
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" && field.Anonymous && embeddedStruct(field.Type) != nil {
			if err := mergeUnknownStructFields(source, destination, field.Type, path); err != nil {
				return err
			}
			continue
		}
		if !field.IsExported() || embeddedStruct(field.Type) == nil {
			continue
		}
		if name == "" {
			name = field.Name
		}
		for sourceKey, sourceValue := range source {
			if !strings.EqualFold(sourceKey, name) {
				continue
			}
			var sourceFields map[string]json.RawMessage
			if json.Unmarshal(sourceValue, &sourceFields) != nil || sourceFields == nil {
				continue
			}
			for destinationKey, destinationValue := range destination {
				if !strings.EqualFold(destinationKey, name) {
					continue
				}
				var destinationFields map[string]json.RawMessage
				if json.Unmarshal(destinationValue, &destinationFields) != nil || destinationFields == nil {
					continue
				}
				if err := mergeUnknownObjectFields(sourceFields, destinationFields, field.Type, path+name+"."); err != nil {
					return err
				}
				encoded, err := json.Marshal(destinationFields)
				if err != nil {
					return err
				}
				destination[destinationKey] = encoded
			}
		}
	}
	return nil
}

func mergeUnknownObjectFields(source, destination map[string]json.RawMessage, typ reflect.Type, path string) error {
	unknown := make(map[string]json.RawMessage, len(source))
	for key, value := range source {
		unknown[key] = value
	}
	deleteOwnedFields(unknown, typ)
	for key, value := range unknown {
		if existing, ok := destination[key]; ok && !sameJSON(value, existing) {
			return fmt.Errorf("%w: field %q", ErrOpaqueConflict, path+key)
		}
		destination[key] = value
	}
	return mergeUnknownStructFields(source, destination, typ, path)
}

func sameJSON(a, b json.RawMessage) bool {
	var compactA, compactB bytes.Buffer
	return json.Compact(&compactA, a) == nil && json.Compact(&compactB, b) == nil && bytes.Equal(compactA.Bytes(), compactB.Bytes())
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
