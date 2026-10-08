package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

var ErrOpaqueConflict = errors.New("conflicting opaque configuration")

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
	return mergeStructFieldsOwned(target, fields, typ, coreFieldNames(typ))
}

func mergeStructFieldsOwned(target, fields map[string]json.RawMessage, typ reflect.Type, names []string) error {
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
		name, included := coreFieldName(field)
		if !included {
			continue
		}
		if name == "" {
			if err := mergeStructFieldsOwned(target, fields, field.Type, names); err != nil {
				return err
			}
			continue
		}
		value, present := fields[name]
		for key, old := range target {
			if coreFieldOwner(key, names) != name {
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
	return mergeUnknownStructFieldsOwned(source, destination, typ, path, coreFieldNames(typ))
}

func mergeUnknownStructFieldsOwned(source, destination map[string]json.RawMessage, typ reflect.Type, path string, names []string) error {
	typ = embeddedStruct(typ)
	if typ == nil {
		return nil
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		name, included := coreFieldName(field)
		if !included {
			continue
		}
		if name == "" {
			if err := mergeUnknownStructFieldsOwned(source, destination, field.Type, path, names); err != nil {
				return err
			}
			continue
		}
		if embeddedStruct(field.Type) == nil {
			continue
		}
		for sourceKey, sourceValue := range source {
			if coreFieldOwner(sourceKey, names) != name {
				continue
			}
			var sourceFields map[string]json.RawMessage
			if json.Unmarshal(sourceValue, &sourceFields) != nil || sourceFields == nil {
				continue
			}
			for destinationKey, destinationValue := range destination {
				if coreFieldOwner(destinationKey, names) != name {
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
