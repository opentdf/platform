package store

import (
	"encoding/json"
	"reflect"
	"strings"
)

func embeddedStruct(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Struct {
		return typ
	}
	return nil
}

// coreFieldName centralizes the existing inclusion rule for all ownership walkers.
// An included field with an empty name is an anonymous struct promoted into the
// current object. Explicitly tagged unexported fields remain excluded.
func coreFieldName(field reflect.StructField) (string, bool) {
	name := strings.Split(field.Tag.Get("json"), ",")[0]
	if name == "-" {
		return "", false
	}
	if name == "" && field.Anonymous && embeddedStruct(field.Type) != nil {
		return "", true
	}
	if !field.IsExported() {
		return "", false
	}
	if name == "" {
		name = field.Name
	}
	return name, true
}

// coreFieldNames keeps declared exact names separate from folded aliases, including
// promoted anonymous fields at the same JSON object boundary.
func coreFieldNames(typ reflect.Type) []string {
	if typ == nil || embeddedStruct(typ) == nil {
		return nil
	}
	typ = embeddedStruct(typ)
	var names []string
	for i := range typ.NumField() {
		field := typ.Field(i)
		name, included := coreFieldName(field)
		if !included {
			continue
		}
		if name == "" {
			names = append(names, coreFieldNames(field.Type)...)
			continue
		}
		names = append(names, name)
	}
	return names
}

func coreFieldOwner(key string, names []string) string {
	for _, name := range names {
		if key == name {
			return name
		}
	}
	for _, name := range names {
		if strings.EqualFold(key, name) {
			return name
		}
	}
	return ""
}

func deleteOwnedFields(fields map[string]json.RawMessage, typ reflect.Type) {
	if typ == nil || embeddedStruct(typ) == nil {
		return
	}
	typ = embeddedStruct(typ)
	for i := range typ.NumField() {
		field := typ.Field(i)
		name, included := coreFieldName(field)
		if !included {
			continue
		}
		if name == "" {
			deleteOwnedFields(fields, field.Type)
			continue
		}
		for key := range fields {
			if strings.EqualFold(key, name) {
				delete(fields, key)
			}
		}
	}
}
