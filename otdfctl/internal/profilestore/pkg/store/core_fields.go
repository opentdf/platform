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
// current object. Like encoding/json, unexported anonymous structs can own
// exported JSON fields, including when the embedded struct has an explicit tag.
func coreFieldName(field reflect.StructField) (string, bool) {
	name := strings.Split(field.Tag.Get("json"), ",")[0]
	if name == "-" {
		return "", false
	}
	if name == "" && field.Anonymous && embeddedStruct(field.Type) != nil {
		return "", true
	}
	if !field.IsExported() && (!field.Anonymous || embeddedStruct(field.Type) == nil) {
		return "", false
	}
	if name == "" {
		name = field.Name
	}
	return name, true
}

// coreFields flattens anonymous promotion at one JSON object boundary. The
// active path prevents recursive anonymous pointers from recursing forever;
// the same type can still appear independently on another promotion path.
func coreFields(typ reflect.Type) []reflect.StructField {
	return appendCoreFields(nil, typ, make(map[reflect.Type]bool))
}

func appendCoreFields(fields []reflect.StructField, typ reflect.Type, active map[reflect.Type]bool) []reflect.StructField {
	if typ == nil {
		return fields
	}
	typ = embeddedStruct(typ)
	if typ == nil || active[typ] {
		return fields
	}
	active[typ] = true
	defer delete(active, typ)
	for i := range typ.NumField() {
		field := typ.Field(i)
		name, included := coreFieldName(field)
		if !included {
			continue
		}
		if name == "" {
			fields = appendCoreFields(fields, field.Type, active)
			continue
		}
		fields = append(fields, field)
	}
	return fields
}

// coreFieldNames keeps declared exact names separate from folded aliases, including
// promoted anonymous fields at the same JSON object boundary.
func coreFieldNames(typ reflect.Type) []string {
	var names []string
	for _, field := range coreFields(typ) {
		name, _ := coreFieldName(field)
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
	for _, name := range coreFieldNames(typ) {
		for key := range fields {
			if strings.EqualFold(key, name) {
				delete(fields, key)
			}
		}
	}
}
