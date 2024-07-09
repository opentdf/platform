package util

import (
	"fmt"
	"reflect"
	"strings"
)

func RedactSensitiveData(i interface{}) interface{} {
	v := reflect.ValueOf(i)
	redacted := redact(v)
	return redacted.Interface()
}

func redact(v reflect.Value) reflect.Value {
	//nolint:exhaustive // default case covers other type
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return v
		}
		redacted := reflect.New(v.Elem().Type())
		redacted.Elem().Set(redact(v.Elem()))
		return redacted
	case reflect.Struct:
		redacted := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := v.Type().Field(i)
			tag := fieldType.Tag.Get("secret")
			if tag == "true" {
				// Redact sensitive fields
				redacted.Field(i).SetString("***")
			} else {
				// Recursively redact nested fields
				redacted.Field(i).Set(redact(field))
			}
		}
		return redacted
	case reflect.Map:
		redacted := reflect.MakeMap(v.Type())
		for _, key := range v.MapKeys() {
			val := v.MapIndex(key)
			redacted.SetMapIndex(key, redact(val))
		}
		return redacted
	case reflect.Slice:
		redacted := reflect.MakeSlice(v.Type(), v.Len(), v.Cap())
		for i := 0; i < v.Len(); i++ {
			redacted.Index(i).Set(redact(v.Index(i)))
		}
		return redacted
	default:
		return v
	}
}

func StructToString(v reflect.Value) string {
	var b strings.Builder
	//nolint:exhaustive // default case covers other type
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return "<nil>"
		}
		return StructToString(v.Elem())
	case reflect.Struct:
		b.WriteString("{")
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if i > 0 {
				b.WriteString(" ")
			}
			field := v.Field(i)
			fieldType := t.Field(i)
			b.WriteString(fieldType.Name)
			b.WriteString(":")
			b.WriteString(StructToString(field))
		}
		b.WriteString("}")
		return b.String()
	case reflect.Map:
		b.WriteString("map[")
		keys := v.MapKeys()
		for i, key := range keys {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString(fmt.Sprintf("%v:%v", key, StructToString(v.MapIndex(key))))
		}
		b.WriteString("]")
		return b.String()
	case reflect.Slice:
		b.WriteString("[")
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString(StructToString(v.Index(i)))
		}
		b.WriteString("]")
		return b.String()
	default:
		return fmt.Sprintf("%v", v.Interface())
	}
}
