package util

import (
	"reflect"
	"strings"
)

func RedactSensitiveData(i interface{}, sensitiveFields []string) interface{} {
	v := reflect.ValueOf(i)
	redacted := redact(v, sensitiveFields)
	return redacted.Interface()
}

func redact(v reflect.Value, sensitiveFields []string) reflect.Value {
	//nolint:exhaustive // default case covers other type
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return v
		}
		redacted := reflect.New(v.Elem().Type())
		redacted.Elem().Set(redact(v.Elem(), sensitiveFields))
		return redacted
	case reflect.Struct:
		redacted := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := v.Type().Field(i)
			if fieldType.Type.Kind() == reflect.String && contains(sensitiveFields, fieldType.Name) {
				redacted.Field(i).SetString("REDACTED")
			} else {
				redacted.Field(i).Set(redact(field, sensitiveFields))
			}
		}
		return redacted
	case reflect.Map:
		redacted := reflect.MakeMap(v.Type())
		for _, key := range v.MapKeys() {
			val := v.MapIndex(key)
			if key.Kind() == reflect.String && contains(sensitiveFields, key.String()) {
				redacted.SetMapIndex(key, reflect.ValueOf("REDACTED"))
			} else {
				redacted.SetMapIndex(key, redact(val, sensitiveFields))
			}
		}
		return redacted
	case reflect.Slice:
		redacted := reflect.MakeSlice(v.Type(), v.Len(), v.Cap())
		for i := 0; i < v.Len(); i++ {
			redacted.Index(i).Set(redact(v.Index(i), sensitiveFields))
		}
		return redacted
	default:
		return v
	}
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if strings.EqualFold(a, item) {
			return true
		}
	}
	return false
}
