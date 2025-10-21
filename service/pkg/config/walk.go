package config

import (
	"reflect"
)

// walk traverses v and calls fn for each Secret encountered.
func walk(v any, fn func(*Secret) error) error {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	return walkValue(rv, fn)
}

func walkValue(rv reflect.Value, fn func(*Secret) error) error {
	if !rv.IsValid() {
		return nil
	}
	// Follow pointers
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}

	//nolint:exhaustive // We only need to traverse struct, map, slice, and array kinds for secrets
	switch rv.Kind() {
	case reflect.Struct:
		rt := rv.Type()
		// Handle Secret itself
		if rt == reflect.TypeOf(Secret{}) {
			if rv.CanAddr() {
				if s, ok := rv.Addr().Interface().(*Secret); ok {
					return fn(s)
				}
				return nil
			}
			// For non-addressable Secret values (e.g., map index), operate on a copy.
			if s, ok := rv.Interface().(Secret); ok {
				return fn(&s)
			}
			return nil
		}
		// Iterate exported fields
		for i := 0; i < rv.NumField(); i++ {
			// Only exported fields
			if rt.Field(i).IsExported() {
				if err := walkValue(rv.Field(i), fn); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		for _, k := range rv.MapKeys() {
			if err := walkValue(rv.MapIndex(k), fn); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < rv.Len(); i++ {
			if err := walkValue(rv.Index(i), fn); err != nil {
				return err
			}
		}
	default:
		// Other kinds: nothing to do
	}
	return nil
}
