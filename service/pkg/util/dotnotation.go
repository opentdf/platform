package util

import "strings"

func Dotnotation(m map[string]interface{}, key string) interface{} {
	keys := strings.Split(key, ".")
	for i, k := range keys {
		if i == len(keys)-1 {
			return m[k]
		}
		if m[k] == nil {
			return nil
		}
		var ok bool
		m, ok = m[k].(map[string]interface{})
		if !ok {
			return nil
		}
	}
	return nil
}
