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
		m = m[k].(map[string]interface{})
	}
	return nil
}
