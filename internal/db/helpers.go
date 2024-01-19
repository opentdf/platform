package db

import "strings"

func removeProtobufEnumPrefix(s string) string {
	// find the first instance of TYPE_
	if strings.Contains(s, "TYPE_") {
		// remove everything left of it
		return s[strings.Index(s, "TYPE_")+5:]
	}
	return s
}
