package namespacedpolicy

import "regexp"

func stripANSI(value string) string {
	tidyWhitespace := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return tidyWhitespace.ReplaceAllString(value, "")
}
