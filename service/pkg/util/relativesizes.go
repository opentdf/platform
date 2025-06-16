package util

import (
	"strconv"
	"strings"
)

// RelativeFileSizeToBytes converts a human-readable file size string (e.g., "10MB", "2GB")
// into its equivalent size in bytes as an int64. Supported units are "TB", "GB", "MB", "KB", and "B" (case-insensitive).
// If the input string cannot be parsed, the function returns the size of 1GB and the parsing error.
//
// Example inputs: "10MB", "2 gb", "512kb", "100b"
func RelativeFileSizeToBytes(size string, defaultSize int64) int64 {
	s := strings.TrimSpace(strings.ToLower(size))
	multiplier := int64(1)

	switch {
	case strings.HasSuffix(s, "tb"):
		multiplier = 1024 * 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "tb")
	case strings.HasSuffix(s, "gb"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "gb")
	case strings.HasSuffix(s, "mb"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "mb")
	case strings.HasSuffix(s, "kb"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "kb")
	case strings.HasSuffix(s, "b"):
		multiplier = 1
		s = strings.TrimSuffix(s, "b")
	}

	val, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		// fallback to defaultSize if parsing fails
		return defaultSize
	}
	return val * multiplier
}
