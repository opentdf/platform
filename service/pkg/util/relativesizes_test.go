package util

import (
	"testing"
)

func TestRelativeFileSizeToBytes(t *testing.T) {
	tests := []struct {
		input     string
		expected  int64
		shouldErr bool
	}{
		{"1GB", 1024 * 1024 * 1024, false},
		{"10mb", 10 * 1024 * 1024, false},
		{"512kb", 512 * 1024, false},
		{"100b", 100, false},
		{"2 TB", 2 * 1024 * 1024 * 1024 * 1024, false},
		{"  5 gb  ", 5 * 1024 * 1024 * 1024, false},
		{"42", 42, false},                     // No unit, should be bytes
		{"invalid", 1024 * 1024 * 1024, true}, // Should fallback to 1GB
	}

	for _, tt := range tests {
		got := RelativeFileSizeToBytes(tt.input, 1024*1024*1024)
		if tt.shouldErr {
			if got != 1024*1024*1024 {
				t.Errorf("expected fallback value for input %q, got %d", tt.input, got)
			}
			continue
		}
		if got != tt.expected {
			t.Errorf("for input %q, expected %d, got %d", tt.input, tt.expected, got)
		}
	}
}
