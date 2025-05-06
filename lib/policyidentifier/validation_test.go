package policyidentifier

import (
	"strings"
	"testing"
)

func TestValidObjectNameRegex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid cases
		{"Simple alphanumeric", "abc123", true},
		{"Single letter", "a", true},
		{"Single number", "1", true},
		{"With underscore middle", "abc_123", true},
		{"With hyphen middle", "abc-123", true},
		{"Max length 253", "a" + strings.Repeat("b", 251) + "c", true},

		// Invalid cases
		{"With dot middle", "abc.123", false},
		{"Mixed special chars", "abc-123_def.456", false},
		{"Empty string", "", false},
		{"Underscore start", "_abc123", false},
		{"Underscore end", "abc123_", false},
		{"Hyphen start", "-abc123", false},
		{"Hyphen end", "abc123-", false},
		{"Dot start", ".abc123", false},
		{"Dot end", "abc123.", false},
		{"Special character", "abc@123", false},
		{"With spaces", "abc 123", false},
		{"Too long > 253", "a" + strings.Repeat("b", 252) + "c", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validObjectNameRegex.MatchString(tt.input)
			if got != tt.want {
				t.Errorf("validObjectNameRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidNamespaceRegex(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      bool
	}{
		// Valid namespaces
		{
			name:      "simple domain",
			namespace: "example.com",
			want:      true,
		},
		{
			name:      "subdomain",
			namespace: "sub.example.com",
			want:      true,
		},
		{
			name:      "multiple subdomains",
			namespace: "deep.sub.example.com",
			want:      true,
		},
		{
			name:      "with numbers",
			namespace: "example123.com",
			want:      true,
		},
		{
			name:      "domain with hyphen",
			namespace: "example-domain.com",
			want:      true,
		},
		{
			name:      "complex domain",
			namespace: "my-example123.sub.example-domain.com",
			want:      true,
		},
		{
			name:      "minimum valid domain",
			namespace: "a.co",
			want:      true,
		},
		{
			name:      "long segment at max 63 char limit",
			namespace: "abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz-abcdefghi.com",
			want:      true,
		},

		// Invalid namespaces
		{
			name:      "empty string",
			namespace: "",
			want:      false,
		},
		{
			name:      "no TLD",
			namespace: "example",
			want:      false,
		},
		{
			name:      "TLD too short",
			namespace: "example.c",
			want:      false,
		},
		{
			name:      "numeric TLD",
			namespace: "example.123",
			want:      false,
		},
		{
			name:      "hyphen at start of segment",
			namespace: "-example.com",
			want:      false,
		},
		{
			name:      "hyphen at end of segment",
			namespace: "example-.com",
			want:      false,
		},
		{
			name:      "segment too long (> 63 chars)",
			namespace: "abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz-abcdefghij.com",
			want:      false,
		},
		{
			name:      "invalid characters",
			namespace: "example_domain.com",
			want:      false,
		},
		{
			name:      "starts with dot",
			namespace: ".example.com",
			want:      false,
		},
		{
			name:      "ends with dot",
			namespace: "example.com.",
			want:      false,
		},
		{
			name:      "double dots",
			namespace: "example..com",
			want:      false,
		},
		{
			name:      "IP address format",
			namespace: "192.168.1.1",
			want:      false, // This is actually invalid because TLD must be letters
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validNamespaceRegex.MatchString(tt.namespace); got != tt.want {
				t.Errorf("validNamespaceRegex.MatchString(%q) = %v, want %v", tt.namespace, got, tt.want)
			}
		})
	}
}
