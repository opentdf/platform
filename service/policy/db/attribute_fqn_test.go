package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefinitionFqnFromValueFqn(t *testing.T) {
	tests := []struct {
		name     string
		valueFqn string
		want     string
	}{
		{
			name:     "https value fqn",
			valueFqn: "https://example.com/attr/foo/value/bar",
			want:     "https://example.com/attr/foo",
		},
		{
			name:     "http value fqn",
			valueFqn: "http://example.com/attr/foo/value/bar",
			want:     "http://example.com/attr/foo",
		},
		{
			name:     "definition fqn",
			valueFqn: "https://example.com/attr/foo",
			want:     "",
		},
		{
			name:     "invalid fqn",
			valueFqn: "not-a-fqn",
			want:     "",
		},
		{
			name:     "empty string",
			valueFqn: "",
			want:     "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := definitionFqnFromValueFqn(tc.valueFqn)
			assert.Equal(t, tc.want, got)
		})
	}
}
