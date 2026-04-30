package namespacedpolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTargetRefString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target TargetRef
		want   string
	}{
		{name: "empty", target: TargetRef{}, want: `id="" (namespace="")`},
		{
			name: "id only",
			target: TargetRef{
				ID: "target-1",
			},
			want: `id="target-1" (namespace="")`,
		},
		{
			name: "id with namespace id",
			target: TargetRef{
				ID:          "target-1",
				NamespaceID: "namespace-1",
			},
			want: `id="target-1" (namespace="namespace-1")`,
		},
		{
			name: "id with namespace fqn",
			target: TargetRef{
				ID:           "target-1",
				NamespaceID:  "namespace-1",
				NamespaceFQN: "https://example.com",
			},
			want: `id="target-1" (namespace="https://example.com")`,
		},
		{
			name: "namespace without id",
			target: TargetRef{
				NamespaceFQN: "https://example.com",
			},
			want: `id="" (namespace="https://example.com")`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.target.String())
		})
	}
}
