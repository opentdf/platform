package namespacedpolicy

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNamespaceFromAttributeValueFallsBackToValueFQN(t *testing.T) {
	t.Parallel()

	namespace := namespaceFromAttributeValue(&policy.Value{
		Fqn: "https://example.com/attr/classification/value/secret",
	})
	require.NotNil(t, namespace)
	assert.Equal(t, "https://example.com", namespace.GetFqn())
}
