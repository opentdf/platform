package access

import (
	"log/slog"
	"sync"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/service/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPolicyConstructionDoesNotMutateSharedValues(t *testing.T) {
	const definitionFQN = "https://scale.example/attr/department"
	value := &policy.Value{Fqn: definitionFQN + "/value/engineering"}
	attr := &policy.Attribute{Fqn: definitionFQN, Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, Values: []*policy.Value{value}}
	// The second mapping exercises values absent from the definition's value list.
	mappings := []*policy.SubjectMapping{
		{Id: "existing", AttributeValue: value, Actions: []*policy.Action{{Name: "read"}}},
		{Id: "additional", AttributeValue: &policy.Value{Fqn: definitionFQN + "/value/sales"}, Actions: []*policy.Action{{Name: "read"}}},
	}
	originalAttribute := proto.CloneOf(attr)
	originalMapping := proto.CloneOf(mappings[1])
	log := &logger.Logger{Logger: slog.New(slog.DiscardHandler)}
	ctx := t.Context()
	const constructions = 16
	results := make(chan *PolicyDecisionPoint, constructions)
	errors := make(chan error, constructions)
	var workers sync.WaitGroup
	for range constructions {
		workers.Go(func() {
			pdp, err := NewPolicyDecisionPoint(ctx, log, []*policy.Attribute{attr}, mappings, nil, true, false)
			results <- pdp
			errors <- err
		})
	}
	workers.Wait()
	close(results)
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	for pdp := range results {
		for _, mapping := range mappings {
			got := pdp.allEntitleableAttributesByValueFQN[mapping.GetAttributeValue().GetFqn()]
			require.Len(t, got.GetValue().GetSubjectMappings(), 1)
		}
	}
	require.True(t, proto.Equal(originalAttribute, attr))
	require.True(t, proto.Equal(originalMapping, mappings[1]))
}
