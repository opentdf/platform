package dynamicentitlement

import (
	"testing"

	"github.com/opentdf/platform/lib/flattening"
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

// --- shared test helpers ---

func entityRep(t *testing.T, props map[string]interface{}) *entityresolution.EntityRepresentation {
	t.Helper()
	s, err := structpb.NewStruct(props)
	require.NoError(t, err)
	return &entityresolution.EntityRepresentation{
		OriginalId:      "entity-1",
		AdditionalProps: []*structpb.Struct{s},
	}
}

func actions(names ...string) []*policy.Action {
	out := make([]*policy.Action, 0, len(names))
	for _, n := range names {
		out = append(out, &policy.Action{Name: n})
	}
	return out
}

func actionNames(acts []*policy.Action) []string {
	out := make([]string, 0, len(acts))
	for _, a := range acts {
		out = append(out, a.GetName())
	}
	return out
}

// --- core mechanic tests ---

func TestParseResourceValue(t *testing.T) {
	def, seg, err := parseResourceValue("https://hospital.co/attr/mrn/value/mrn-123")
	require.NoError(t, err)
	assert.Equal(t, "https://hospital.co/attr/mrn", def)
	assert.Equal(t, "mrn-123", seg)

	// case is normalized to lowercase, matching lib/identifier behavior
	def, seg, err = parseResourceValue("https://hospital.co/attr/MRN/value/MRN-123")
	require.NoError(t, err)
	assert.Equal(t, "https://hospital.co/attr/mrn", def)
	assert.Equal(t, "mrn-123", seg)

	// a definition FQN (no /value/) is not a value FQN
	_, _, err = parseResourceValue("https://hospital.co/attr/mrn")
	require.ErrorIs(t, err, ErrNotValueFQN)

	// an email-like value is rejected by the current (strict) identifier character set —
	// a finding: today's value grammar cannot represent emails/dotted IDs.
	_, _, err = parseResourceValue("https://acme.co/attr/owner/value/user@acme.co")
	require.Error(t, err)
}

func TestValidateValueSegment(t *testing.T) {
	for _, s := range []string{"mrn-123", "abc", "a_b-c", "123", "acct-42"} {
		require.NoError(t, validateValueSegment(s), s)
	}
	// FQN-structural chars, percent-encoding, NUL, and non-ASCII are always forbidden.
	for _, s := range []string{"", "a/b", "a.b", "a%2Fb", "a\x00b", "naïve"} {
		require.ErrorIs(t, validateValueSegment(s), ErrAmbiguousValueSegment, s)
	}
}

func TestEvaluateDynamicMatchOperatorErrors(t *testing.T) {
	f, err := flattening.Flatten(map[string]interface{}{"a": "b"})
	require.NoError(t, err)

	_, err = evaluateDynamicMatch(OperatorUnspecified, f, ".a", "b", nil)
	require.ErrorIs(t, err, ErrUnspecifiedOperator)

	_, err = evaluateDynamicMatch(DynamicOperator(99), f, ".a", "b", nil)
	require.ErrorIs(t, err, ErrUnsupportedOperator)
}

func TestEvaluateDynamicMatchSemantics(t *testing.T) {
	f, err := flattening.Flatten(map[string]interface{}{
		"scalar": "mrn-123",
		"list":   []interface{}{"a", "prefix-team-suffix"},
	})
	require.NoError(t, err)

	got, err := evaluateDynamicMatch(ResourceValueIn, f, ".scalar", "mrn-123", nil)
	require.NoError(t, err)
	assert.True(t, got)

	got, err = evaluateDynamicMatch(ResourceValueIn, f, ".scalar", "mrn-999", nil)
	require.NoError(t, err)
	assert.False(t, got)

	// substring semantics: "team" is contained in "prefix-team-suffix"
	got, err = evaluateDynamicMatch(ResourceValueInContains, f, ".list[]", "team", nil)
	require.NoError(t, err)
	assert.True(t, got)
}
