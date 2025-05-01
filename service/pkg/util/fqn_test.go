package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseResourceMappingGroupFqn_Valid_Succeeds(t *testing.T) {
	fqn := "https://namespace.com/resm/group_name"

	parsed, err := ParseResourceMappingGroupFqn(fqn)
	require.NoError(t, err)
	require.Equal(t, fqn, parsed.Fqn)
	require.Equal(t, "namespace.com", parsed.Namespace)
	require.Equal(t, "group_name", parsed.GroupName)
}

func TestParseResourceMappingGroupFqn_Invalid_Fails(t *testing.T) {
	invalidFQNs := []string{
		"",
		"invalid",
		"https://namespace.com",
		"http://namespace.com/resm/group_name",
		"somethinghttps://namespace.com/resm/group_name",
		"https://namespace.com/resm",
		"https://namespace.com/resm/",
	}

	for _, fqn := range invalidFQNs {
		parsed, err := ParseResourceMappingGroupFqn(fqn)
		require.EqualError(t, err, "error: valid FQN format of https://<namespace>/resm/<group name> must be provided")
		require.Nil(t, parsed)
	}
}

func TestParseRegisteredResourceValueFqn_Valid_Succeeds(t *testing.T) {
	fqn := "https://reg_res/valid/value/test"

	parsed, err := ParseRegisteredResourceValueFqn(fqn)
	require.NoError(t, err)
	require.Equal(t, fqn, parsed.Fqn)
	require.Equal(t, "valid", parsed.Name)
	require.Equal(t, "test", parsed.Value)
}

func TestParseRegisteredResourceValueFqn_Invalid_Fails(t *testing.T) {
	invalidFQNs := []string{
		"",
		"invalid",
		"https://reg_res",
		"https://reg_res/invalid",
		"http://reg_res/test/value/something",
		"somethinghttps://reg_res/test/value/something",
		"https://reg_res/invalid/value",
		"https://reg_res/invalid/value/",
	}

	for _, fqn := range invalidFQNs {
		parsed, err := ParseRegisteredResourceValueFqn(fqn)
		require.EqualError(t, err, "error: valid FQN format of https://reg_res/<name>/value/<value> must be provided")
		require.Nil(t, parsed)
	}
}
