package resourcemapping

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/stretchr/testify/require"
)

var (
	validFqns = []string{
		"https://example.com/resm/group1",
		"https://scenario.com/resm/group2",
		"https://hypenated-ns.com/resm/group3",
	}

	invalidFqns = []string{
		// empty string
		"",

		// invalid string
		"invalid",

		// http protocol
		"http://example.com/resm/group1",

		// invalid namespace
		"https://invalid/resm/group1",
		"https://example.com-/resm/group2",
		"https://-example.com/resm/group2",
		"https://example.c/resm-/group3",

		// missing /resm/ qualifier
		"https://example.com/group1",
		"https://scenario.com/invalid/group2",

		// invalid group name
		"https://example.com/resm/-group_1",
		"https://example.com/resm/group2-",
		"https://example.com/resm/group!_3",
	}
)

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func runFqnValidator(fqn string) error {
	req := &resourcemapping.ListResourceMappingGroupsByFqnsRequest{
		Fqns: []string{fqn},
	}

	err := getValidator().Validate(req)
	return err
}

func Test_ListResourceMappingGroupsByFqnsRequest_Valid_Succeeds(t *testing.T) {
	for _, fqn := range validFqns {
		err := runFqnValidator(fqn)
		require.NoError(t, err, "valid FQN failed: %s", fqn)
	}
}

func Test_ListResourceMappingGroupsByFqnsRequest_Invalid_Fails(t *testing.T) {
	for _, fqn := range invalidFqns {
		err := runFqnValidator(fqn)
		require.Error(t, err, "invalid FQN succeeded: %s", fqn)
	}
}

func Test_ListResourceMappingGroupsByFqnsRequest_EmptyArray_Fails(t *testing.T) {
	req := &resourcemapping.ListResourceMappingGroupsByFqnsRequest{
		Fqns: []string{},
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_ListResourceMappingGroupsByFqnsRequest_NilArray_Fails(t *testing.T) {
	req := &resourcemapping.ListResourceMappingGroupsByFqnsRequest{
		Fqns: nil,
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_ListResourceMappingGroupsByFqnsRequest_AnyInvalid_Fails(t *testing.T) {
	req := &resourcemapping.ListResourceMappingGroupsByFqnsRequest{
		Fqns: []string{
			validFqns[0],
			invalidFqns[0],
		},
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_ListResourceMappingGroupsByFqnsRequest_AllValid_Succeeds(t *testing.T) {
	req := &resourcemapping.ListResourceMappingGroupsByFqnsRequest{
		Fqns: validFqns,
	}

	err := getValidator().Validate(req)
	require.NoError(t, err)
}
