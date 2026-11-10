package resourcemapping

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/stretchr/testify/require"
)

const (
	validUUID              = "390e0058-7ae8-48f6-821c-9db07c831276"
	errMessageOptionalUUID = "optional_uuid_format"
	errMessageMinItems     = "min_items"
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

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func getMaxTerms() []string {
	maxTerms := make([]string, 1000)
	for i := range maxTerms {
		maxTerms[i] = "abc"
	}
	return maxTerms
}

func runFqnValidator(fqn string) error {
	req := &resourcemapping.ListResourceMappingsByGroupFqnsRequest{
		Fqns: []string{fqn},
	}

	err := getValidator().Validate(req)
	return err
}

func Test_ListResourceMappingsByGroupFqnsRequest_Valid_Succeeds(t *testing.T) {
	for _, fqn := range validFqns {
		err := runFqnValidator(fqn)
		require.NoError(t, err, "valid FQN failed: %s", fqn)
	}
}

func Test_ListResourceMappingsByGroupFqnsRequest_Invalid_Fails(t *testing.T) {
	for _, fqn := range invalidFqns {
		err := runFqnValidator(fqn)
		require.Error(t, err, "invalid FQN succeeded: %s", fqn)
	}
}

func Test_ListResourceMappingsByGroupFqnsRequest_EmptyArray_Fails(t *testing.T) {
	req := &resourcemapping.ListResourceMappingsByGroupFqnsRequest{
		Fqns: []string{},
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageMinItems)
}

func Test_ListResourceMappingsByGroupFqnsRequest_NilArray_Fails(t *testing.T) {
	req := &resourcemapping.ListResourceMappingsByGroupFqnsRequest{
		Fqns: nil,
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageMinItems)
}

func Test_ListResourceMappingsByGroupFqnsRequest_AnyInvalid_Fails(t *testing.T) {
	req := &resourcemapping.ListResourceMappingsByGroupFqnsRequest{
		Fqns: []string{
			validFqns[0],
			invalidFqns[0],
		},
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_ListResourceMappingsByGroupFqnsRequest_AllValid_Succeeds(t *testing.T) {
	req := &resourcemapping.ListResourceMappingsByGroupFqnsRequest{
		Fqns: validFqns,
	}

	err := getValidator().Validate(req)
	require.NoError(t, err)
}

func Test_ListResourceMappingsRequest_Succeeds(t *testing.T) {
	v := getValidator()
	req := &resourcemapping.ListResourceMappingsRequest{}

	err := v.Validate(req)
	require.NoError(t, err, "group_id is optional")

	req.GroupId = validUUID
	err = v.Validate(req)
	require.NoError(t, err, "group_id is valid UUID")

	req.GroupId = "invalid-id"
	err = v.Validate(req)
	require.Error(t, err, "group_id is not a valid UUID")
	require.Contains(t, err.Error(), errMessageOptionalUUID)
}

func Test_CreateResourceMappingRequest_Succeeds(t *testing.T) {
	v := getValidator()
	maxTerms := getMaxTerms()

	good := []struct {
		valueID  string
		terms    []string
		groupID  string
		scenario string
	}{
		{
			validUUID,
			[]string{"term1", "term2"},
			validUUID,
			"everything provided",
		},
		{
			validUUID,
			[]string{"term1", "term2"},
			"",
			"empty group ID",
		},
		{
			validUUID,
			[]string{"term1"},
			"",
			"min terms list",
		},
		{
			validUUID,
			maxTerms,
			"",
			"max terms list length",
		},
	}

	for _, test := range good {
		req := &resourcemapping.CreateResourceMappingRequest{
			AttributeValueId: test.valueID,
			Terms:            test.terms,
			GroupId:          test.groupID,
		}
		err := v.Validate(req)
		require.NoError(t, err, test.scenario)
	}
}

func Test_CreateResourceMappingRequest_Fails(t *testing.T) {
	v := getValidator()
	maxTerms := getMaxTerms()

	bad := []struct {
		valueID  string
		terms    []string
		groupID  string
		scenario string
	}{
		{
			validUUID,
			append(maxTerms, "abc"),
			validUUID,
			"one term above max list length",
		},
		{
			validUUID,
			[]string{},
			"",
			"empty terms list",
		},
		{
			validUUID,
			nil,
			"",
			"nil terms list",
		},
		{
			"",
			[]string{"term1"},
			"",
			"empty attribute value ID",
		},
		{
			"bad-id",
			[]string{"term1"},
			"",
			"invalid attribute value ID",
		},
		{
			validUUID,
			maxTerms,
			"bad-id",
			"invalid group id",
		},
	}

	for _, test := range bad {
		req := &resourcemapping.CreateResourceMappingRequest{
			AttributeValueId: test.valueID,
			Terms:            test.terms,
			GroupId:          test.groupID,
		}
		err := v.Validate(req)
		require.Error(t, err, test.scenario)
	}
}

func Test_UpdateResourceMappingRequest_Succeeds(t *testing.T) {
	v := getValidator()
	maxTerms := getMaxTerms()

	good := []struct {
		valueID  string
		terms    []string
		groupID  string
		scenario string
	}{
		{
			validUUID,
			[]string{"term1", "term2"},
			validUUID,
			"everything provided",
		},
		{
			validUUID,
			[]string{"term1", "term2"},
			"",
			"empty group ID",
		},
		{
			validUUID,
			[]string{},
			"",
			"empty terms list",
		},
		{
			validUUID,
			nil,
			"",
			"nil terms list",
		},
		{
			"",
			[]string{"term1"},
			"",
			"empty valud ID",
		},
		{
			"",
			maxTerms,
			"",
			"max terms list length",
		},
	}

	for _, test := range good {
		req := &resourcemapping.UpdateResourceMappingRequest{
			Id:               validUUID,
			AttributeValueId: test.valueID,
			Terms:            test.terms,
			GroupId:          test.groupID,
		}
		err := v.Validate(req)
		require.NoError(t, err, test.scenario)
	}
}

func Test_UpdateResourceMappingRequest_Fails(t *testing.T) {
	v := getValidator()
	maxTerms := getMaxTerms()

	bad := []struct {
		id       string
		valueID  string
		terms    []string
		groupID  string
		scenario string
	}{
		{
			validUUID,
			validUUID,
			append(maxTerms, "abc"),
			validUUID,
			"one term above max list length",
		},
		{
			"bad-id",
			validUUID,
			[]string{},
			"",
			"invalid resource mapping ID",
		},
		{
			"",
			validUUID,
			[]string{},
			"",
			"empty required resource mapping ID",
		},
		{
			validUUID,
			"bad-id",
			[]string{"term1"},
			"",
			"invalid attribute value ID",
		},
		{
			validUUID,
			validUUID,
			maxTerms,
			"bad-id",
			"invalid group id",
		},
	}

	for _, test := range bad {
		req := &resourcemapping.CreateResourceMappingRequest{
			AttributeValueId: test.valueID,
			Terms:            test.terms,
			GroupId:          test.groupID,
		}
		err := v.Validate(req)
		require.Error(t, err, test.scenario)
	}
}
