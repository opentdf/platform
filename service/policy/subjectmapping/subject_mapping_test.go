package subjectmapping

import (
	"testing"

	"github.com/bufbuild/protovalidate-go"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/require"
)

func getValidator() *protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

func Test_CreateSubjectMappingRequest_NilActionsArray_Fails(t *testing.T) {
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: "av-test-id",
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_CreateSubjectMappingRequest_EmptyActionsArray_Fails(t *testing.T) {
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: "av-test-id",
		Actions:          []*policy.Action{},
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_CreateSubjectMappingRequest_PopulatedArray_Succeeds(t *testing.T) {
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: "av-test-id",
		Actions: []*policy.Action{
			{
				Value: &policy.Action_Custom{
					Custom: "my custom action",
				},
			},
		},
	}

	err := getValidator().Validate(req)
	require.NoError(t, err)
}

func Test_MatchSubjectMappingsRequest_MissingSelector_Fails(t *testing.T) {
	props := []*policy.SubjectProperty{
		{
			ExternalValue: "some_value",
		},
	}
	req := &subjectmapping.MatchSubjectMappingsRequest{SubjectProperties: props}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_MatchSubjectMappingsRequest_EmptyArray_Fails(t *testing.T) {
	props := []*policy.SubjectProperty{}
	req := &subjectmapping.MatchSubjectMappingsRequest{SubjectProperties: props}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_MatchSubjectMappingsRequest_Succeeds(t *testing.T) {
	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: ".some_field",
			ExternalValue:         "some_value",
		},
	}
	req := &subjectmapping.MatchSubjectMappingsRequest{SubjectProperties: props}

	err := getValidator().Validate(req)
	require.NoError(t, err)
}
