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

var fakeID = "cf75540a-cd58-4c6c-a502-7108be7a6edd"

func Test_CreateSubjectMappingRequest_NilActionsArray_Fails(t *testing.T) {
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fakeID,
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_CreateSubjectMappingRequest_EmptyActionsArray_Fails(t *testing.T) {
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fakeID,
		Actions:          []*policy.Action{},
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
}

func Test_CreateSubjectMappingRequest_PopulatedArray_BadValueID_Fails(t *testing.T) {
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
	require.Error(t, err)
	require.Contains(t, err.Error(), "attribute_value_id")
	require.Contains(t, err.Error(), "[string.uuid]")
}

func Test_CreateSubjectMappingRequest_PopulatedArray_Succeeds(t *testing.T) {
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fakeID,
		Actions: []*policy.Action{
			{
				Value: &policy.Action_Custom{
					Custom: "my custom action",
				},
			},
		},
	}

	err := getValidator().Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "attribute_value_id")
	require.Contains(t, err.Error(), "[string.uuid]")
}
