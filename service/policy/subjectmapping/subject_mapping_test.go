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

const (
	errMessageUUID         = "string.uuid"
	errMessageOptionalUUID = "optional_uuid_format"
	fakeID                 = "cf75540a-cd58-4c6c-a502-7108be7a6edd"
)

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
	require.Contains(t, err.Error(), errMessageUUID)
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
	require.NoError(t, err)
}

func Test_CreateSubjectMappingRequest_WithExistingSubjectConditionSetID_Succeeds(t *testing.T) {
	v := getValidator()
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fakeID,
		Actions: []*policy.Action{
			{
				Value: &policy.Action_Standard{
					Standard: policy.Action_STANDARD_ACTION_DECRYPT,
				},
			},
		},
		ExistingSubjectConditionSetId: fakeID,
	}

	err := v.Validate(req)
	require.NoError(t, err)

	req.ExistingSubjectConditionSetId = "bad-scs-id"
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOptionalUUID)
}

func Test_UpdateSubjectMappingRequest_Succeeds(t *testing.T) {
	v := getValidator()
	req := &subjectmapping.UpdateSubjectMappingRequest{}

	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageUUID)

	req.Id = fakeID
	err = v.Validate(req)
	require.NoError(t, err, "valid uuid format for ID")

	req.SubjectConditionSetId = "bad-id"
	err = v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), errMessageOptionalUUID)

	req.SubjectConditionSetId = fakeID
	err = v.Validate(req)
	require.NoError(t, err, "valid uuid format for subject_condition_set_id")
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

func Test_MatchSubjectMappingsRequest_EmptyExternalValue_Succeeds(t *testing.T) {
	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: ".some_field",
		},
	}
	req := &subjectmapping.MatchSubjectMappingsRequest{SubjectProperties: props}

	err := getValidator().Validate(req)
	require.NoError(t, err)
}
