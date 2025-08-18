package subjectmapping

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/require"
)

func getValidator() protovalidate.Validator {
	v, err := protovalidate.New()
	if err != nil {
		panic(err)
	}
	return v
}

const (
	errMessageUUID         = "string.uuid"
	errLessThanMinItems    = "repeated.min_items"
	errMessageOptionalUUID = "optional_uuid_format"
	fakeID                 = "cf75540a-cd58-4c6c-a502-7108be7a6edd"
)

var validActions = []*policy.Action{
	{
		Name: "action1",
	},
	{
		Name: "read",
	},
}

func Test_CreateSubjectMappingRequest_InvalidSubjectConditionSet_Fails(t *testing.T) {
	testCases := []struct {
		name           string
		setupRequest   func() *subjectmapping.CreateSubjectMappingRequest
		expectedError  string
		expectedDetail string
	}{
		{
			name: "empty subject sets",
			setupRequest: func() *subjectmapping.CreateSubjectMappingRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{}
				return &subjectmapping.CreateSubjectMappingRequest{
					AttributeValueId:       fakeID,
					NewSubjectConditionSet: conditionSet,
					Actions:                validActions,
				}
			},
			expectedError:  errLessThanMinItems,
			expectedDetail: "subject_sets",
		},
		{
			name: "empty subject set",
			setupRequest: func() *subjectmapping.CreateSubjectMappingRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{{}},
				}
				return &subjectmapping.CreateSubjectMappingRequest{
					AttributeValueId:       fakeID,
					NewSubjectConditionSet: conditionSet,
					Actions:                validActions,
				}
			},
			expectedError:  errLessThanMinItems,
			expectedDetail: "subject_sets",
		},
		{
			name: "empty condition groups",
			setupRequest: func() *subjectmapping.CreateSubjectMappingRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{},
						},
					},
				}
				return &subjectmapping.CreateSubjectMappingRequest{
					AttributeValueId:       fakeID,
					NewSubjectConditionSet: conditionSet,
					Actions:                validActions,
				}
			},
			expectedError:  errLessThanMinItems,
			expectedDetail: "condition_groups",
		},
		{
			name: "empty condition group",
			setupRequest: func() *subjectmapping.CreateSubjectMappingRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{{}},
						},
					},
				}
				return &subjectmapping.CreateSubjectMappingRequest{
					AttributeValueId:       fakeID,
					NewSubjectConditionSet: conditionSet,
					Actions:                validActions,
				}
			},
			expectedError:  errLessThanMinItems,
			expectedDetail: "condition_groups",
		},
		{
			name: "missing operator",
			setupRequest: func() *subjectmapping.CreateSubjectMappingRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{
								{
									Conditions: []*policy.Condition{
										{
											SubjectExternalSelectorValue: ".some_field",
											SubjectExternalValues:        []string{"some_value"},
										},
									},
								},
							},
						},
					},
				}
				return &subjectmapping.CreateSubjectMappingRequest{
					AttributeValueId:       fakeID,
					NewSubjectConditionSet: conditionSet,
					Actions:                validActions,
				}
			},
			expectedError: "operator",
		},
		{
			name: "missing subject external selector value",
			setupRequest: func() *subjectmapping.CreateSubjectMappingRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{
								{
									Conditions: []*policy.Condition{
										{
											Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
											SubjectExternalSelectorValue: "",
											SubjectExternalValues:        []string{"some_value"},
										},
									},
								},
							},
						},
					},
				}
				return &subjectmapping.CreateSubjectMappingRequest{
					AttributeValueId:       fakeID,
					NewSubjectConditionSet: conditionSet,
					Actions:                validActions,
				}
			},
			expectedError: "subject_external_selector_value",
		},
		{
			name: "empty subject external values",
			setupRequest: func() *subjectmapping.CreateSubjectMappingRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{
								{
									Conditions: []*policy.Condition{
										{
											Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
											SubjectExternalSelectorValue: ".some_field",
											SubjectExternalValues:        []string{},
										},
									},
								},
							},
						},
					},
				}
				return &subjectmapping.CreateSubjectMappingRequest{
					AttributeValueId:       fakeID,
					NewSubjectConditionSet: conditionSet,
					Actions:                validActions,
				}
			},
			expectedError: "subject_external_values",
		},
	}

	validator := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := tc.setupRequest()
			err := validator.Validate(request)

			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expectedError)
		})
	}
}

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

func Test_CreateSubjectMappingRequest_NoActionNameProvided_Fails(t *testing.T) {
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
}

func Test_CreateSubjectMappingRequest_PopulatedArray_BadValueID_Fails(t *testing.T) {
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: "av-test-id",
		Actions: []*policy.Action{
			{
				Name: "read",
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
				Name: "create",
			},
		},
	}
	err := getValidator().Validate(req)
	require.NoError(t, err)

	req = &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fakeID,
		Actions: []*policy.Action{
			{
				Id: fakeID,
			},
		},
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func Test_CreateSubjectMappingRequest_WithExistingSubjectConditionSetID_Succeeds(t *testing.T) {
	v := getValidator()
	req := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fakeID,
		Actions: []*policy.Action{
			{
				Name: "update",
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

	req.Actions = []*policy.Action{
		{
			Name: "read",
		},
	}
	err = v.Validate(req)
	require.NoError(t, err, "valid actions with action name")

	req.Actions = []*policy.Action{
		{
			Id: fakeID,
		},
	}
	err = v.Validate(req)
	require.NoError(t, err, "valid actions with action ID")
}

func Test_UpdateSubjectMappingRequest_Fails(t *testing.T) {
	testCases := []struct {
		name           string
		setupRequest   func() *subjectmapping.UpdateSubjectMappingRequest
		expectedError  string
		expectedDetail string
	}{
		{
			name: "missing ID",
			setupRequest: func() *subjectmapping.UpdateSubjectMappingRequest {
				return &subjectmapping.UpdateSubjectMappingRequest{}
			},
			expectedError: errMessageUUID,
		},
		{
			name: "invalid ID format",
			setupRequest: func() *subjectmapping.UpdateSubjectMappingRequest {
				return &subjectmapping.UpdateSubjectMappingRequest{
					Id: "invalid-id-format",
				}
			},
			expectedError: errMessageUUID,
		},
		{
			name: "invalid subject_condition_set_id format",
			setupRequest: func() *subjectmapping.UpdateSubjectMappingRequest {
				return &subjectmapping.UpdateSubjectMappingRequest{
					Id:                    fakeID,
					SubjectConditionSetId: "invalid-subject-condition-set-id",
				}
			},
			expectedError: errMessageOptionalUUID,
		},
		{
			name: "missing action name",
			setupRequest: func() *subjectmapping.UpdateSubjectMappingRequest {
				return &subjectmapping.UpdateSubjectMappingRequest{
					Id: fakeID,
					Actions: []*policy.Action{
						{
							Value: &policy.Action_Custom{
								Custom: "my custom action",
							},
						},
					},
				}
			},
			expectedError: "action_name_or_id_not_empty",
		},
	}

	validator := getValidator()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request := tc.setupRequest()
			err := validator.Validate(request)

			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expectedError)
			if tc.expectedDetail != "" {
				require.Contains(t, err.Error(), tc.expectedDetail)
			}
		})
	}
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
