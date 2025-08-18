package subjectmapping

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/require"
)

func Test_CreateSubjectConditionSetRequest_InvalidSubjectConditionSet_Fails(t *testing.T) {
	testCases := []struct {
		name           string
		setupRequest   func() *subjectmapping.CreateSubjectConditionSetRequest
		expectedError  string
		expectedDetail string
	}{
		// TODO: uncomment this skipped test case when protovalidate change is merged
		// {
		// 	name: "missing subject condition set",
		// 	setupRequest: func() *subjectmapping.CreateSubjectConditionSetRequest {
		// 		return &subjectmapping.CreateSubjectConditionSetRequest{}
		// 	},
		// 	expectedError: "required",
		// },
		{
			name: "empty subject sets",
			setupRequest: func() *subjectmapping.CreateSubjectConditionSetRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{}
				return &subjectmapping.CreateSubjectConditionSetRequest{
					SubjectConditionSet: conditionSet,
				}
			},
			expectedError:  errLessThanMinItems,
			expectedDetail: "subject_sets",
		},
		{
			name: "empty subject set",
			setupRequest: func() *subjectmapping.CreateSubjectConditionSetRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{{}},
				}
				return &subjectmapping.CreateSubjectConditionSetRequest{
					SubjectConditionSet: conditionSet,
				}
			},
			expectedError:  errLessThanMinItems,
			expectedDetail: "subject_sets",
		},
		{
			name: "empty condition groups",
			setupRequest: func() *subjectmapping.CreateSubjectConditionSetRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{},
						},
					},
				}
				return &subjectmapping.CreateSubjectConditionSetRequest{
					SubjectConditionSet: conditionSet,
				}
			},
			expectedError:  errLessThanMinItems,
			expectedDetail: "condition_groups",
		},
		{
			name: "empty condition group",
			setupRequest: func() *subjectmapping.CreateSubjectConditionSetRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{{}},
						},
					},
				}
				return &subjectmapping.CreateSubjectConditionSetRequest{
					SubjectConditionSet: conditionSet,
				}
			},
			expectedError:  errLessThanMinItems,
			expectedDetail: "condition_groups",
		},
		{
			name: "missing operator",
			setupRequest: func() *subjectmapping.CreateSubjectConditionSetRequest {
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
				return &subjectmapping.CreateSubjectConditionSetRequest{
					SubjectConditionSet: conditionSet,
				}
			},
			expectedError: "operator",
		},
		{
			name: "missing subject external selector value",
			setupRequest: func() *subjectmapping.CreateSubjectConditionSetRequest {
				conditionSet := &subjectmapping.SubjectConditionSetCreate{
					SubjectSets: []*policy.SubjectSet{
						{
							ConditionGroups: []*policy.ConditionGroup{
								{
									Conditions: []*policy.Condition{
										{
											Operator:              policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
											SubjectExternalValues: []string{"some_value"},
										},
									},
								},
							},
						},
					},
				}
				return &subjectmapping.CreateSubjectConditionSetRequest{
					SubjectConditionSet: conditionSet,
				}
			},
			expectedError: "subject_external_selector_value",
		},
		{
			name: "empty subject external values",
			setupRequest: func() *subjectmapping.CreateSubjectConditionSetRequest {
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
				return &subjectmapping.CreateSubjectConditionSetRequest{
					SubjectConditionSet: conditionSet,
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

			if tc.expectedDetail != "" {
				require.Contains(t, err.Error(), tc.expectedDetail)
			}
		})
	}
}

func Test_CreateSubjectConditionSetRequest_ValidSubjectConditionSet_Succeeds(t *testing.T) {
	conditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						Conditions: []*policy.Condition{
							{
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalSelectorValue: ".some_field",
								SubjectExternalValues:        []string{"some_value"},
							},
						},
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
					},
				},
			},
		},
	}
	req := &subjectmapping.CreateSubjectConditionSetRequest{
		SubjectConditionSet: conditionSet,
	}

	err := getValidator().Validate(req)
	require.NoError(t, err)
}
