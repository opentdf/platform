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
					NamespaceId:         fakeID,
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
					NamespaceId:         fakeID,
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
					NamespaceId:         fakeID,
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
					NamespaceId:         fakeID,
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
					NamespaceId:         fakeID,
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
					NamespaceId:         fakeID,
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
					NamespaceId:         fakeID,
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
		NamespaceId:         fakeID,
	}

	err := getValidator().Validate(req)
	require.NoError(t, err)

	req = &subjectmapping.CreateSubjectConditionSetRequest{
		SubjectConditionSet: conditionSet,
		NamespaceFqn:        validNamespaceFQN,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)

	req = &subjectmapping.CreateSubjectConditionSetRequest{
		SubjectConditionSet: conditionSet,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func Test_CreateSubjectConditionSetRequest_MissingNamespace_Succeeds(t *testing.T) {
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

	req = &subjectmapping.CreateSubjectConditionSetRequest{
		SubjectConditionSet: conditionSet,
		NamespaceFqn:        validNamespaceFQN,
	}
	err = getValidator().Validate(req)
	require.NoError(t, err)
}

func Test_CreateSubjectConditionSetRequest_InvalidNamespace_Fails(t *testing.T) {
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

	testCases := []struct {
		name          string
		req           *subjectmapping.CreateSubjectConditionSetRequest
		expectedError string
	}{
		{
			name: "invalid namespace id",
			req: &subjectmapping.CreateSubjectConditionSetRequest{
				SubjectConditionSet: conditionSet,
				NamespaceId:         "bad-namespace-id",
			},
			expectedError: errMessageUUID,
		},
		{
			name: "invalid namespace fqn",
			req: &subjectmapping.CreateSubjectConditionSetRequest{
				SubjectConditionSet: conditionSet,
				NamespaceFqn:        "not-a-uri",
			},
			expectedError: errMessageURI,
		},
		{
			name: "both namespace id and fqn",
			req: &subjectmapping.CreateSubjectConditionSetRequest{
				SubjectConditionSet: conditionSet,
				NamespaceId:         fakeID,
				NamespaceFqn:        validNamespaceFQN,
			},
			expectedError: errMessageOneof,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expectedError)
		})
	}
}

func Test_ListSubjectConditionSetsRequest_Succeeds(t *testing.T) {
	testCases := []struct {
		name string
		req  *subjectmapping.ListSubjectConditionSetsRequest
	}{
		{
			name: "no filters",
			req:  &subjectmapping.ListSubjectConditionSetsRequest{},
		},
		{
			name: "namespace id only",
			req: &subjectmapping.ListSubjectConditionSetsRequest{
				NamespaceId: fakeID,
			},
		},
		{
			name: "namespace fqn only",
			req: &subjectmapping.ListSubjectConditionSetsRequest{
				NamespaceFqn: validNamespaceFQN,
			},
		},
		{
			name: "pagination only",
			req: &subjectmapping.ListSubjectConditionSetsRequest{
				Pagination: &policy.PageRequest{
					Limit:  10,
					Offset: 5,
				},
			},
		},
		{
			name: "namespace filter with pagination",
			req: &subjectmapping.ListSubjectConditionSetsRequest{
				NamespaceFqn: validNamespaceFQN,
				Pagination: &policy.PageRequest{
					Limit: 20,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			require.NoError(t, err)
		})
	}
}

func Test_ListSubjectConditionSetsRequest_Fails(t *testing.T) {
	testCases := []struct {
		name          string
		req           *subjectmapping.ListSubjectConditionSetsRequest
		expectedError string
	}{
		{
			name: "invalid namespace id",
			req: &subjectmapping.ListSubjectConditionSetsRequest{
				NamespaceId: "bad-namespace-id",
			},
			expectedError: errMessageUUID,
		},
		{
			name: "invalid namespace fqn",
			req: &subjectmapping.ListSubjectConditionSetsRequest{
				NamespaceFqn: "not-a-uri",
			},
			expectedError: errMessageURI,
		},
		{
			name: "both namespace id and fqn",
			req: &subjectmapping.ListSubjectConditionSetsRequest{
				NamespaceId:  fakeID,
				NamespaceFqn: validNamespaceFQN,
			},
			expectedError: errMessageOneof,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := getValidator().Validate(tc.req)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.expectedError)
		})
	}
}

func Test_ListSubjectConditionSetsRequest_Sort(t *testing.T) {
	v := getValidator()

	// no sort — valid
	req := &subjectmapping.ListSubjectConditionSetsRequest{}
	require.NoError(t, v.Validate(req))

	// one sort item — valid
	req = &subjectmapping.ListSubjectConditionSetsRequest{
		Sort: []*subjectmapping.SubjectConditionSetsSort{
			{
				Field:     subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_CREATED_AT,
				Direction: policy.SortDirection_SORT_DIRECTION_ASC,
			},
		},
	}
	require.NoError(t, v.Validate(req))

	// two sort items — exceeds max_items = 1
	req = &subjectmapping.ListSubjectConditionSetsRequest{
		Sort: []*subjectmapping.SubjectConditionSetsSort{
			{
				Field:     subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_CREATED_AT,
				Direction: policy.SortDirection_SORT_DIRECTION_ASC,
			},
			{
				Field:     subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UPDATED_AT,
				Direction: policy.SortDirection_SORT_DIRECTION_DESC,
			},
		},
	}
	err := v.Validate(req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sort")
}
