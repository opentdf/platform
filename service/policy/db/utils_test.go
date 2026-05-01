package db

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetListLimit(t *testing.T) {
	var defaultListLimit int32 = 1000
	cases := []struct {
		limit    int32
		expected int32
	}{
		{
			0,
			1000,
		},
		{
			1,
			1,
		},
		{
			10000,
			10000,
		},
	}

	for _, test := range cases {
		result := getListLimit(test.limit, defaultListLimit)
		assert.Equal(t, test.expected, result)
	}
}

func Test_GetNextOffset(t *testing.T) {
	var defaultTestListLimit int32 = 250
	cases := []struct {
		currOffset int32
		limit      int32
		total      int32
		expected   int32
		scenario   string
	}{
		{
			currOffset: 0,
			limit:      defaultTestListLimit,
			total:      1000,
			expected:   defaultTestListLimit,
			scenario:   "defaulted limit with many remaining",
		},
		{
			currOffset: 100,
			limit:      100,
			total:      1000,
			expected:   200,
			scenario:   "custom limit with many remaining",
		},
		{
			currOffset: 100,
			limit:      100,
			total:      200,
			expected:   0,
			scenario:   "custom limit with none remaining",
		},
		{
			currOffset: 100,
			limit:      defaultTestListLimit,
			total:      200,
			expected:   0,
			scenario:   "default limit with none remaining",
		},
		{
			currOffset: 350 - defaultTestListLimit - 1,
			limit:      defaultTestListLimit,
			total:      350,
			expected:   349,
			scenario:   "default limit with exactly one remaining",
		},
		{
			currOffset: 1000 - 500 - 1,
			limit:      500,
			total:      1000,
			expected:   1000 - 1,
			scenario:   "custom limit with exactly one remaining",
		},
	}

	for _, test := range cases {
		result := getNextOffset(test.currOffset, test.limit, test.total)
		assert.Equal(t, test.expected, result, test.scenario)
	}
}

func Test_GetNamespacesSortParams(t *testing.T) {
	cases := []struct {
		name          string
		sort          []*namespaces.NamespacesSort
		expectedField string
		expectedDir   string
	}{
		{
			name:          "nil sort returns empty strings",
			sort:          nil,
			expectedField: "",
			expectedDir:   "",
		},
		{
			name:          "empty slice returns empty strings",
			sort:          []*namespaces.NamespacesSort{},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "UNSPECIFIED field with ASC preserves direction",
			sort: []*namespaces.NamespacesSort{
				{Field: namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "",
			expectedDir:   "ASC",
		},
		{
			name: "UNSPECIFIED field with DESC preserves direction",
			sort: []*namespaces.NamespacesSort{
				{Field: namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "",
			expectedDir:   "DESC",
		},
		{
			name: "both UNSPECIFIED returns empty strings",
			sort: []*namespaces.NamespacesSort{
				{Field: namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "NAME with ASC",
			sort: []*namespaces.NamespacesSort{
				{Field: namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "name",
			expectedDir:   "ASC",
		},
		{
			name: "NAME with DESC",
			sort: []*namespaces.NamespacesSort{
				{Field: namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "name",
			expectedDir:   "DESC",
		},
		{
			name: "FQN with unspecified direction returns empty direction",
			sort: []*namespaces.NamespacesSort{
				{Field: namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_FQN},
			},
			expectedField: "fqn",
			expectedDir:   "",
		},
		{
			name: "CREATED_AT with ASC",
			sort: []*namespaces.NamespacesSort{
				{Field: namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "created_at",
			expectedDir:   "ASC",
		},
		{
			name: "UPDATED_AT with DESC",
			sort: []*namespaces.NamespacesSort{
				{Field: namespaces.SortNamespacesType_SORT_NAMESPACES_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "updated_at",
			expectedDir:   "DESC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field, dir := GetNamespacesSortParams(tc.sort)
			assert.Equal(t, tc.expectedField, field)
			assert.Equal(t, tc.expectedDir, dir)
		})
	}
}

func Test_GetSubjectMappingsSortParams(t *testing.T) {
	cases := []struct {
		name          string
		sort          []*subjectmapping.SubjectMappingsSort
		expectedField string
		expectedDir   string
	}{
		{
			name:          "nil sort returns empty strings",
			sort:          nil,
			expectedField: "",
			expectedDir:   "",
		},
		{
			name:          "empty slice returns empty strings",
			sort:          []*subjectmapping.SubjectMappingsSort{},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "UNSPECIFIED field with ASC preserves direction",
			sort: []*subjectmapping.SubjectMappingsSort{
				{Field: subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "",
			expectedDir:   "ASC",
		},
		{
			name: "UNSPECIFIED field with DESC preserves direction",
			sort: []*subjectmapping.SubjectMappingsSort{
				{Field: subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "",
			expectedDir:   "DESC",
		},
		{
			name: "both UNSPECIFIED returns empty strings",
			sort: []*subjectmapping.SubjectMappingsSort{
				{Field: subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "CREATED_AT with ASC",
			sort: []*subjectmapping.SubjectMappingsSort{
				{Field: subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "created_at",
			expectedDir:   "ASC",
		},
		{
			name: "CREATED_AT with DESC",
			sort: []*subjectmapping.SubjectMappingsSort{
				{Field: subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "created_at",
			expectedDir:   "DESC",
		},
		{
			name: "CREATED_AT with unspecified direction returns empty direction",
			sort: []*subjectmapping.SubjectMappingsSort{
				{Field: subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_CREATED_AT},
			},
			expectedField: "created_at",
			expectedDir:   "",
		},
		{
			name: "UPDATED_AT with ASC",
			sort: []*subjectmapping.SubjectMappingsSort{
				{Field: subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "updated_at",
			expectedDir:   "ASC",
		},
		{
			name: "UPDATED_AT with DESC",
			sort: []*subjectmapping.SubjectMappingsSort{
				{Field: subjectmapping.SortSubjectMappingsType_SORT_SUBJECT_MAPPINGS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "updated_at",
			expectedDir:   "DESC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field, dir := GetSubjectMappingsSortParams(tc.sort)
			assert.Equal(t, tc.expectedField, field)
			assert.Equal(t, tc.expectedDir, dir)
		})
	}
}

func Test_UnmarshalAllActionsProto(t *testing.T) {
	tests := []struct {
		name              string
		stdActionsJSON    []byte
		customActionsJSON []byte
		wantLen           int
	}{
		{
			name:              "Only Standard Actions",
			stdActionsJSON:    []byte(`[{"id":"std1", "name":"Standard One"}, {"id":"std2", "name":"Standard Two"}]`),
			customActionsJSON: []byte(`[]`),
			wantLen:           2,
		},
		{
			name:              "Only Custom Actions",
			stdActionsJSON:    []byte(`[]`),
			customActionsJSON: []byte(`[{"id":"custom1", "name":"Custom One"}, {"id":"custom2", "name":"Custom Two"}]`),
			wantLen:           2,
		},
		{
			name:              "Both Standard and Custom Actions",
			stdActionsJSON:    []byte(`[{"id":"std1", "name":"Standard One"}, {"id":"std2", "name":"Standard Two"}]`),
			customActionsJSON: []byte(`[{"id":"custom1", "name":"Custom One"}, {"id":"custom2", "name":"Custom Two"}]`),
			wantLen:           4,
		},
		{
			name:              "Empty Actions",
			stdActionsJSON:    []byte(`[]`),
			customActionsJSON: []byte(`[]`),
			wantLen:           0,
		},
		{
			name:              "Nil Actions",
			stdActionsJSON:    nil,
			customActionsJSON: nil,
			wantLen:           0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions := []*policy.Action{}

			err := unmarshalAllActionsProto(tt.stdActionsJSON, tt.customActionsJSON, &actions)
			if err != nil {
				t.Errorf("unmarshalAllActionsProto() unexpected error = %v", err)
			}

			if len(actions) != tt.wantLen {
				t.Errorf("unmarshalAllActionsProto() len(actions) = %v, wantLen %v", len(actions), tt.wantLen)
			}
		})
	}
}

func Test_UnmarshalPrivatePublicKeyContext(t *testing.T) {
	tests := []struct {
		name    string
		pubCtx  []byte
		privCtx []byte
		wantErr bool
	}{
		{
			name:    "Successful unmarshal of both public and private keys",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Successful unmarshal of only public key",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{}`),
			wantErr: false,
		},
		{
			name:    "Successful unmarshal of only private key",
			pubCtx:  []byte(`{}`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Invalid public key JSON",
			pubCtx:  []byte(`{"pem": "invalid`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: true,
		},
		{
			name:    "Invalid private key JSON",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{"keyId": "invalid`),
			wantErr: true,
		},
		{
			name:    "Empty public context",
			pubCtx:  []byte(`{}`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Empty private context",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{}`),
			wantErr: false,
		},
		{
			name:    "Nil public and private key pointers",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Nil public key pointer",
			pubCtx:  nil,
			privCtx: []byte(`{"keyId": "PRIVATE_KEY_ID", "wrappedKey": "WRAPPED_PRIVATE_KEY"}`),
			wantErr: false,
		},
		{
			name:    "Nil private key pointer",
			pubCtx:  []byte(`{"pem": "PUBLIC_KEY_PEM"}`),
			privCtx: nil,
			wantErr: false,
		},
		{
			name:    "Nil public and private key pointers",
			pubCtx:  nil,
			privCtx: nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKeyCtx, privKeyCtx, err := unmarshalPrivatePublicKeyContext(tt.pubCtx, tt.privCtx)

			if tt.wantErr {
				require.Error(t, err)
				return // Exit early if an error was expected
			}

			// If we reach here, no error was expected
			require.NoError(t, err)

			if tt.pubCtx == nil {
				assert.Nil(t, pubKeyCtx, "pubKeyCtx should be nil when tt.pubCtx is nil for test: %s", tt.name)
			} else {
				assert.NotNil(t, pubKeyCtx, "pubKeyCtx should not be nil when tt.pubCtx is not nil for test: %s", tt.name)
				// Only check GetPem if input tt.pubCtx was not empty and not an empty JSON object,
				// implying it was intended to contain the "PUBLIC_KEY_PEM".
				if len(tt.pubCtx) > 0 && string(tt.pubCtx) != `{}` {
					assert.Equal(t, "PUBLIC_KEY_PEM", pubKeyCtx.GetPem(), "Mismatch in pubKeyCtx.GetPem() for test: %s", tt.name)
				}
			}

			if tt.privCtx == nil {
				assert.Nil(t, privKeyCtx, "privKeyCtx should be nil when tt.privCtx is nil for test: %s", tt.name)
			} else {
				assert.NotNil(t, privKeyCtx, "privKeyCtx should not be nil when tt.privCtx is not nil for test: %s", tt.name)
				// Only check GetKeyId and GetWrappedKey if input tt.privCtx was not empty and not an empty JSON object,
				// implying it was intended to contain the "PRIVATE_KEY_ID" and "WRAPPED_PRIVATE_KEY".
				if len(tt.privCtx) > 0 && string(tt.privCtx) != `{}` {
					assert.Equal(t, "PRIVATE_KEY_ID", privKeyCtx.GetKeyId(), "Mismatch in privKeyCtx.GetKeyId() for test: %s", tt.name)
					assert.Equal(t, "WRAPPED_PRIVATE_KEY", privKeyCtx.GetWrappedKey(), "Mismatch in privKeyCtx.GetWrappedKey() for test: %s", tt.name)
				}
			}
		})
	}
}

func Test_GetAttributesSortParams(t *testing.T) {
	cases := []struct {
		name          string
		sort          []*attributes.AttributesSort
		expectedField string
		expectedDir   string
	}{
		{
			name:          "nil sort returns empty strings",
			sort:          nil,
			expectedField: "",
			expectedDir:   "",
		},
		{
			name:          "empty slice returns empty strings",
			sort:          []*attributes.AttributesSort{},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "UNSPECIFIED field with ASC preserves direction",
			sort: []*attributes.AttributesSort{
				{Field: attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "",
			expectedDir:   "ASC",
		},
		{
			name: "UNSPECIFIED field with DESC preserves direction",
			sort: []*attributes.AttributesSort{
				{Field: attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "",
			expectedDir:   "DESC",
		},
		{
			name: "both UNSPECIFIED returns empty strings",
			sort: []*attributes.AttributesSort{
				{Field: attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "NAME with ASC",
			sort: []*attributes.AttributesSort{
				{Field: attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "name",
			expectedDir:   "ASC",
		},
		{
			name: "NAME with DESC",
			sort: []*attributes.AttributesSort{
				{Field: attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "name",
			expectedDir:   "DESC",
		},
		{
			name: "CREATED_AT with ASC",
			sort: []*attributes.AttributesSort{
				{Field: attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "created_at",
			expectedDir:   "ASC",
		},
		{
			name: "CREATED_AT with unspecified direction returns empty direction",
			sort: []*attributes.AttributesSort{
				{Field: attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_CREATED_AT},
			},
			expectedField: "created_at",
			expectedDir:   "",
		},
		{
			name: "UPDATED_AT with DESC",
			sort: []*attributes.AttributesSort{
				{Field: attributes.SortAttributesType_SORT_ATTRIBUTES_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "updated_at",
			expectedDir:   "DESC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field, dir := GetAttributesSortParams(tc.sort)
			assert.Equal(t, tc.expectedField, field)
			assert.Equal(t, tc.expectedDir, dir)
		})
	}
}

func Test_GetSubjectConditionSetsSortParams(t *testing.T) {
	cases := []struct {
		name          string
		sort          []*subjectmapping.SubjectConditionSetsSort
		expectedField string
		expectedDir   string
	}{
		{
			name:          "nil sort returns empty strings",
			sort:          nil,
			expectedField: "",
			expectedDir:   "",
		},
		{
			name:          "empty slice returns empty strings",
			sort:          []*subjectmapping.SubjectConditionSetsSort{},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "UNSPECIFIED field with ASC preserves direction",
			sort: []*subjectmapping.SubjectConditionSetsSort{
				{Field: subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "",
			expectedDir:   "ASC",
		},
		{
			name: "UNSPECIFIED field with DESC preserves direction",
			sort: []*subjectmapping.SubjectConditionSetsSort{
				{Field: subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "",
			expectedDir:   "DESC",
		},
		{
			name: "both UNSPECIFIED returns empty strings",
			sort: []*subjectmapping.SubjectConditionSetsSort{
				{Field: subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "CREATED_AT with ASC",
			sort: []*subjectmapping.SubjectConditionSetsSort{
				{Field: subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "created_at",
			expectedDir:   "ASC",
		},
		{
			name: "CREATED_AT with DESC",
			sort: []*subjectmapping.SubjectConditionSetsSort{
				{Field: subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "created_at",
			expectedDir:   "DESC",
		},
		{
			name: "CREATED_AT with unspecified direction returns empty direction",
			sort: []*subjectmapping.SubjectConditionSetsSort{
				{Field: subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_CREATED_AT},
			},
			expectedField: "created_at",
			expectedDir:   "",
		},
		{
			name: "UPDATED_AT with DESC",
			sort: []*subjectmapping.SubjectConditionSetsSort{
				{Field: subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "updated_at",
			expectedDir:   "DESC",
		},
		{
			name: "UPDATED_AT with ASC",
			sort: []*subjectmapping.SubjectConditionSetsSort{
				{Field: subjectmapping.SortSubjectConditionSetsType_SORT_SUBJECT_CONDITION_SETS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "updated_at",
			expectedDir:   "ASC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field, dir := GetSubjectConditionSetsSortParams(tc.sort)
			assert.Equal(t, tc.expectedField, field)
			assert.Equal(t, tc.expectedDir, dir)
		})
	}
}

func Test_GetObligationsSortParams(t *testing.T) {
	cases := []struct {
		name          string
		sort          []*obligations.ObligationsSort
		expectedField string
		expectedDir   string
	}{
		{
			name:          "nil sort returns empty strings",
			sort:          nil,
			expectedField: "",
			expectedDir:   "",
		},
		{
			name:          "empty slice returns empty strings",
			sort:          []*obligations.ObligationsSort{},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "UNSPECIFIED field with ASC preserves direction",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "",
			expectedDir:   "ASC",
		},
		{
			name: "UNSPECIFIED field with DESC preserves direction",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "",
			expectedDir:   "DESC",
		},
		{
			name: "both UNSPECIFIED returns empty strings",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "NAME with ASC",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "name",
			expectedDir:   "ASC",
		},
		{
			name: "NAME with DESC",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "name",
			expectedDir:   "DESC",
		},
		{
			name: "FQN with ASC",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_FQN, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "fqn",
			expectedDir:   "ASC",
		},
		{
			name: "FQN with DESC",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_FQN, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "fqn",
			expectedDir:   "DESC",
		},
		{
			name: "FQN with unspecified direction returns empty direction",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_FQN},
			},
			expectedField: "fqn",
			expectedDir:   "",
		},
		{
			name: "CREATED_AT with ASC",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "created_at",
			expectedDir:   "ASC",
		},
		{
			name: "CREATED_AT with DESC",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "created_at",
			expectedDir:   "DESC",
		},
		{
			name: "UPDATED_AT with ASC",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "updated_at",
			expectedDir:   "ASC",
		},
		{
			name: "UPDATED_AT with DESC",
			sort: []*obligations.ObligationsSort{
				{Field: obligations.SortObligationsType_SORT_OBLIGATIONS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "updated_at",
			expectedDir:   "DESC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field, dir := GetObligationsSortParams(tc.sort)
			assert.Equal(t, tc.expectedField, field)
			assert.Equal(t, tc.expectedDir, dir)
		})
	}
}

func Test_GetKeyAccessServersSortParams(t *testing.T) {
	tests := []struct {
		name              string
		sort              []*kasregistry.KeyAccessServersSort
		expectedField     string
		expectedDirection string
	}{
		{
			name:              "nil sort returns empty strings",
			sort:              nil,
			expectedField:     "",
			expectedDirection: "",
		},
		{
			name:              "empty slice returns empty strings",
			sort:              []*kasregistry.KeyAccessServersSort{},
			expectedField:     "",
			expectedDirection: "",
		},
		{
			name: "UNSPECIFIED field with ASC preserves direction",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField:     "",
			expectedDirection: "ASC",
		},
		{
			name: "UNSPECIFIED field with DESC preserves direction",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "",
			expectedDirection: "DESC",
		},
		{
			name: "both UNSPECIFIED returns empty strings",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField:     "",
			expectedDirection: "",
		},
		{
			name: "NAME with ASC",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField:     "name",
			expectedDirection: "ASC",
		},
		{
			name: "NAME with DESC",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "name",
			expectedDirection: "DESC",
		},
		{
			name: "URI with ASC",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_URI, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField:     "uri",
			expectedDirection: "ASC",
		},
		{
			name: "URI with DESC",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_URI, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "uri",
			expectedDirection: "DESC",
		},
		{
			name: "CREATED_AT with ASC",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField:     "created_at",
			expectedDirection: "ASC",
		},
		{
			name: "CREATED_AT with DESC",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "created_at",
			expectedDirection: "DESC",
		},
		{
			name: "UPDATED_AT with DESC",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "updated_at",
			expectedDirection: "DESC",
		},
		{
			name: "UNSPECIFIED direction returns empty direction",
			sort: []*kasregistry.KeyAccessServersSort{
				{Field: kasregistry.SortKeyAccessServersType_SORT_KEY_ACCESS_SERVERS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField:     "created_at",
			expectedDirection: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			field, direction := GetKeyAccessServersSortParams(tc.sort)
			assert.Equal(t, tc.expectedField, field)
			assert.Equal(t, tc.expectedDirection, direction)
		})
	}
}

func Test_GetRegisteredResourcesSortParams(t *testing.T) {
	cases := []struct {
		name          string
		sort          []*registeredresources.RegisteredResourcesSort
		expectedField string
		expectedDir   string
	}{
		{
			name:          "nil sort returns empty strings",
			sort:          nil,
			expectedField: "",
			expectedDir:   "",
		},
		{
			name:          "empty slice returns empty strings",
			sort:          []*registeredresources.RegisteredResourcesSort{},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "UNSPECIFIED field with ASC preserves direction",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "",
			expectedDir:   "ASC",
		},
		{
			name: "UNSPECIFIED field with DESC preserves direction",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "",
			expectedDir:   "DESC",
		},
		{
			name: "both UNSPECIFIED returns empty strings",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField: "",
			expectedDir:   "",
		},
		{
			name: "NAME with ASC",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "name",
			expectedDir:   "ASC",
		},
		{
			name: "NAME with DESC",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_NAME, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "name",
			expectedDir:   "DESC",
		},
		{
			name: "NAME with unspecified direction returns empty direction",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_NAME},
			},
			expectedField: "name",
			expectedDir:   "",
		},
		{
			name: "CREATED_AT with ASC",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "created_at",
			expectedDir:   "ASC",
		},
		{
			name: "CREATED_AT with DESC",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "created_at",
			expectedDir:   "DESC",
		},
		{
			name: "UPDATED_AT with ASC",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField: "updated_at",
			expectedDir:   "ASC",
		},
		{
			name: "UPDATED_AT with DESC",
			sort: []*registeredresources.RegisteredResourcesSort{
				{Field: registeredresources.SortRegisteredResourcesType_SORT_REGISTERED_RESOURCES_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField: "updated_at",
			expectedDir:   "DESC",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			field, dir := GetRegisteredResourcesSortParams(tc.sort)
			assert.Equal(t, tc.expectedField, field)
			assert.Equal(t, tc.expectedDir, dir)
		})
	}
}

func Test_GetKasKeysSortParams(t *testing.T) {
	tests := []struct {
		name              string
		sort              []*kasregistry.KasKeysSort
		expectedField     string
		expectedDirection string
	}{
		{
			name:              "nil sort returns empty strings",
			sort:              nil,
			expectedField:     "",
			expectedDirection: "",
		},
		{
			name:              "empty slice returns empty strings",
			sort:              []*kasregistry.KasKeysSort{},
			expectedField:     "",
			expectedDirection: "",
		},
		{
			name: "UNSPECIFIED field with ASC preserves direction",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField:     "",
			expectedDirection: "ASC",
		},
		{
			name: "UNSPECIFIED field with DESC preserves direction",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "",
			expectedDirection: "DESC",
		},
		{
			name: "both UNSPECIFIED returns empty strings",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_UNSPECIFIED, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField:     "",
			expectedDirection: "",
		},
		{
			name: "KEY_ID with ASC",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_KEY_ID, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField:     "key_id",
			expectedDirection: "ASC",
		},
		{
			name: "KEY_ID with DESC",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_KEY_ID, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "key_id",
			expectedDirection: "DESC",
		},
		{
			name: "CREATED_AT with ASC",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField:     "created_at",
			expectedDirection: "ASC",
		},
		{
			name: "CREATED_AT with DESC",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_CREATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "created_at",
			expectedDirection: "DESC",
		},
		{
			name: "UPDATED_AT with ASC",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_ASC},
			},
			expectedField:     "updated_at",
			expectedDirection: "ASC",
		},
		{
			name: "UPDATED_AT with DESC",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_UPDATED_AT, Direction: policy.SortDirection_SORT_DIRECTION_DESC},
			},
			expectedField:     "updated_at",
			expectedDirection: "DESC",
		},
		{
			name: "UNSPECIFIED direction returns empty direction",
			sort: []*kasregistry.KasKeysSort{
				{Field: kasregistry.SortKasKeysType_SORT_KAS_KEYS_TYPE_KEY_ID, Direction: policy.SortDirection_SORT_DIRECTION_UNSPECIFIED},
			},
			expectedField:     "key_id",
			expectedDirection: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			field, direction := GetKasKeysSortParams(tc.sort)
			assert.Equal(t, tc.expectedField, field)
			assert.Equal(t, tc.expectedDirection, direction)
		})
	}
}
