package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

type NamespacesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

const nonExistentNamespaceID = "88888888-2222-3333-4444-999999999999"

var (
	deactivatedNsID        string
	deactivatedAttrID      string
	deactivatedAttrValueID string
	stillActiveNsID        string
	stillActiveAttributeID string
)

func (s *NamespacesSuite) SetupSuite() {
	slog.Info("setting up db.Namespaces test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_namespaces"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
	deactivatedNsID, deactivatedAttrID, deactivatedAttrValueID = setupCascadeDeactivateNamespace(s)
}

func (s *NamespacesSuite) TearDownSuite() {
	slog.Info("tearing down db.Namespaces test suite")
	s.f.TearDown()
}

func (s *NamespacesSuite) getActiveNamespaceFixtures() []fixtures.FixtureDataNamespace {
	return []fixtures.FixtureDataNamespace{
		s.f.GetNamespaceKey("example.com"),
		s.f.GetNamespaceKey("example.net"),
		s.f.GetNamespaceKey("example.org"),
	}
}

func (s *NamespacesSuite) Test_CreateNamespace() {
	testData := s.getActiveNamespaceFixtures()

	for _, ns := range testData {
		ns.Name = strings.Replace(ns.Name, "example", "test", 1)
		createdNamespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: ns.Name})
		s.Require().NoError(err)
		s.NotNil(createdNamespace)
	}

	// Creating a namespace with a name conflict should fail
	for _, ns := range testData {
		_, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: ns.Name})
		s.Require().Error(err)
		s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	}
}

func (s *NamespacesSuite) Test_CreateNamespace_NormalizeCasing() {
	name := "TeStInG-NaMeSpAcE-123.com"
	createdNamespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: name})
	s.Require().NoError(err)
	s.NotNil(createdNamespace)
	s.Equal(strings.ToLower(name), createdNamespace.GetName())

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, createdNamespace.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(strings.ToLower(name), got.GetName(), createdNamespace.GetName())
}

func (s *NamespacesSuite) Test_GetNamespace() {
	testData := s.getActiveNamespaceFixtures()

	for _, test := range testData {
		testCases := []struct {
			name           string
			input          interface{}
			identifierType string
		}{
			{
				name:           "Deprecated ID",
				input:          test.ID,
				identifierType: "Deprecated ID",
			},
			{
				name:           "New Identifier - ID",
				input:          &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: test.ID},
				identifierType: "New ID",
			},
			{
				name:           "New Identifier - FQN",
				input:          &namespaces.GetNamespaceRequest_Fqn{Fqn: test.Name},
				identifierType: "FQN",
			},
		}

		for _, tc := range testCases {
			s.Run(fmt.Sprintf("%s - %s", test.Name, tc.name), func() { // Include namespace name in test name
				gotNamespace, err := s.db.PolicyClient.GetNamespace(s.ctx, tc.input)
				s.Require().NoError(err, "Failed to get Namespace by %s: %v", tc.identifierType, tc.input)
				s.Require().NotNil(gotNamespace, "Expected non-nil Namespace for %s: %v", tc.identifierType, tc.input)

				// name retrieved by ID equal to name used to create
				s.Equal(test.Name, gotNamespace.GetName(), "Name mismatch for %s: %v", tc.identifierType, tc.input)

				metadata := gotNamespace.GetMetadata()
				s.Require().NotNil(metadata, "Metadata should not be nil for %s: %v", tc.identifierType, tc.input)
				createdAt := metadata.GetCreatedAt()
				updatedAt := metadata.GetUpdatedAt()
				s.Require().NotNil(createdAt, "CreatedAt should not be nil for %s: %v", tc.identifierType, tc.input)
				s.Require().NotNil(updatedAt, "UpdatedAt should not be nil for %s: %v", tc.identifierType, tc.input)

				s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0, "CreatedAt is invalid for %s: %v", tc.identifierType, tc.input)
				s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0, "UpdatedAt is invalid for %s: %v", tc.identifierType, tc.input)
			})
		}
	}
}

func (s *NamespacesSuite) Test_GetNamespace_NotFound() {
	testCases := []struct {
		name           string
		input          interface{} // Input to GetNamespace - could be ID string or identifier struct
		identifierType string      // For descriptive error messages
	}{
		{
			name:           "Not Found - Deprecated ID",
			input:          nonExistentNamespaceID, // Assuming nonExistentNamespaceID is defined in your test suite
			identifierType: "Deprecated ID",
		},
		{
			name:           "Not Found - New Identifier ID",
			input:          &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: nonExistentNamespaceID},
			identifierType: "New ID",
		},
		{
			name:           "Not Found - New Identifier FQN",
			input:          &namespaces.GetNamespaceRequest_Fqn{Fqn: "non-existent-namespace-fqn"}, // Example non-existent FQN
			identifierType: "FQN",
		},
		// Add more test cases here if you want to test other "not found" scenarios
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			gotNamespace, err := s.db.PolicyClient.GetNamespace(s.ctx, tc.input)
			s.Require().Error(err, "Expected error when Namespace is not found by %s: %v", tc.identifierType, tc.input)
			s.Nil(gotNamespace, "Expected nil Namespace when not found by %s: %v", tc.identifierType, tc.input)
			s.Require().ErrorIs(err, db.ErrNotFound, "Expected ErrNotFound when Namespace is not found by %s: %v", tc.identifierType, tc.input)
		})
	}
}

func (s *NamespacesSuite) Test_GetNamespace_InactiveState_Succeeds() {
	inactive := s.f.GetNamespaceKey("deactivated_ns")
	// Ensure our fixtures matches expected string enum
	s.False(inactive.Active)

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, inactive.ID)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(inactive.Name, got.GetName())
}

func (s *NamespacesSuite) Test_ListNamespaces_NoPagination_Succeeds() {
	testData := s.getActiveNamespaceFixtures()

	listNamespacesRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
	})
	s.Require().NoError(err)
	s.NotNil(listNamespacesRsp)
	listed := listNamespacesRsp.GetNamespaces()
	s.GreaterOrEqual(len(listed), len(testData))

	for _, f := range testData {
		found := false
		for _, ns := range listed {
			if ns.GetId() == f.ID {
				found = true
			}
		}
		s.True(found)
	}
}

func (s *NamespacesSuite) Test_ListNamespaces_Limit_Succeeds() {
	var limit int32 = 2
	listRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetNamespaces()
	s.Equal(len(listed), int(limit))

	for _, ns := range listed {
		s.NotEmpty(ns.GetFqn())
		s.NotEmpty(ns.GetId())
		s.NotEmpty(ns.GetName())
	}
}

func (s *NamespacesSuite) Test_ListNamespaces_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *NamespacesSuite) Test_ListNamespaces_Offset_Succeeds() {
	req := &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
	}
	// make initial list request to compare against
	listRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetNamespaces()

	// set the offset pagination
	offset := 4
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetListRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetListRsp)
	offsetListed := offsetListRsp.GetNamespaces()

	// length is reduced by the offset amount
	s.Equal(len(offsetListed), len(listed)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, ns := range offsetListed {
		s.True(proto.Equal(ns, listed[i+offset]))
	}
}

func (s *NamespacesSuite) Test_UpdateNamespace() {
	fixedLabel := "fixed label"
	updateLabel := "update label"
	updatedLabel := "true"
	newLabel := "new label"

	labels := map[string]string{
		"fixed":  fixedLabel,
		"update": updateLabel,
	}
	updateLabels := map[string]string{
		"update": updatedLabel,
		"new":    newLabel,
	}
	expectedLabels := map[string]string{
		"fixed":  fixedLabel,
		"update": updatedLabel,
		"new":    newLabel,
	}
	created, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "updating-namespace.com",
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	metadata := created.GetMetadata()

	s.Require().NoError(err)
	s.NotNil(created)

	updatedWithoutChange, err := s.db.PolicyClient.UpdateNamespace(s.ctx, created.GetId(), &namespaces.UpdateNamespaceRequest{})
	s.Require().NoError(err)
	s.NotNil(updatedWithoutChange)
	s.Equal(created.GetId(), updatedWithoutChange.GetId())

	updatedWithChange, err := s.db.PolicyClient.UpdateNamespace(s.ctx, created.GetId(), &namespaces.UpdateNamespaceRequest{
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())
	s.EqualValues(expectedLabels, updatedWithChange.GetMetadata().GetLabels())

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	updatedMetadata := got.GetMetadata()
	createdTime := metadata.GetCreatedAt().AsTime()
	updatedTime := updatedMetadata.GetUpdatedAt().AsTime()
	s.True(createdTime.Before(updatedTime))
}

func (s *NamespacesSuite) Test_UpdateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.UpdateNamespace(s.ctx, nonExistentNamespaceID, &namespaces.UpdateNamespaceRequest{
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"updated": "true"},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_DeactivateNamespace() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deactivating-namespace.com"})
	s.Require().NoError(err)
	s.NotEqual("", n)

	inactive, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(inactive)
	s.False(inactive.GetActive().GetValue())

	// Deactivated namespace should not be found on List
	listNamespacesRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
	})
	s.Require().NoError(err)
	s.NotNil(listNamespacesRsp)
	listed := listNamespacesRsp.GetNamespaces()
	for _, ns := range listed {
		s.NotEqual(n.GetId(), ns.GetId())
	}

	// inactive namespace should still be found on Get
	gotNamespace, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(gotNamespace)
	s.Equal(n.GetId(), gotNamespace.GetId())
	s.False(gotNamespace.GetActive().GetValue())
}

// reusable setup for creating a namespace -> attr -> value and then deactivating the namespace (cascades down)
func setupCascadeDeactivateNamespace(s *NamespacesSuite) (string, string, string) {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "cascading-deactivate-namespace"})
	s.Require().NoError(err)
	s.NotEqual("", n)

	// add an attribute under that namespaces
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__cascading-deactivate-attribute",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	// add a value under that attribute
	val := &attributes.CreateAttributeValueRequest{
		Value: "test__cascading-deactivate-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.Require().NoError(err)
	s.NotNil(createdVal)

	// deactivate the namespace
	deletedNs, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(deletedNs)

	return n.GetId(), createdAttr.GetId(), createdVal.GetId()
}

func (s *NamespacesSuite) Test_DeactivateNamespace_Cascades_List() {
	type test struct {
		name     string
		testFunc func(state common.ActiveStateEnum) bool
		state    common.ActiveStateEnum
		isFound  bool
	}

	listNamespaces := func(state common.ActiveStateEnum) bool {
		listNamespacesRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
			State: state,
		})
		s.Require().NoError(err)
		s.NotNil(listNamespacesRsp)

		listed := listNamespacesRsp.GetNamespaces()
		for _, ns := range listed {
			if deactivatedNsID == ns.GetId() {
				return true
			}
		}
		return false
	}

	listAttributes := func(state common.ActiveStateEnum) bool {
		listAttrsRsp, err := s.db.PolicyClient.ListAttributes(s.ctx, &attributes.ListAttributesRequest{
			State: state,
		})
		s.Require().NoError(err)
		s.NotNil(listAttrsRsp)

		listed := listAttrsRsp.GetAttributes()
		for _, a := range listed {
			if deactivatedAttrID == a.GetId() {
				return true
			}
		}
		return false
	}

	listValues := func(state common.ActiveStateEnum) bool {
		listedValsRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
			AttributeId: deactivatedAttrID,
			State:       state,
		})
		s.Require().NoError(err)
		s.NotNil(listedValsRsp)
		listed := listedValsRsp.GetValues()
		for _, v := range listed {
			if deactivatedAttrValueID == v.GetId() {
				return true
			}
		}
		return false
	}

	tests := []test{
		{
			name:     "namespace is NOT found in LIST of ACTIVE",
			testFunc: listNamespaces,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			isFound:  false,
		},
		{
			name:     "namespace is found when filtering for INACTIVE state",
			testFunc: listNamespaces,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE,
			isFound:  true,
		},
		{
			name:     "namespace is found when filtering for ANY state",
			testFunc: listNamespaces,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for INACTIVE state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for ANY state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			isFound:  true,
		},
		{
			name:     "attribute is NOT found when filtering for ACTIVE state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			isFound:  false,
		},
		{
			name:     "value is NOT found in LIST of ACTIVE",
			testFunc: listValues,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			isFound:  false,
		},
		{
			name:     "value is found when filtering for INACTIVE state",
			testFunc: listValues,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE,
			isFound:  true,
		},
		{
			name:     "value is found when filtering for ANY state",
			testFunc: listValues,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			isFound:  true,
		},
	}

	for _, tableTest := range tests {
		s.Run(tableTest.name, func() {
			found := tableTest.testFunc(tableTest.state)
			s.Equal(tableTest.isFound, found)
		})
	}
}

func (s *NamespacesSuite) Test_DeactivateNamespace_Cascades_ToAttributesAndValues_Get() {
	// ensure the namespace has state inactive
	gotNs, err := s.db.PolicyClient.GetNamespace(s.ctx, deactivatedNsID)
	s.Require().NoError(err)
	s.NotNil(gotNs)
	s.False(gotNs.GetActive().GetValue())

	// ensure the attribute has state inactive
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivatedAttrID)
	s.Require().NoError(err)
	s.NotNil(gotAttr)
	s.False(gotAttr.GetActive().GetValue())

	// ensure the value has state inactive
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, deactivatedAttrValueID)
	s.Require().NoError(err)
	s.NotNil(gotVal)
	s.False(gotVal.GetActive().GetValue())
}

func (s *NamespacesSuite) Test_DeactivateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.DeactivateNamespace(s.ctx, nonExistentNamespaceID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)

	ns, err = s.db.PolicyClient.DeactivateNamespace(s.ctx, nonExistentNamespaceID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_DeactivateNamespace_AllAttributesDeactivated() {
	// Create a namespace
	n, _ := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deactivating-namespace.com"})

	// Create an attribute under that namespace
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__deactivate-attribute",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	_, _ = s.db.PolicyClient.CreateAttribute(s.ctx, attr)

	// Deactivate the namespace
	_, _ = s.db.PolicyClient.DeactivateNamespace(s.ctx, n.GetId())

	// Get the attributes of the namespace
	attrs, _ := s.db.PolicyClient.GetAttributesByNamespace(s.ctx, n.GetId())

	// Check if all attributes are deactivated
	for _, attr := range attrs {
		s.False(attr.GetActive().GetValue())
	}
}

func (s *NamespacesSuite) Test_UnsafeDeleteNamespace_Cascades() {
	// create namespace, with an attribute and values
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deleting-namespace.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	attr := &attributes.CreateAttributeRequest{
		Name:        "test__deleting-attribute",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	val := &attributes.CreateAttributeValueRequest{
		Value: "test__deleting-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.Require().NoError(err)
	s.NotNil(createdVal)

	val = &attributes.CreateAttributeValueRequest{
		Value: "test__deleting-value-2",
	}
	createdVal2, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.Require().NoError(err)
	s.NotNil(createdVal2)

	existing, _ := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())

	// delete the namespace
	deleted, err := s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, existing, existing.GetFqn())
	s.Require().NoError(err)
	s.NotNil(deleted)

	// Deleted namespace should not be found on GET
	ns, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)

	// Deleted attribute should not be found on GET
	a, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(a)

	// Deleted values should not be found on GET
	v, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdVal.GetId())
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(v)
	v, err = s.db.PolicyClient.GetAttributeValue(s.ctx, createdVal2.GetId())
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(v)
}

func (s *NamespacesSuite) Test_UnsafeDeleteNamespace_ShouldBeAbleToRecreateDeletedNamespace() {
	// create namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deleting-namespace.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	got, _ := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())

	// delete the namespace
	_, err = s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, got, got.GetFqn())
	s.Require().NoError(err)

	// create the namespace again
	n, err = s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deleting-namespace.com"})
	s.Require().NoError(err)
	s.NotNil(n)
}

func (s *NamespacesSuite) Test_UnsafeDeleteNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, &policy.Namespace{}, "does.not.exist")
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)

	created, _ := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "deletingns.com"})
	s.NotNil(created)
	got, _ := s.db.PolicyClient.GetNamespace(s.ctx, created.GetId())
	s.NotNil(got)
	s.NotEqual("", got.GetFqn())

	ns, err = s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, got, "https://bad.fqn")
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_UnsafeReactivateNamespace_SetsActiveStatusOfNamespace() {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "reactivating-namespace.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	// deactivate the namespace
	_, err = s.db.PolicyClient.DeactivateNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)

	// test that it's deactivated
	deactivated, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivated)
	s.False(deactivated.GetActive().GetValue())

	// reactivate the namespace
	reactivated, err := s.db.PolicyClient.UnsafeReactivateNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(reactivated)

	// test that it's active
	active, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(active)
	s.True(active.GetActive().GetValue())

	// test that the namespace is found in the list of active namespaces
	listNamespacesRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
	})
	s.Require().NoError(err)
	s.NotNil(listNamespacesRsp)
	listed := listNamespacesRsp.GetNamespaces()
	found := false
	for _, ns := range listed {
		if n.GetId() == ns.GetId() {
			found = true
			break
		}
	}
	s.True(found)

	// test that the namespace is not found in the list of inactive namespaces
	listNamespacesRsp, err = s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE,
	})
	s.Require().NoError(err)
	s.NotNil(listNamespacesRsp)
	listed = listNamespacesRsp.GetNamespaces()
	found = false
	for _, ns := range listed {
		if n.GetId() == ns.GetId() {
			found = true
			break
		}
	}
	s.False(found)
}

func (s *NamespacesSuite) Test_UnsafeReactivateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.UnsafeReactivateNamespace(s.ctx, nonExistentNamespaceID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)

	ns, err = s.db.PolicyClient.UnsafeReactivateNamespace(s.ctx, nonExistentNamespaceID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_UnsafeReactivateNamespace_ShouldNotReactivateChildren() {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "reactivating-ns.io"})
	s.Require().NoError(err)
	s.NotNil(n)

	// create an attribute definition
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "reactivating-attr",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)
	s.NotNil(attr)

	// create a value for the attribute definition
	val, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{
		Value: "reactivating-val",
	})
	s.Require().NoError(err)
	s.NotNil(val)

	// deactivate the namespace
	_, err = s.db.PolicyClient.DeactivateNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)

	// ensure all are inactive
	deactivatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivatedNs)
	s.False(deactivatedNs.GetActive().GetValue())

	deactivatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivatedAttr)
	s.False(deactivatedAttr.GetActive().GetValue())

	deactivatedVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, val.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivatedVal)
	s.False(deactivatedVal.GetActive().GetValue())

	// reactivate the namespace
	_, err = s.db.PolicyClient.UnsafeReactivateNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)

	// ensure the namespace is active
	reactivatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(reactivatedNs)
	s.True(reactivatedNs.GetActive().GetValue())

	// ensure the attribute definition is still inactive
	reactivatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	s.NotNil(reactivatedAttr)
	s.False(reactivatedAttr.GetActive().GetValue())

	// ensure the values are still inactive
	reactivatedVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, val.GetId())
	s.Require().NoError(err)
	s.NotNil(reactivatedVal)
	s.False(reactivatedVal.GetActive().GetValue())
}

func (s *NamespacesSuite) Test_UnsafeUpdateNamespace() {
	name := "unsafe.gov"
	after := "hello.world"
	created, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: name})
	s.Require().NoError(err)
	s.NotNil(created)

	updated, err := s.db.PolicyClient.UnsafeUpdateNamespace(s.ctx, created.GetId(), after)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())
	s.Equal(after, updated.GetName())

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("https://"+after, got.GetFqn())
	s.True(got.GetActive().GetValue())
	createdTime := created.GetMetadata().GetCreatedAt().AsTime()
	updatedTime := got.GetMetadata().GetUpdatedAt().AsTime()
	s.True(createdTime.Before(updatedTime))

	// should be able to create original name after unsafely updating
	recreated, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: name})
	s.Require().NoError(err)
	s.NotNil(recreated)
	s.NotEqual(created.GetId(), recreated.GetId())
}

// validate a namespace with a definition and values are all lookupable by fqn
func (s *NamespacesSuite) Test_UnsafeUpdateNamespace_CascadesInFqns() {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "updating-namespace.io"})
	s.Require().NoError(err)
	s.NotNil(n)

	// create an attribute under that namespace
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__updating-attr",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"test_val1"},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
	createdAttr, _ = s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	createdVal := createdAttr.GetValues()[0]

	// update the namespace
	updated, err := s.db.PolicyClient.UnsafeUpdateNamespace(s.ctx, n.GetId(), "updated.ca")
	s.Require().NoError(err)
	s.NotNil(updated)

	// ensure the namespace has the proper fqn
	gotNs, err := s.db.PolicyClient.GetNamespace(s.ctx, updated.GetId())
	s.Require().NoError(err)
	s.NotNil(gotNs)
	s.Equal("https://updated.ca", gotNs.GetFqn())

	// ensure the attribute has the proper fqn
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(gotAttr)
	s.Equal("https://updated.ca/attr/test__updating-attr", gotAttr.GetFqn())

	// ensure the value has the proper fqn
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdVal.GetId())
	s.Require().NoError(err)
	s.NotNil(gotVal)
	s.Equal("https://updated.ca/attr/test__updating-attr/value/test_val1", gotVal.GetFqn())
}

func (s *NamespacesSuite) Test_UnsafeUpdateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.UnsafeUpdateNamespace(s.ctx, nonExistentNamespaceID, "does.not.exist")
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_UnsafeUpdateNamespace_NormalizeCasing() {
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "TeStInG-XYZ.com"})
	s.Require().NoError(err)
	s.NotNil(ns)

	got, _ := s.db.PolicyClient.GetNamespace(s.ctx, ns.GetId())
	s.NotNil(got)
	s.Equal("testing-xyz.com", got.GetName())

	updated, err := s.db.PolicyClient.UnsafeUpdateNamespace(s.ctx, ns.GetId(), "HELLOWORLD.COM")
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal("helloworld.com", updated.GetName())

	got, _ = s.db.PolicyClient.GetNamespace(s.ctx, ns.GetId())
	s.NotNil(got)
	s.Equal("helloworld.com", got.GetName())
	s.Contains(got.GetFqn(), "helloworld.com")
	s.Equal("https://helloworld.com", got.GetFqn())
}

/*
	Key Access Server Grant Assignments (KAS Grants)
*/

func (s *NamespacesSuite) Test_AssignKASGrant() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "kas-namespace.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	// test no grants on the namespace
	got, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())

	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "kas.uri/ns",
		PublicKey: pubKey,
		Name:      "kas-name-ns",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(kas)

	// assign a grant
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       n.GetId(),
		KeyAccessServerId: kas.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	// get the namespace and verify the grant is present
	got, err = s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetGrants(), 1)
	s.Equal(kas.GetId(), got.GetGrants()[0].GetId())
	s.Equal(kasRegistry.GetName(), got.GetGrants()[0].GetName())
}

func (s *NamespacesSuite) Test_AssignKASGrant_FailsInvalidIds() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "kas-failure-namespace.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://testingassignmentfailure.com/key",
		},
	}
	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "https://testingassignmentfailure.com",
		PublicKey: pubKey,
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(kas)

	// ns doesn't exist
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       nonExistentNamespaceID,
		KeyAccessServerId: kas.GetId(),
	})
	s.Nil(grant)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)

	// kas doesn't exist
	grant, err = s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       n.GetId(),
		KeyAccessServerId: nonExistentKasRegistryID,
	})
	s.Nil(grant)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *NamespacesSuite) Test_AssignKASGrant_FailsAlreadyAssigned() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "kas-conflict.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "kas.conflict/ns",
		PublicKey: pubKey,
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(kas)

	// assign a grant
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       n.GetId(),
		KeyAccessServerId: kas.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	// assign again
	grant, err = s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       n.GetId(),
		KeyAccessServerId: kas.GetId(),
	})
	s.Nil(grant)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
}

func (s *NamespacesSuite) Test_RemoveKASGrant() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "kas-removal-namespace.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "kas.uri/removal",
		PublicKey: pubKey,
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(kas)

	// verify namespace has no grants
	got, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())

	granted := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       n.GetId(),
		KeyAccessServerId: kas.GetId(),
	}
	// grant kas to namespace
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, granted)
	s.Require().NoError(err)
	s.NotNil(grant)

	// verify namespace has grant
	got, err = s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetGrants(), 1)
	s.Equal(kas.GetId(), got.GetGrants()[0].GetId())

	// remove grant
	removed, err := s.db.PolicyClient.RemoveKeyAccessServerFromNamespace(s.ctx, granted)
	s.Require().NoError(err)
	s.NotNil(removed)
	s.Equal(granted.GetKeyAccessServerId(), removed.GetKeyAccessServerId())
	s.Equal(granted.GetNamespaceId(), removed.GetNamespaceId())

	// verify namespace has no grants
	got, err = s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())
}

func (s *NamespacesSuite) Test_RemoveKASGrant_FailsInvalidIds() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "kas-failure-namespace-remove.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://testingremovalfailure.com/key",
		},
	}
	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "https://testingremovalfailure.com",
		PublicKey: pubKey,
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(kas)

	// ns doesn't exist
	grant, err := s.db.PolicyClient.RemoveKeyAccessServerFromNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       nonExistentNamespaceID,
		KeyAccessServerId: kas.GetId(),
	})
	s.Nil(grant)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)

	// kas doesn't exist
	grant, err = s.db.PolicyClient.RemoveKeyAccessServerFromNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       n.GetId(),
		KeyAccessServerId: nonExistentKasRegistryID,
	})
	s.Nil(grant)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *NamespacesSuite) Test_RemoveKASGrant_FailsAlreadyRemoved() {
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "kas-conflict-removal.com"})
	s.Require().NoError(err)
	s.NotNil(n)

	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "kas.conflictremoval/ns",
		PublicKey: pubKey,
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(kas)

	granted := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       n.GetId(),
		KeyAccessServerId: kas.GetId(),
	}
	// assign a grant
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, granted)
	s.Require().NoError(err)
	s.NotNil(grant)

	// remove once
	grant, err = s.db.PolicyClient.RemoveKeyAccessServerFromNamespace(s.ctx, granted)
	s.NotNil(grant)
	s.Require().NoError(err)

	// remove again
	grant, err = s.db.PolicyClient.RemoveKeyAccessServerFromNamespace(s.ctx, granted)
	s.Nil(grant)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func TestNamespacesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping namespaces integration tests")
	}
	suite.Run(t, new(NamespacesSuite))
}
