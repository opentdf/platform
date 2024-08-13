package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
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
		gotNamespace, err := s.db.PolicyClient.GetNamespace(s.ctx, test.ID)
		s.Require().NoError(err)
		s.NotNil(gotNamespace)
		// name retrieved by ID equal to name used to create
		s.Equal(test.Name, gotNamespace.GetName())
		metadata := gotNamespace.GetMetadata()
		createdAt := metadata.GetCreatedAt()
		updatedAt := metadata.GetUpdatedAt()
		s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0)
		s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0)
	}

	// Getting a namespace with an nonExistent id should fail
	_, err := s.db.PolicyClient.GetNamespace(s.ctx, nonExistentNamespaceID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
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

func (s *NamespacesSuite) Test_GetNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.PolicyClient.GetNamespace(s.ctx, nonExistentNamespaceID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(ns)
}

func (s *NamespacesSuite) Test_ListNamespaces() {
	testData := s.getActiveNamespaceFixtures()

	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	s.Require().NoError(err)
	s.NotNil(gotNamespaces)
	s.GreaterOrEqual(len(gotNamespaces), len(testData))
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
	start := time.Now().Add(-time.Second)
	created, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "updating-namespace.com",
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	end := time.Now().Add(time.Second)
	metadata := created.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.True(createdAt.AsTime().After(start))
	s.True(createdAt.AsTime().Before(end))

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

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	s.True(got.GetMetadata().GetUpdatedAt().AsTime().After(updatedAt.AsTime()))
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

	// Deactivated namespace should not be found on List
	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	s.Require().NoError(err)
	s.NotNil(gotNamespaces)
	for _, ns := range gotNamespaces {
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
		testFunc func(state string) bool
		state    string
		isFound  bool
	}

	listNamespaces := func(state string) bool {
		listedNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, state)
		s.Require().NoError(err)
		s.NotNil(listedNamespaces)
		for _, ns := range listedNamespaces {
			if deactivatedNsID == ns.GetId() {
				return true
			}
		}
		return false
	}

	listAttributes := func(state string) bool {
		listedAttrs, err := s.db.PolicyClient.ListAllAttributes(s.ctx, state, "")
		s.Require().NoError(err)
		s.NotNil(listedAttrs)
		for _, a := range listedAttrs {
			if deactivatedAttrID == a.GetId() {
				return true
			}
		}
		return false
	}

	listValues := func(state string) bool {
		listedVals, err := s.db.PolicyClient.ListAttributeValues(s.ctx, deactivatedAttrID, state)
		s.Require().NoError(err)
		s.NotNil(listedVals)
		for _, v := range listedVals {
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
			state:    policydb.StateActive,
			isFound:  false,
		},
		{
			name:     "namespace is found when filtering for INACTIVE state",
			testFunc: listNamespaces,
			state:    policydb.StateInactive,
			isFound:  true,
		},
		{
			name:     "namespace is found when filtering for ANY state",
			testFunc: listNamespaces,
			state:    policydb.StateAny,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for INACTIVE state",
			testFunc: listAttributes,
			state:    policydb.StateInactive,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for ANY state",
			testFunc: listAttributes,
			state:    policydb.StateAny,
			isFound:  true,
		},
		{
			name:     "attribute is NOT found when filtering for ACTIVE state",
			testFunc: listAttributes,
			state:    policydb.StateActive,
			isFound:  false,
		},
		{
			name:     "value is NOT found in LIST of ACTIVE",
			testFunc: listValues,
			state:    policydb.StateActive,
			isFound:  false,
		},
		{
			name:     "value is found when filtering for INACTIVE state",
			testFunc: listValues,
			state:    policydb.StateInactive,
			isFound:  true,
		},
		{
			name:     "value is found when filtering for ANY state",
			testFunc: listValues,
			state:    policydb.StateAny,
			isFound:  true,
		},
	}

	for _, tableTest := range tests {
		s.T().Run(tableTest.name, func(t *testing.T) {
			found := tableTest.testFunc(tableTest.state)
			assert.Equal(t, tableTest.isFound, found)
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
	gotNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateActive)
	s.Require().NoError(err)
	s.NotNil(gotNamespaces)
	found := false
	for _, ns := range gotNamespaces {
		if n.GetId() == ns.GetId() {
			found = true
			break
		}
	}
	s.True(found)

	// test that the namespace is not found in the list of inactive namespaces
	gotNamespaces, err = s.db.PolicyClient.ListNamespaces(s.ctx, policydb.StateInactive)
	s.Require().NoError(err)
	s.NotNil(gotNamespaces)
	found = false
	for _, ns := range gotNamespaces {
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
	s.True(updated.GetActive().GetValue())
	s.Equal(after, updated.GetName())
	createdTime := created.GetMetadata().GetCreatedAt().AsTime()
	updatedTime := updated.GetMetadata().GetUpdatedAt().AsTime()
	s.True(createdTime.Before(updatedTime))

	got, err := s.db.PolicyClient.GetNamespace(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("https://"+after, got.GetFqn())

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

	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "kas.uri/ns",
		PublicKey: pubKey,
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(kas)

	// create a grant
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, policydb.AssignKeyAccessServerToNamespaceParams{
		NamespaceID:       n.GetId(),
		KeyAccessServerID: kas.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	// get the namespace and verify the grant is present
	got, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
}

func TestNamespacesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping namespaces integration tests")
	}
	suite.Run(t, new(NamespacesSuite))
}
