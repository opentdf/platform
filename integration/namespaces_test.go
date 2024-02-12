package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type NamespacesSuite struct {
	suite.Suite
	schema string
	f      Fixtures
	db     DBInterface
	ctx    context.Context
}

const nonExistentNamespaceId = "88888888-2222-3333-4444-999999999999"

func (s *NamespacesSuite) SetupSuite() {
	slog.Info("setting up db.Namespaces test suite")
	s.ctx = context.Background()
	s.schema = "test_opentdf_namespaces"
	s.db = NewDBInterface(s.schema)
	s.f = NewFixture(s.db)
	s.f.Provision()
}

func (s *NamespacesSuite) TearDownSuite() {
	slog.Info("tearing down db.Namespaces test suite")
	s.f.TearDown()
}

func getActiveNamespaceFixtures() []FixtureDataNamespace {
	return []FixtureDataNamespace{
		fixtures.GetNamespaceKey("example.com"),
		fixtures.GetNamespaceKey("example.net"),
		fixtures.GetNamespaceKey("example.org"),
	}
}

func (s *NamespacesSuite) Test_CreateNamespace() {
	testData := getActiveNamespaceFixtures()

	for _, ns := range testData {
		ns.Name = strings.Replace(ns.Name, "example", "test", 1)
		createdNamespace, err := s.db.Client.CreateNamespace(s.ctx, ns.Name)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), createdNamespace)
	}

	// Creating a namespace with a name conflict should fail
	for _, ns := range testData {
		_, err := s.db.Client.CreateNamespace(s.ctx, ns.Name)
		assert.NotNil(s.T(), err)
		assert.ErrorIs(s.T(), err, db.ErrUniqueConstraintViolation)
	}
}

func (s *NamespacesSuite) Test_GetNamespace() {
	testData := getActiveNamespaceFixtures()

	for _, test := range testData {
		gotNamespace, err := s.db.Client.GetNamespace(s.ctx, test.Id)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), gotNamespace)
		// name retrieved by ID equal to name used to create
		assert.Equal(s.T(), test.Name, gotNamespace.Name)
	}

	// Getting a namespace with an nonExistent id should fail
	_, err := s.db.Client.GetNamespace(s.ctx, nonExistentNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *NamespacesSuite) Test_GetNamespace_UnspecifiedState_Succeeds() {
	unspecified := fixtures.GetNamespaceKey("unspecified_state")
	// Ensure our fixtures matches expected string enum
	assert.Equal(s.T(), unspecified.State, db.StateUnspecified)

	got, err := s.db.Client.GetNamespace(s.ctx, unspecified.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), unspecified.Name, got.Name)
}

func (s *NamespacesSuite) Test_GetNamespace_InactiveState_Succeeds() {
	inactive := fixtures.GetNamespaceKey("inactive_state")
	// Ensure our fixtures matches expected string enum
	assert.Equal(s.T(), inactive.State, db.StateInactive)

	got, err := s.db.Client.GetNamespace(s.ctx, inactive.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), inactive.Name, got.Name)
}

func (s *NamespacesSuite) Test_GetNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.Client.GetNamespace(s.ctx, nonExistentNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)
}

func (s *NamespacesSuite) Test_ListNamespaces() {
	testData := getActiveNamespaceFixtures()

	gotNamespaces, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	assert.GreaterOrEqual(s.T(), len(gotNamespaces), len(testData))
}

func (s *NamespacesSuite) Test_UpdateNamespace() {
	testData := getActiveNamespaceFixtures()

	for i, ns := range testData {
		updatedName := fmt.Sprintf("%s-updated", ns.Name)
		testData[i].Name = updatedName
		updatedNamespace, err := s.db.Client.UpdateNamespace(s.ctx, ns.Id, updatedName)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), updatedNamespace)
		assert.Equal(s.T(), updatedName, updatedNamespace.Name)
	}

	// Update when the namespace does not exist should fail
	_, err := s.db.Client.UpdateNamespace(s.ctx, nonExistentNamespaceId, "new-namespace.com")
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)

	// Update to a conflict should fail
	gotNamespace, e := s.db.Client.UpdateNamespace(s.ctx, testData[0].Id, testData[1].Name)
	assert.Nil(s.T(), gotNamespace)
	assert.NotNil(s.T(), e)
	assert.ErrorIs(s.T(), e, db.ErrUniqueConstraintViolation)
}

func (s *NamespacesSuite) Test_UpdateNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.Client.UpdateNamespace(s.ctx, nonExistentNamespaceId, "new-namespace.com")
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)
}

func (s *NamespacesSuite) Test_DeleteNamespace_HardDelete() {
	testData := getActiveNamespaceFixtures()
	isSoftDelete := false

	// Deletion should fail when the namespace is referenced as FK in attribute(s)
	for _, ns := range testData {
		deleted, err := s.db.Client.DeleteNamespace(s.ctx, ns.Id, isSoftDelete)
		assert.NotNil(s.T(), err)
		assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
		assert.Nil(s.T(), deleted)
	}

	// Deletion should succeed when NOT referenced as FK in attribute(s)
	newNamespaceId, err := s.db.Client.CreateNamespace(s.ctx, "new-namespace.com")
	assert.Nil(s.T(), err)
	assert.NotEqual(s.T(), "", newNamespaceId)

	deleted, err := s.db.Client.DeleteNamespace(s.ctx, newNamespaceId, isSoftDelete)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	// Deleted namespace should not be found on List
	gotNamespaces, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	for _, ns := range gotNamespaces {
		assert.NotEqual(s.T(), newNamespaceId, ns.Id)
	}

	// Deleted namespace should not be found on Get
	_, err = s.db.Client.GetNamespace(s.ctx, newNamespaceId)
	fmt.Println(err)
	assert.NotNil(s.T(), err)
}

func (s *NamespacesSuite) Test_DeleteNamespace_SoftDelete() {
	isSoftDelete := true

	id, err := s.db.Client.CreateNamespace(s.ctx, "testing-soft-delete-namespace.com")
	assert.Nil(s.T(), err)
	assert.NotEqual(s.T(), "", id)

	deleted, err := s.db.Client.DeleteNamespace(s.ctx, id, isSoftDelete)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	// Deleted namespace should not be found on List
	gotNamespaces, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	for _, ns := range gotNamespaces {
		assert.NotEqual(s.T(), id, ns.Id)
	}

	// Deleted namespace should still be found on Get
	gotNamespace, err := s.db.Client.GetNamespace(s.ctx, id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespace)
	assert.Equal(s.T(), id, gotNamespace.Id)
}

// TODO: update these tests to use GETs (not LISTs) and assert on the state once provided in protos/struct types
func (s *NamespacesSuite) Test_SoftDeleteNamespace_Cascades_ToAttributesAndValues() {
	// create a namespace
	nsId, err := s.db.Client.CreateNamespace(s.ctx, "cascading-soft-delete-namespace.com")
	assert.Nil(s.T(), err)
	assert.NotEqual(s.T(), "", nsId)

	// add an attribute under that namespaces
	attr := &attributes.AttributeCreateUpdate{
		Name:        "test__cascading-soft-delete-attribute",
		NamespaceId: nsId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.Client.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	// add a value under that attribute
	val := &attributes.ValueCreateUpdate{
		Value: "test__cascading-soft-delete-value",
	}
	createdVal, err := s.db.Client.CreateAttributeValue(s.ctx, createdAttr.Id, val)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdVal)

	// soft delete the namespace
	deletedNs, err := s.db.Client.DeleteNamespace(s.ctx, nsId, true)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deletedNs)

	// ensure the namespace is not found in LIST
	listedNamespaces, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), listedNamespaces)
	for _, ns := range listedNamespaces {
		assert.NotEqual(s.T(), nsId, ns.Id)
	}

	// ensure the attribute is not found in LIST
	listedAttrs, err := s.db.Client.ListAllAttributes(s.ctx, db.StateActive)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), listedAttrs)
	for _, a := range listedAttrs {
		assert.NotEqual(s.T(), createdAttr.Id, a.Id)
		assert.NotEqual(s.T(), nsId, a.Namespace.Id)
	}

	// ensure the value is not found in LIST
	listedVals, err := s.db.Client.ListAttributeValues(s.ctx, createdAttr.Id, db.StateActive)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), listedVals)
	fmt.Println("listedVals:", listedVals)

	// TODO: figure out why this isn't working
	assert.Equal(s.T(), 0, len(listedVals))
}

func (s *NamespacesSuite) Test_DeleteNamespace_DoesNotExist_ShouldFail() {
	ns, err := s.db.Client.DeleteNamespace(s.ctx, nonExistentNamespaceId, true)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)

	ns, err = s.db.Client.DeleteNamespace(s.ctx, nonExistentNamespaceId, false)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
	assert.Nil(s.T(), ns)
}

func TestNamespacesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping namespaces integration tests")
	}
	suite.Run(t, new(NamespacesSuite))
}
