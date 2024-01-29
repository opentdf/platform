package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/opentdf-v2-poc/internal/db"
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

const nonExistantNamespaceId = "88888888-2222-3333-4444-999999999999"

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

func getNamespaceFixtures() []FixtureDataNamespace {
	return []FixtureDataNamespace{
		fixtures.GetNamespaceKey("example.com"),
		fixtures.GetNamespaceKey("example.net"),
		fixtures.GetNamespaceKey("example.org"),
	}
}

func (s *NamespacesSuite) Test_CreateNamespace() {
	testData := getNamespaceFixtures()

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
	testData := getNamespaceFixtures()

	for _, test := range testData {
		gotNamespace, err := s.db.Client.GetNamespace(s.ctx, test.Id)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), gotNamespace)
		// name retrieved by ID equal to name used to create
		assert.Equal(s.T(), test.Name, gotNamespace.Name)
	}

	// Getting a namespace with an nonexistant id should fail
	_, err := s.db.Client.GetNamespace(s.ctx, nonExistantNamespaceId)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *NamespacesSuite) Test_ListNamespaces() {
	testData := getNamespaceFixtures()

	gotNamespaces, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	assert.GreaterOrEqual(s.T(), len(gotNamespaces), len(testData))
}

func (s *NamespacesSuite) Test_UpdateNamespace() {
	testData := getNamespaceFixtures()

	for i, ns := range testData {
		updatedName := fmt.Sprintf("%s-updated", ns.Name)
		testData[i].Name = updatedName
		updatedNamespace, err := s.db.Client.UpdateNamespace(s.ctx, ns.Id, updatedName)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), updatedNamespace)
		assert.Equal(s.T(), updatedName, updatedNamespace.Name)
	}

	// Update when the namespace does not exist should fail
	_, err := s.db.Client.UpdateNamespace(s.ctx, nonExistantNamespaceId, "new-namespace.com")
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)

	// Update to a conflict should fail
	gotNamespace, e := s.db.Client.UpdateNamespace(s.ctx, testData[0].Id, testData[1].Name)
	assert.Nil(s.T(), gotNamespace)
	assert.NotNil(s.T(), e)
	assert.ErrorIs(s.T(), e, db.ErrUniqueConstraintViolation)
}

func (s *NamespacesSuite) Test_DeleteNamespace() {
	testData := getNamespaceFixtures()

	// Deletion should fail when the namespace is referenced as FK in attribute(s)
	for _, ns := range testData {
		err := s.db.Client.DeleteNamespace(s.ctx, ns.Id)
		assert.NotNil(s.T(), err)
		assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
	}

	// Deletion should succeed when NOT referenced as FK in attribute(s)
	newNamespaceId, err := s.db.Client.CreateNamespace(s.ctx, "new-namespace.com")
	assert.Nil(s.T(), err)
	assert.NotEqual(s.T(), "", newNamespaceId)

	err = s.db.Client.DeleteNamespace(s.ctx, newNamespaceId)
	assert.Nil(s.T(), err)

	// Deleted namespace should not be found on List
	gotNamespaces, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	for _, ns := range gotNamespaces {
		assert.NotEqual(s.T(), newNamespaceId, ns.Id)
	}

	// Deleted namespace should not be found on Get
	_, err = s.db.Client.GetNamespace(s.ctx, newNamespaceId)
	assert.NotNil(s.T(), err)
}

func TestNamespacesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping namespaces integration tests")
	}
	suite.Run(t, new(NamespacesSuite))
}
