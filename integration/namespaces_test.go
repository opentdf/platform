package integration

import (
	"context"
	"fmt"
	"log/slog"
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
		createdNamespace, err := s.db.Client.CreateNamespace(s.ctx, ns.Name)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), createdNamespace)
	}

	// Creating a namespace with the same name should fail
	for _, ns := range testData {
		_, err := s.db.Client.CreateNamespace(s.ctx, ns.Name)
		assert.NotNil(s.T(), err)
		assert.ErrorIs(s.T(), err, db.ErrUniqueConstraintViolation)
	}
}

func (s *NamespacesSuite) Test_GetNamespace() {
	testData := getNamespaceFixtures()

	for _, ns := range testData {
		createdNamespace, err := s.db.Client.CreateNamespace(s.ctx, ns.Name)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), createdNamespace)
	}

	for _, test := range testData {
		gotNamespace, err := s.db.Client.GetNamespace(s.ctx, test.Id)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), gotNamespace)
		// name retrieved by ID equal to name used to create
		assert.Equal(s.T(), test.Name, gotNamespace.Name)
	}

	// Getting a namespace with an nonexistant ID should fail
	_, err := s.db.Client.GetNamespace(s.ctx, "some-nonexistant-uuid")
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *NamespacesSuite) Test_ListNamespaces() {
	testData := getNamespaceFixtures()

	// Listing when there are none should return an empty list and no error
	expectedNone, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), expectedNone)
	assert.Equal(s.T(), 0, len(expectedNone))

	for _, ns := range testData {
		createdNamespace, err := s.db.Client.CreateNamespace(s.ctx, ns.Name)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), createdNamespace)
	}

	gotNamespaces, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	assert.Equal(s.T(), len(testData), len(gotNamespaces))
}

func (s *NamespacesSuite) Test_UpdateNamespace() {
	testData := getNamespaceFixtures()

	for _, ns := range testData {
		createdNamespace, err := s.db.Client.CreateNamespace(s.ctx, ns.Name)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), createdNamespace)
	}

	for _, ns := range testData {
		updatedName := fmt.Sprintf("%s-updated", ns.Name)
		updatedNamespace, err := s.db.Client.UpdateNamespace(s.ctx, ns.Id, updatedName)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), updatedNamespace)
		assert.Equal(s.T(), updatedName, updatedNamespace.Name)
	}

	// Update when the namespace does not exist should fail
	_, err := s.db.Client.UpdateNamespace(s.ctx, "some-nonexistant-uuid", "new-namespace.com")
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *NamespacesSuite) Test_DeleteNamespace() {
	testData := getNamespaceFixtures()

	for _, ns := range testData {
		createdNamespace, err := s.db.Client.CreateNamespace(s.ctx, ns.Name)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), createdNamespace)
	}

	for _, ns := range testData {
		err := s.db.Client.DeleteNamespace(s.ctx, ns.Id)
		assert.Nil(s.T(), err)
	}

	// Listing should find no namespaces after deleting all
	gotNamespaces, err := s.db.Client.ListNamespaces(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNamespaces)
	assert.Equal(s.T(), 0, len(gotNamespaces))
}

func TestNamespacesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping namespaces integration tests")
	}
	suite.Run(t, new(NamespacesSuite))
}
