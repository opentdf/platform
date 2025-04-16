package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

type RegisteredResourcesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *RegisteredResourcesSuite) SetupSuite() {
	slog.Info("setting up db.RegisteredResources test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_registered_resources"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *RegisteredResourcesSuite) TearDownSuite() {
	slog.Info("tearing down db.RegisteredResources test suite")
	s.f.TearDown()
}

func TestRegisteredResourcesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registered resources integration test")
	}
	suite.Run(t, new(RegisteredResourcesSuite))
}

///
/// Registered Resources
///

// Create

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_NormalizedName_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name: "TeST_CrEaTe_NorMa-LiZeD",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Equal(strings.ToLower(req.Name), created.Name)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_WithValues_Succeeds() {
	values := []string{
		"test_create_values__value1",
		"test_create_values__value2",
	}
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name:   "test_create_values",
		Values: values,
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Require().Equal(len(created.Values), 2)
	s.Equal(values[0], created.Values[0].Value)
	s.Equal(values[1], created.Values[1].Value)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_WithMetadata_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create_metadata",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Require().Equal(len(created.Metadata.Labels), 2)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_WithNonUniqueName_Fails() {
	existing := s.f.GetRegisteredResourceKey("res_with_values")
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name: existing.Name,
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(created)
}

///
/// Registered Resource Values
///

// Create

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_Succeeds() {
	res := s.f.GetRegisteredResourceKey("res_only")
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.ID,
		Value:      "test_create_value",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_NormalizedName_Succeeds() {
	res := s.f.GetRegisteredResourceKey("res_only")
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.ID,
		Value:      "TeST_CrEaTe_NorMa-LiZeD",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Equal(strings.ToLower(req.Value), created.Value)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_WithMetadata_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: s.f.GetRegisteredResourceKey("res_only").ID,
		Value:      "test_create_metadata",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Require().Equal(len(created.Metadata.Labels), 2)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_WithInvalidResource_Fails() {
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: "00000000-0000-0000-0000-000000000000",
		Value:      "test_create_value__invalid_resource",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
	s.Nil(created)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_WithNonUniqueResourceAndValue_Fails() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue := s.f.GetRegisteredResourceValueKey("res_with_values__value1")

	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: existingRes.ID,
		Value:      existingResValue.Value,
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(created)
}
