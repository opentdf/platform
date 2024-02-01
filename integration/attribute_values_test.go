package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// TODO: test failure of create/update with invalid member id's [https://github.com/opentdf/opentdf-v2-poc/issues/105]

var nonExistentAttributeValueUuid = "78909865-8888-9999-9999-000000000000"

type AttributeValuesSuite struct {
	suite.Suite
	schema string
	f      Fixtures
	db     DBInterface
	ctx    context.Context
}

func (s *AttributeValuesSuite) SetupSuite() {
	slog.Info("setting up db.AttributeValues test suite")
	s.ctx = context.Background()
	s.schema = "test_opentdf_attribute_values"
	s.db = NewDBInterface(s.schema)
	s.f = NewFixture(s.db)
	s.f.Provision()
}

func (s *AttributeValuesSuite) TearDownSuite() {
	slog.Info("tearing down db.AttributeValues test suite")
	s.f.TearDown()
}

func (s *AttributeValuesSuite) Test_ListAttributeValues() {
	attrId := fixtures.GetAttributeValueKey("example.com/attr/attr1/value/value1").AttributeDefinitionId

	list, err := s.db.Client.ListAttributeValues(s.ctx, attrId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), list)

	// ensure list contains the two test fixtures and that response matches expected data
	f1 := fixtures.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	fmt.Println("f1", f1)
	f2 := fixtures.GetAttributeValueKey("example.com/attr/attr1/value/value2")
	fmt.Println("f2", f2)

	fmt.Println(list)
	for _, item := range list {
		if item.Id == f1.Id {
			assert.Equal(s.T(), f1.Id, item.Id)
			assert.Equal(s.T(), f1.Value, item.Value)
			assert.Equal(s.T(), len(f1.Members), len(item.Members))
			assert.Equal(s.T(), f1.AttributeDefinitionId, item.AttributeId)
		} else if item.Id == f2.Id {
			assert.Equal(s.T(), f2.Id, item.Id)
			assert.Equal(s.T(), f2.Value, item.Value)
			assert.Equal(s.T(), len(f2.Members), len(item.Members))
			assert.Equal(s.T(), f2.AttributeDefinitionId, item.AttributeId)
		}
	}
}

func (s *AttributeValuesSuite) Test_GetAttributeValue() {
	f := fixtures.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	v, err := s.db.Client.GetAttributeValue(s.ctx, f.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), v)

	assert.Equal(s.T(), f.Id, v.Id)
	assert.Equal(s.T(), f.Value, v.Value)
	assert.Equal(s.T(), len(f.Members), len(v.Members))
}

func (s *AttributeValuesSuite) Test_GetAttributeValue_NotFound() {
	attr, err := s.db.Client.GetAttributeValue(s.ctx, nonExistentAttributeValueUuid)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), attr)
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_NoMembers_Succeeds() {
	attrDef := fixtures.GetAttributeKey("example.net/attr/attr1")
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my attribute value",
		},
		Description: "test create attribute value description",
	}

	value := &attributes.ValueCreateUpdate{
		Value:    "value create with members test value",
		Metadata: metadata,
	}
	createdValue, err := s.db.Client.CreateAttributeValue(s.ctx, attrDef.Id, value)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdValue)

	got, err := s.db.Client.GetAttributeValue(s.ctx, createdValue.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), createdValue.Id, got.Id)
	assert.Equal(s.T(), createdValue.Value, got.Value)
	assert.Equal(s.T(), len(createdValue.Members), len(got.Members))
	assert.Equal(s.T(), createdValue.Metadata.Description, got.Metadata.Description)
	assert.EqualValues(s.T(), createdValue.Metadata.Labels, got.Metadata.Labels)
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithMembers_Succeeds() {
	attrDef := fixtures.GetAttributeKey("example.net/attr/attr1")
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "testing create with members",
		},
		Description: "testing create with members",
	}

	value := &attributes.ValueCreateUpdate{
		Value: "value3",
		Members: []string{
			fixtures.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id,
			fixtures.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id,
		},
		Metadata: metadata,
	}
	createdValue, err := s.db.Client.CreateAttributeValue(s.ctx, attrDef.Id, value)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdValue)

	got, err := s.db.Client.GetAttributeValue(s.ctx, createdValue.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), createdValue.Id, got.Id)
	assert.Equal(s.T(), createdValue.Value, got.Value)
	assert.Equal(s.T(), createdValue.Metadata.Description, got.Metadata.Description)
	assert.EqualValues(s.T(), createdValue.Metadata.Labels, got.Metadata.Labels)
	assert.EqualValues(s.T(), createdValue.Members, got.Members)
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithInvalidAttributeId_Fails() {
	value := &attributes.ValueCreateUpdate{
		Value: "some value",
	}
	createdValue, err := s.db.Client.CreateAttributeValue(s.ctx, nonExistentAttrId, value)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), createdValue)
}

func (s *AttributeValuesSuite) Test_UpdateAttributeValue() {
	// create a value
	attrDef := fixtures.GetAttributeKey("example.net/attr/attr1")
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "created attribute value",
		},
		Description: "created attribute value",
	}

	value := &attributes.ValueCreateUpdate{
		Value:    "created value testing update",
		Metadata: metadata,
	}
	createdValue, err := s.db.Client.CreateAttributeValue(s.ctx, attrDef.Id, value)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdValue)

	// update the created value
	updatedValue := &attributes.ValueCreateUpdate{
		Value: "updated value testing update",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"name": "updated attribute value",
			},
			Description: "updated attribute value",
		},
	}
	updated, err := s.db.Client.UpdateAttributeValue(s.ctx, createdValue.Id, updatedValue)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)

	// get it again and compare
	got, err := s.db.Client.GetAttributeValue(s.ctx, createdValue.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), updated.Id, got.Id)
	assert.Equal(s.T(), updatedValue.Value, got.Value)
	assert.Equal(s.T(), updatedValue.Metadata.Description, got.Metadata.Description)
	assert.EqualValues(s.T(), updatedValue.Metadata.Labels, got.Metadata.Labels)
	assert.Equal(s.T(), len(updatedValue.Members), len(got.Members))
}

func (s *AttributeValuesSuite) Test_UpdateAttributeValue_WithInvalidId_Fails() {
	updatedValue := &attributes.ValueCreateUpdate{
		Value: "updated value testing update",
	}
	updated, err := s.db.Client.UpdateAttributeValue(s.ctx, nonExistentAttributeValueUuid, updatedValue)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), updated)
}

func (s *AttributeValuesSuite) Test_DeleteAttribute() {
	// create a value
	value := &attributes.ValueCreateUpdate{
		Value: "created value testing delete",
	}
	createdValue, err := s.db.Client.CreateAttributeValue(s.ctx, fixtures.GetAttributeKey("example.net/attr/attr1").Id, value)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdValue)

	// delete it
	resp, err := s.db.Client.DeleteAttributeValue(s.ctx, createdValue.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), resp)

	// get it again to verify it no longer exists
	got, err := s.db.Client.GetAttributeValue(s.ctx, createdValue.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), got)
}

func (s *AttributeValuesSuite) Test_DeleteAttribute_NotFound() {
	resp, err := s.db.Client.DeleteAttributeValue(s.ctx, nonExistentAttributeValueUuid)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
}

func TestAttributeValuesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attribute values integration tests")
	}
	suite.Run(t, new(AttributeValuesSuite))
}
