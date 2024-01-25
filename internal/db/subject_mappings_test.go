package db

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SubjectMappingTestSuite struct {
	suite.Suite
	db *Client
}

func (suite *SubjectMappingTestSuite) SetupSuite() {
}

func (suite *SubjectMappingTestSuite) TearDownSuite() {
}

func (suite *SubjectMappingTestSuite) TestCreateSubjectMappingSql() {
	expectedColumns := strings.Join([]string{
		"attribute_value_id",
		"operator",
		"subject_attribute",
		"subject_attribute_values",
		"metadata",
	}, ",")
	expectedValues := []interface{}{
		"attribute_value_id--test",
		"operator--test",
		"subject_attribute--test",
		[]string{"subject_attribute_values--test1", "subject_attribute_values--test2"},
		[]byte("a"),
	}

	sql, args, err := createSubjectMappingSql(
		expectedValues[0].(string),
		expectedValues[1].(string),
		expectedValues[2].(string),
		expectedValues[3].([]string),
		expectedValues[4].([]byte),
	)

	assert.Nil(suite.T(), err)
	assert.Contains(suite.T(), sql, "INSERT INTO "+SubjectMappingTable+" ("+expectedColumns+")")
	assert.Contains(suite.T(), sql, "VALUES ($1,$2,$3,$4,$5)")
	assert.Equal(suite.T(), expectedValues, args)
}

func TestDBSubjectMappingTestSuite(t *testing.T) {
	suite.Run(t, new(SubjectMappingTestSuite))
}
