package tests

import (
	"testing"

	"github.com/opentdf/opentdf-v2-poc/sdk/subjectmapping"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type SubjectMappingSuite struct {
	suite.Suite
	conn   *grpc.ClientConn
	client subjectmapping.SubjectMappingServiceClient
}

func (suite *SubjectMappingSuite) SetupSuite() {
	conn, err := grpc.Dial("localhost:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		suite.T().Fatal(err)
	}
	suite.conn = conn

	suite.client = subjectmapping.NewSubjectMappingServiceClient(conn)
}

func (suite *SubjectMappingSuite) TearDownSuite() {
	suite.conn.Close()
}

func TestSubjectMappingSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subject mapping integration tests")
	}
	suite.Run(t, new(SubjectMappingSuite))
}
