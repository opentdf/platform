package tests

import (
	"testing"

	"github.com/opentdf/opentdf-v2-poc/gen/acse"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AcseSuite struct {
	suite.Suite
	conn   *grpc.ClientConn
	client acse.SubjectEncodingServiceClient
}

func (suite *AcseSuite) SetupSuite() {
	conn, err := grpc.Dial("localhost:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		suite.T().Fatal(err)
	}
	suite.conn = conn

	suite.client = acse.NewSubjectEncodingServiceClient(conn)
}

func (suite *AcseSuite) TearDownSuite() {
	suite.conn.Close()
}

func TestAcseSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acse integration tests")
	}
	suite.Run(t, new(AcseSuite))
}
