package tests

import (
	"testing"

	"github.com/opentdf/opentdf-v2-poc/gen/acre"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AcreSuite struct {
	suite.Suite
	conn   *grpc.ClientConn
	client acre.ResourcEncodingServiceClient
}

func (suite *AcreSuite) SetupSuite() {
	conn, err := grpc.Dial("localhost:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		suite.T().Fatal(err)
	}
	suite.conn = conn

	suite.client = acre.NewResourcEncodingServiceClient(conn)
}

func (suite *AcreSuite) TearDownSuite() {
	suite.conn.Close()
}

func TestAcreSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping acre integration tests")
	}
	suite.Run(t, new(AcreSuite))
}
