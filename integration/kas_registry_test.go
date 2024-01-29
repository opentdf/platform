package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var nonExistentKasRegistryId = "78909865-8888-9999-9999-000000654321"

type KasRegistrySuite struct {
	suite.Suite
	schema string
	f      Fixtures
	db     DBInterface
	ctx    context.Context
}

func (s *KasRegistrySuite) SetupSuite() {
	slog.Info("setting up db.KasRegistry test suite")
	s.ctx = context.Background()
	s.schema = "test_opentdf_kas_registry"
	s.db = NewDBInterface(s.schema)
	s.f = NewFixture(s.db)
	s.f.Provision()
}

func (s *KasRegistrySuite) TearDownSuite() {
	slog.Info("tearing down db.KasRegistry test suite")
	s.f.TearDown()
}

func getKasRegistryFixtures() []FixtureDataKasRegistry {
	return []FixtureDataKasRegistry{
		fixtures.GetKasRegistryKey("key_access_server_1"),
		fixtures.GetKasRegistryKey("key_access_server_2"),
	}
}

func (s *KasRegistrySuite) Test_ListKeyAccessServers() {
	fixtures := getKasRegistryFixtures()
	list, err := s.db.Client.ListKeyAccessServers(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), list)
	for _, fixture := range fixtures {
		for _, item := range list {
			if item.Id == fixture.Id {
				assert.Equal(s.T(), fixture.Id, item.Id)
				if item.PublicKey.GetRemote() != "" {
					assert.Equal(s.T(), fixture.PubKey.PublicKey, item.PublicKey.GetRemote())
				} else {
					assert.Equal(s.T(), fixture.PubKey.PublicKey, item.PublicKey.GetLocal())
				}
				assert.Equal(s.T(), fixture.KeyAccessServer, item.Name)
			}
		}
	}
}

// func (s *KasRegistrySuite) Test_GetKeyAccessServer() {
// 	fixtures := getKasRegistryFixtures()
// 	for _, fixture := range fixtures {
// 		item, err := s.db.Client.GetKeyAccessServer(s.ctx, fixture.Id)
// 		assert.Nil(s.T(), err)
// 		assert.NotNil(s.T(), item)
// 		assert.Equal(s.T(), fixture.Id, item.Id)
// 		if item.PublicKey.GetRemote() != "" {
// 			assert.Equal(s.T(), fixture.PubKey.PublicKey, item.PublicKey.GetRemote())
// 		} else {
// 			assert.Equal(s.T(), fixture.PubKey.PublicKey, item.PublicKey.GetLocal())
// 		}
// 		assert.Equal(s.T(), fixture.KeyAccessServer, item.Name)
// 	}

// }

func TestKasRegistrySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistry integration tests")
	}
	suite.Run(t, new(KasRegistrySuite))
}
