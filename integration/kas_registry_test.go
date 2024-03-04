package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/common"
	kasr "github.com/opentdf/platform/protocol/go/kasregistry"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var nonExistentKasRegistryId = "78909865-8888-9999-9999-000000654321"

type KasRegistrySuite struct {
	suite.Suite
	schema string
	f      fixtures.Fixtures
	db     fixtures.DBInterface
	ctx    context.Context
}

func (s *KasRegistrySuite) SetupSuite() {
	slog.Info("setting up db.KasRegistry test suite")
	s.ctx = context.Background()
	s.schema = "test_opentdf_kas_registry"
	s.db = fixtures.NewDBInterface(*Config)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *KasRegistrySuite) TearDownSuite() {
	slog.Info("tearing down db.KasRegistry test suite")
	s.f.TearDown()
}

func (s *KasRegistrySuite) getKasRegistryFixtures() []fixtures.FixtureDataKasRegistry {
	return []fixtures.FixtureDataKasRegistry{
		s.f.GetKasRegistryKey("key_access_server_1"),
		s.f.GetKasRegistryKey("key_access_server_2"),
	}
}

func (s *KasRegistrySuite) Test_ListKeyAccessServers() {
	fixtures := s.getKasRegistryFixtures()
	list, err := s.db.KASRClient.ListKeyAccessServers(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), list)
	for _, fixture := range fixtures {
		for _, item := range list {
			if item.Id == fixture.Id {
				assert.Equal(s.T(), fixture.Id, item.Id)
				if item.PublicKey.GetRemote() != "" {
					assert.Equal(s.T(), fixture.PubKey.Remote, item.PublicKey.GetRemote())
				} else {
					assert.Equal(s.T(), fixture.PubKey.Local, item.PublicKey.GetLocal())
				}
				assert.Equal(s.T(), fixture.Uri, item.Uri)
			}
		}
	}
}

func (s *KasRegistrySuite) Test_GetKeyAccessServer() {
	remoteFixture := s.f.GetKasRegistryKey("key_access_server_1")
	localFixture := s.f.GetKasRegistryKey("key_access_server_2")

	remote, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, remoteFixture.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), remote)
	assert.Equal(s.T(), remoteFixture.Id, remote.Id)
	assert.Equal(s.T(), remoteFixture.Uri, remote.Uri)
	assert.Equal(s.T(), remoteFixture.PubKey.Remote, remote.PublicKey.GetRemote())

	local, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, localFixture.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), local)
	assert.Equal(s.T(), localFixture.Id, local.Id)
	assert.Equal(s.T(), localFixture.Uri, local.Uri)
	assert.Equal(s.T(), localFixture.PubKey.Local, local.PublicKey.GetLocal())
}

func (s *KasRegistrySuite) Test_GetKeyAccessServerWithNonExistentIdFails() {
	resp, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, nonExistentKasRegistryId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_Remote() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my key access server",
		},
		Description: "test create key access server description",
	}

	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}

	kasRegistry := &kasr.KeyAccessServerCreateUpdate{
		Uri:       "kas.uri",
		PublicKey: pubKey,
		Metadata:  metadata,
	}
	createdKasRegistry, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdKasRegistry)
	assert.Equal(s.T(), kasRegistry.Uri, createdKasRegistry.Uri)
	assert.Equal(s.T(), kasRegistry.PublicKey.GetRemote(), createdKasRegistry.PublicKey.GetRemote())
	assert.Equal(s.T(), createdKasRegistry.PublicKey.GetLocal(), "")
	assert.Equal(s.T(), kasRegistry.Metadata.Description, createdKasRegistry.Metadata.Description)
	assert.EqualValues(s.T(), kasRegistry.Metadata.Labels, createdKasRegistry.Metadata.Labels)
	assert.NotEqual(s.T(), "", createdKasRegistry.Id)
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_Local() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "local KAS",
		},
		Description: "this KAS has a locally provided key",
	}

	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Local{
			Local: "some_local_public_key_in_base64",
		},
	}

	kasRegistry := &kasr.KeyAccessServerCreateUpdate{
		Uri:       "testingCreation.uri.com",
		PublicKey: pubKey,
		Metadata:  metadata,
	}
	createdKasRegistry, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdKasRegistry)
	assert.Equal(s.T(), kasRegistry.Uri, createdKasRegistry.Uri)
	assert.Equal(s.T(), kasRegistry.PublicKey.GetLocal(), createdKasRegistry.PublicKey.GetLocal())
	assert.Equal(s.T(), createdKasRegistry.PublicKey.GetRemote(), "")
	assert.Equal(s.T(), kasRegistry.Metadata.Description, createdKasRegistry.Metadata.Description)
	assert.EqualValues(s.T(), kasRegistry.Metadata.Labels, createdKasRegistry.Metadata.Labels)
	assert.NotEqual(s.T(), "", createdKasRegistry.Id)
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer() {
	// create a test KAS
	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	testKas := &kasr.KeyAccessServerCreateUpdate{
		Uri:       "testingUpdateWithRemoteKey.com",
		PublicKey: pubKey,
	}
	createdKas, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, testKas)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdKas)

	// update it with new values and metadata
	updatedMetadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "updated name",
		},
		Description: "updated description",
	}
	updatedKas := &kasr.KeyAccessServerCreateUpdate{
		Uri:       "updatedUri.com",
		PublicKey: pubKey,
		Metadata:  updatedMetadata,
	}
	updated, err := s.db.KASRClient.UpdateKeyAccessServer(s.ctx, createdKas.Id, updatedKas)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)

	// get after update to validate changes were successful
	got, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, createdKas.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), createdKas.Id, got.Id)
	assert.Equal(s.T(), updatedKas.Uri, got.Uri)
	assert.Equal(s.T(), updatedKas.PublicKey.GetRemote(), got.PublicKey.GetRemote())
	assert.Equal(s.T(), updatedMetadata.Description, got.Metadata.Description)
	assert.EqualValues(s.T(), updatedMetadata.Labels, got.Metadata.Labels)
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServerWithNonExistentIdFails() {
	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Local{
			Local: "this_is_a_local_key",
		},
	}
	updatedKas := &kasr.KeyAccessServerCreateUpdate{
		Uri:       "someKasUri.com",
		PublicKey: pubKey,
	}
	resp, err := s.db.KASRClient.UpdateKeyAccessServer(s.ctx, nonExistentKasRegistryId, updatedKas)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *KasRegistrySuite) Test_DeleteKeyAccessServer() {
	// create a test KAS
	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	testKas := &kasr.KeyAccessServerCreateUpdate{
		Uri:       "deleting.net",
		PublicKey: pubKey,
	}
	createdKas, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, testKas)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdKas)

	// delete it
	deleted, err := s.db.KASRClient.DeleteKeyAccessServer(s.ctx, createdKas.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	// get after delete to validate it's gone
	resp, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, createdKas.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
}

func (s *KasRegistrySuite) Test_DeleteKeyAccessServerWithNonExistentIdFails() {
	resp, err := s.db.KASRClient.DeleteKeyAccessServer(s.ctx, nonExistentKasRegistryId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func TestKasRegistrySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistry integration tests")
	}
	suite.Run(t, new(KasRegistrySuite))
}
