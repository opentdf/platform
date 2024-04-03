package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	kasr "github.com/opentdf/platform/protocol/go/kasregistry"
	"github.com/opentdf/platform/services/internal/db"
	"github.com/opentdf/platform/services/internal/fixtures"

	"github.com/stretchr/testify/suite"
)

var nonExistentKasRegistryId = "78909865-8888-9999-9999-000000654321"

type KasRegistrySuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context
}

func (s *KasRegistrySuite) SetupSuite() {
	slog.Info("setting up db.KasRegistry test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_kas_registry"
	s.db = fixtures.NewDBInterface(c)
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
	s.NoError(err)
	s.NotNil(list)
	for _, fixture := range fixtures {
		for _, item := range list {
			if item.GetId() == fixture.Id {
				s.Equal(fixture.Id, item.GetId())
				if item.GetPublicKey().GetRemote() != "" {
					s.Equal(fixture.PubKey.Remote, item.GetPublicKey().GetRemote())
				} else {
					s.Equal(fixture.PubKey.Local, item.GetPublicKey().GetLocal())
				}
				s.Equal(fixture.Uri, item.GetUri())
			}
		}
	}
}

func (s *KasRegistrySuite) Test_GetKeyAccessServer() {
	remoteFixture := s.f.GetKasRegistryKey("key_access_server_1")
	localFixture := s.f.GetKasRegistryKey("key_access_server_2")

	remote, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, remoteFixture.Id)
	s.NoError(err)
	s.NotNil(remote)
	s.Equal(remoteFixture.Id, remote.GetId())
	s.Equal(remoteFixture.Uri, remote.GetUri())
	s.Equal(remoteFixture.PubKey.Remote, remote.GetPublicKey().GetRemote())

	local, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, localFixture.Id)
	s.NoError(err)
	s.NotNil(local)
	s.Equal(localFixture.Id, local.GetId())
	s.Equal(localFixture.Uri, local.GetUri())
	s.Equal(localFixture.PubKey.Local, local.GetPublicKey().GetLocal())
}

func (s *KasRegistrySuite) Test_GetKeyAccessServerWithNonExistentIdFails() {
	resp, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, nonExistentKasRegistryId)
	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_Remote() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my key access server",
		},
	}

	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}

	kasRegistry := &kasr.CreateKeyAccessServerRequest{
		Uri:       "kas.uri",
		PublicKey: pubKey,
		Metadata:  metadata,
	}
	r, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.NoError(err)
	s.NotNil(r)
	s.NotEqual("", r.GetId())
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_Local() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "local KAS",
		},
	}

	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Local{
			Local: "some_local_public_key_in_base64",
		},
	}

	kasRegistry := &kasr.CreateKeyAccessServerRequest{
		Uri:       "testingCreation.uri.com",
		PublicKey: pubKey,
		Metadata:  metadata,
	}
	r, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.NoError(err)
	s.NotNil(r)
	s.NotZero(r.GetId())
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_Everything() {
	fixedLabel := "fixed label"
	updateLabel := "update label"
	updatedLabel := "true"
	newLabel := "new label"

	uri := "testingUpdateWithRemoteKey.com"
	pubKeyRemote := "https://remote.com/key"
	updatedUri := "updatedUri.com"
	updatedPubKeyRemote := "https://remote2.com/key"

	// create a test KAS
	created, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, &kasr.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &kasr.PublicKey{
			PublicKey: &kasr.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"fixed":  fixedLabel,
				"update": updateLabel,
			},
		},
	})
	s.NoError(err)
	s.NotNil(created)

	// update it with new values and metadata
	updated, err := s.db.KASRClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasr.UpdateKeyAccessServerRequest{
		Uri: updatedUri,
		PublicKey: &kasr.PublicKey{
			PublicKey: &kasr.PublicKey_Remote{
				Remote: updatedPubKeyRemote,
			},
		},
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"update": updatedLabel,
				"new":    newLabel,
			},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were successful
	got, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(updatedUri, got.GetUri())
	s.Equal(updatedPubKeyRemote, got.GetPublicKey().GetRemote())
	s.Zero(got.GetPublicKey().GetLocal())
	s.Equal(fixedLabel, got.GetMetadata().GetLabels()["fixed"])
	s.Equal(updatedLabel, got.GetMetadata().GetLabels()["update"])
	s.Equal(newLabel, got.GetMetadata().GetLabels()["new"])
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_Metadata_DoesNotAlterOtherValues() {
	uri := "testingUpdateMetadata.com"
	pubKeyRemote := "https://remote.com/key"

	// create a test KAS
	created, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, &kasr.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &kasr.PublicKey{
			PublicKey: &kasr.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
	})
	s.NoError(err)
	s.NotNil(created)

	// update it with new metadata
	updated, err := s.db.KASRClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasr.UpdateKeyAccessServerRequest{
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"new": "new label",
			},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were to metadata alone
	got, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(uri, got.GetUri())
	s.Equal(pubKeyRemote, got.GetPublicKey().GetRemote())
	s.Zero(got.GetPublicKey().GetLocal())
	s.Equal("new label", got.GetMetadata().GetLabels()["new"])
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_Uri_DoesNotAlterOtherValues() {
	uri := "testingUpdateUri.com"
	pubKeyRemote := "https://remote.com/key"
	updatedUri := "updatingUri.com"

	// create a test KAS
	created, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, &kasr.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &kasr.PublicKey{
			PublicKey: &kasr.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
	})
	s.NoError(err)
	s.NotNil(created)

	// update it with new uri
	updated, err := s.db.KASRClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasr.UpdateKeyAccessServerRequest{
		Uri: updatedUri,
	})
	s.NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were successful
	got, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(updatedUri, got.GetUri())
	s.Equal(pubKeyRemote, got.GetPublicKey().GetRemote())
	s.Zero(got.GetPublicKey().GetLocal())
	s.Nil(got.GetMetadata().GetLabels())
}

// the same test but only altering the key
func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_PublicKey_DoesNotAlterOtherValues() {
	uri := "testingUpdateKey.com"
	pubKeyRemote := "https://remote.com/key"
	updatedPubKeyLocal := "my_key"

	// create a test KAS
	created, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, &kasr.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &kasr.PublicKey{
			PublicKey: &kasr.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"unchanged": "unchanged label",
			},
		},
	})
	s.NoError(err)
	s.NotNil(created)

	// update it with new key
	updated, err := s.db.KASRClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasr.UpdateKeyAccessServerRequest{
		PublicKey: &kasr.PublicKey{
			PublicKey: &kasr.PublicKey_Local{
				Local: updatedPubKeyLocal,
			},
		},
	})
	s.NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were successful
	got, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(uri, got.GetUri())
	s.Equal(updatedPubKeyLocal, got.GetPublicKey().GetLocal())
	s.Zero(got.GetPublicKey().GetRemote())
	s.Equal("unchanged label", got.GetMetadata().GetLabels()["unchanged"])
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServerWithNonExistentIdFails() {
	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Local{
			Local: "this_is_a_local_key",
		},
	}
	updatedKas := &kasr.UpdateKeyAccessServerRequest{
		Uri:       "someKasUri.com",
		PublicKey: pubKey,
	}
	resp, err := s.db.KASRClient.UpdateKeyAccessServer(s.ctx, nonExistentKasRegistryId, updatedKas)
	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *KasRegistrySuite) Test_DeleteKeyAccessServer() {
	// create a test KAS
	pubKey := &kasr.PublicKey{
		PublicKey: &kasr.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	testKas := &kasr.CreateKeyAccessServerRequest{
		Uri:       "deleting.net",
		PublicKey: pubKey,
	}
	createdKas, err := s.db.KASRClient.CreateKeyAccessServer(s.ctx, testKas)
	s.NoError(err)
	s.NotNil(createdKas)

	// delete it
	deleted, err := s.db.KASRClient.DeleteKeyAccessServer(s.ctx, createdKas.GetId())
	s.NoError(err)
	s.NotNil(deleted)

	// get after delete to validate it's gone
	resp, err := s.db.KASRClient.GetKeyAccessServer(s.ctx, createdKas.GetId())
	s.NotNil(err)
	s.Nil(resp)
}

func (s *KasRegistrySuite) Test_DeleteKeyAccessServerWithNonExistentIdFails() {
	resp, err := s.db.KASRClient.DeleteKeyAccessServer(s.ctx, nonExistentKasRegistryId)
	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrNotFound)
}

func TestKasRegistrySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistry integration tests")
	}
	suite.Run(t, new(KasRegistrySuite))
}
