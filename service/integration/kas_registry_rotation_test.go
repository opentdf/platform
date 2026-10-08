package integration

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
)

func rotationSuccessor() *kasregistry.RotateKeyRequest_NewKey {
	return &kasregistry.RotateKeyRequest_NewKey{
		KeyId:         uuid.NewString(),
		Algorithm:     policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx:  &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{KeyId: validKeyID1, WrappedKey: keyCtx},
	}
}

func (s *KasRegistryKeySuite) rotationSource() (*policy.KasKey, *[]string) {
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Name: "rotation-" + uuid.NewString(),
		Uri:  "https://rotation-" + uuid.NewString() + ".example.com",
	})
	s.Require().NoError(err)
	key, err := s.db.PolicyClient.CreateKey(s.ctx, &kasregistry.CreateKeyRequest{
		KasId:         kas.GetId(),
		KeyId:         uuid.NewString(),
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx:  &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{KeyId: validKeyID1, WrappedKey: keyCtx},
		Metadata:      &common.MetadataMutable{Labels: map[string]string{"org_id": "test-org"}},
	})
	s.Require().NoError(err)
	ids := []string{key.GetKasKey().GetKey().GetId()}
	s.T().Cleanup(func() { s.cleanupKeys(ids, []string{kas.GetId()}) })
	return key.GetKasKey(), &ids
}

func (s *KasRegistryKeySuite) Test_RotateKey_RejectsPersistedNonActiveSource() {
	for _, status := range []int32{int32(policy.KeyStatus_KEY_STATUS_UNSPECIFIED), int32(policy.KeyStatus_KEY_STATUS_ROTATED), 99} {
		s.Run(fmt.Sprintf("status_%d", status), func() {
			source, _ := s.rotationSource()
			_, err := s.db.PolicyClient.Pgx.Exec(s.ctx,
				"UPDATE key_access_server_keys SET key_status = $1 WHERE id = $2", status, source.GetKey().GetId())
			s.Require().NoError(err)
			// The supplied snapshot still says ACTIVE; the database is authoritative.
			s.Require().Equal(policy.KeyStatus_KEY_STATUS_ACTIVE, source.GetKey().GetKeyStatus())
			var resp *kasregistry.RotateKeyResponse
			err = s.db.PolicyClient.RunInTx(s.ctx, func(tx *policydb.PolicyDBClient) error {
				resp, err = tx.RotateKey(s.ctx, source, rotationSuccessor())
				return err
			})
			s.Require().ErrorIs(err, db.ErrKeyNotActive)
			s.Nil(resp)
			s.assertRotationKeyCount(source.GetKasId(), 1)
			persisted, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{Id: source.GetKey().GetId()})
			s.Require().NoError(err)
			s.Equal(policy.KeyStatus(status), persisted.GetKey().GetKeyStatus())
			s.Equal(source.GetKey().GetMetadata().GetLabels(), persisted.GetKey().GetMetadata().GetLabels())
		})
	}
}

func (s *KasRegistryKeySuite) Test_RotateKey_MissingSourceRemainsNotFound() {
	err := s.db.PolicyClient.RunInTx(s.ctx, func(tx *policydb.PolicyDBClient) error {
		_, err := tx.RotateKey(s.ctx, &policy.KasKey{Key: &policy.AsymmetricKey{Id: uuid.NewString()}}, rotationSuccessor())
		return err
	})
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *KasRegistryKeySuite) Test_RotateKey_ConcurrentRequestsHaveOneSuccessor() {
	source, keyIDs := s.rotationSource()
	namespace := s.createNamespace()
	s.T().Cleanup(func() { s.cleanupNamespacesAndAttrs([]*policy.Namespace{namespace}) })
	s.createNamespaceMapping(source.GetKey().GetId(), namespace.GetId())
	// Preserve labels written after the service fetched its source snapshot.
	_, err := s.db.PolicyClient.UpdateKey(s.ctx, &kasregistry.UpdateKeyRequest{
		Id: source.GetKey().GetId(), Metadata: &common.MetadataMutable{Labels: map[string]string{"later": "value"}},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	type result struct {
		resp *kasregistry.RotateKeyResponse
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			var resp *kasregistry.RotateKeyResponse
			err := s.db.PolicyClient.RunInTx(s.ctx, func(tx *policydb.PolicyDBClient) error {
				var err error
				resp, err = tx.RotateKey(s.ctx, source, rotationSuccessor())
				return err
			})
			results <- result{resp: resp, err: err}
		}()
	}
	close(start)
	var winner *kasregistry.RotateKeyResponse
	conflicts := 0
	for range 2 {
		r := <-results
		if r.err != nil {
			s.Require().ErrorIs(r.err, db.ErrKeyNotActive)
			s.Nil(r.resp)
			conflicts++
			continue
		}
		s.Require().Nil(winner, "only one rotation may succeed")
		winner = r.resp
		*keyIDs = append(*keyIDs, r.resp.GetKasKey().GetKey().GetId())
	}
	s.Require().NotNil(winner)
	s.Equal(1, conflicts)
	s.assertRotationKeyCount(source.GetKasId(), 2)
	s.Equal(policy.KeyStatus_KEY_STATUS_ACTIVE, winner.GetKasKey().GetKey().GetKeyStatus())
	s.Equal(map[string]string{
		"org_id": "test-org", "later": "value", "rotated_to_kid": winner.GetKasKey().GetKey().GetKeyId(),
	}, winner.GetRotatedResources().GetRotatedOutKey().GetKey().GetMetadata().GetLabels())
	persisted, err := s.db.PolicyClient.GetNamespace(s.ctx, &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: namespace.GetId()})
	s.Require().NoError(err)
	s.Require().Len(persisted.GetKasKeys(), 1)
	s.Equal(winner.GetKasKey().GetKey().GetKeyId(), persisted.GetKasKeys()[0].GetPublicKey().GetKid())
}

func (s *KasRegistryKeySuite) Test_RotateKey_RollbackRestoresStatusLabelsBaseAndMappings() {
	source, _ := s.rotationSource()
	namespace := s.createNamespace()
	s.T().Cleanup(func() { s.cleanupNamespacesAndAttrs([]*policy.Namespace{namespace}) })
	s.createNamespaceMapping(source.GetKey().GetId(), namespace.GetId())
	_, err := s.db.PolicyClient.SetBaseKey(s.ctx, &kasregistry.SetBaseKeyRequest{
		ActiveKey: &kasregistry.SetBaseKeyRequest_Id{Id: source.GetKey().GetId()},
	})
	s.Require().NoError(err)
	failure := errors.New("failure after mapping transfer")
	newKey := rotationSuccessor()
	err = s.db.PolicyClient.RunInTx(s.ctx, func(tx *policydb.PolicyDBClient) error {
		if _, err := tx.RotateKey(s.ctx, source, newKey); err != nil {
			return err
		}
		return failure
	})
	s.Require().ErrorIs(err, failure)
	s.assertRotationSourceUnchanged(source)
	s.assertRotationKeyCount(source.GetKasId(), 1)
	base, err := s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Equal(source.GetKey().GetKeyId(), base.GetPublicKey().GetKid())
	persisted, err := s.db.PolicyClient.GetNamespace(s.ctx, &namespaces.GetNamespaceRequest_NamespaceId{NamespaceId: namespace.GetId()})
	s.Require().NoError(err)
	s.Require().Len(persisted.GetKasKeys(), 1)
	s.Equal(source.GetKey().GetKeyId(), persisted.GetKasKeys()[0].GetPublicKey().GetKid())
	// Failure creating the successor must roll back the status/lineage as well.
	newKey.KeyId = source.GetKey().GetKeyId()
	err = s.db.PolicyClient.RunInTx(s.ctx, func(tx *policydb.PolicyDBClient) error {
		_, err := tx.RotateKey(s.ctx, source, newKey)
		return err
	})
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.assertRotationSourceUnchanged(source)
	s.assertRotationKeyCount(source.GetKasId(), 1)
}

func (s *KasRegistryKeySuite) Test_RotateKey_EmptyBaseKeysRemainEmpty() {
	source, keyIDs := s.rotationSource()
	var count int
	err := s.db.PolicyClient.Pgx.QueryRow(s.ctx, "SELECT count(*) FROM base_keys").Scan(&count)
	s.Require().NoError(err)
	s.Require().Zero(count)
	err = s.db.PolicyClient.RunInTx(s.ctx, func(tx *policydb.PolicyDBClient) error {
		resp, err := tx.RotateKey(s.ctx, source, rotationSuccessor())
		if err == nil {
			*keyIDs = append(*keyIDs, resp.GetKasKey().GetKey().GetId())
		}
		return err
	})
	s.Require().NoError(err)
	err = s.db.PolicyClient.Pgx.QueryRow(s.ctx, "SELECT count(*) FROM base_keys").Scan(&count)
	s.Require().NoError(err)
	s.Zero(count)
}

func (s *KasRegistryKeySuite) assertRotationKeyCount(kasID string, expected int) {
	var count int
	err := s.db.PolicyClient.Pgx.QueryRow(s.ctx,
		"SELECT count(*) FROM key_access_server_keys WHERE key_access_server_id = $1", kasID).Scan(&count)
	s.Require().NoError(err)
	s.Equal(expected, count)
}

func (s *KasRegistryKeySuite) assertRotationSourceUnchanged(source *policy.KasKey) {
	persisted, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{Id: source.GetKey().GetId()})
	s.Require().NoError(err)
	s.Equal(policy.KeyStatus_KEY_STATUS_ACTIVE, persisted.GetKey().GetKeyStatus())
	s.Equal(source.GetKey().GetMetadata().GetLabels(), persisted.GetKey().GetMetadata().GetLabels())
}
