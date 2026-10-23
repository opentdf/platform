package unsafe

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/protocol/go/policy/unsafe/unsafeconnectv2"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type UnsafeService struct { //nolint:revive // UnsafeService is a valid name for this struct
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(unsafeSvc *UnsafeService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		unsafeSvc.config = sharedCfg
		unsafeSvc.dbClient = policydb.NewClient(unsafeSvc.dbClient.Client, unsafeSvc.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))
		unsafeSvc.logger.Info("unsafe service config reloaded")
		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[unsafeconnectv2.UnsafeServiceHandler] {
	unsafeSvc := new(UnsafeService)
	onUpdateConfigHook := OnConfigUpdate(unsafeSvc)

	return &serviceregistry.Service[unsafeconnectv2.UnsafeServiceHandler]{
		Close: unsafeSvc.Close,
		ServiceOptions: serviceregistry.ServiceOptions[unsafeconnectv2.UnsafeServiceHandler]{
			Namespace:              ns,
			DB:                     dbRegister,
			ServiceDesc:            &unsafe.UnsafeService_ServiceDesc,
			ConnectRPCRegisterFunc: unsafeconnectv2.RegisterUnsafeServiceHandler,
			OnConfigUpdate:         onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (unsafeconnectv2.UnsafeServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting unsafe service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				unsafeSvc.logger = logger
				unsafeSvc.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				unsafeSvc.config = cfg
				return unsafeSvc, nil
			},
		},
	}
}

// Close gracefully shuts down the service, closing the database client.
func (s *UnsafeService) Close() {
	s.logger.Info("gracefully shutting down unsafe service")
	s.dbClient.Close()
}

//
// Unsafe Namespace RPCs
//

func (s *UnsafeService) UnsafeUpdateNamespace(ctx context.Context, req *unsafe.UnsafeUpdateNamespaceRequest) (*unsafe.UnsafeUpdateNamespaceResponse, error) {
	id := req.GetId()
	name := req.GetName()

	rsp := &unsafe.UnsafeUpdateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   id,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetNamespace(ctx, id)
		if err != nil {
			return err
		}

		updated, err := txClient.UnsafeUpdateNamespace(ctx, id, name)
		if err != nil {
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated

		rsp.Namespace = &policy.Namespace{
			Id: id,
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("namespace", req.String()))
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (s *UnsafeService) UnsafeReactivateNamespace(ctx context.Context, req *unsafe.UnsafeReactivateNamespaceRequest) (*unsafe.UnsafeReactivateNamespaceResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeReactivateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   id,
	}

	original, err := s.dbClient.GetNamespace(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeReactivateNamespace(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Namespace = &policy.Namespace{
		Id: id,
	}

	return rsp, nil
}

func (s *UnsafeService) UnsafeDeleteNamespace(ctx context.Context, req *unsafe.UnsafeDeleteNamespaceRequest) (*unsafe.UnsafeDeleteNamespaceResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeDeleteNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   id,
	}

	existing, err := s.dbClient.GetNamespace(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteNamespace(ctx, existing, req.GetFqn())
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Namespace = &policy.Namespace{
		Id: id,
	}

	return rsp, nil
}

//
// Unsafe Attribute Definition RPCs
//

func (s *UnsafeService) UnsafeUpdateAttribute(ctx context.Context, req *unsafe.UnsafeUpdateAttributeRequest) (*unsafe.UnsafeUpdateAttributeResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeUpdateAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ObjectID:   id,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetAttribute(ctx, id)
		if err != nil {
			return err
		}

		updated, err := txClient.UnsafeUpdateAttribute(ctx, req)
		if err != nil {
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated

		rsp.Attribute = &policy.Attribute{
			Id: id,
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("attribute", req.String()))
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (s *UnsafeService) UnsafeReactivateAttribute(ctx context.Context, req *unsafe.UnsafeReactivateAttributeRequest) (*unsafe.UnsafeReactivateAttributeResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeReactivateAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ObjectID:   id,
	}

	original, err := s.dbClient.GetAttribute(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeReactivateAttribute(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: id,
	}

	return rsp, nil
}

func (s *UnsafeService) UnsafeDeleteAttribute(ctx context.Context, req *unsafe.UnsafeDeleteAttributeRequest) (*unsafe.UnsafeDeleteAttributeResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeDeleteAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ObjectID:   id,
	}

	existing, err := s.dbClient.GetAttribute(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteAttribute(ctx, existing, req.GetFqn())
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: id,
	}

	return rsp, nil
}

//
// Unsafe Attribute Value RPCs
//

func (s *UnsafeService) UnsafeUpdateAttributeValue(ctx context.Context, req *unsafe.UnsafeUpdateAttributeValueRequest) (*unsafe.UnsafeUpdateAttributeValueResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeUpdateAttributeValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeValue,
		ObjectID:   id,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetAttributeValue(ctx, id)
		if err != nil {
			return err
		}

		updated, err := txClient.UnsafeUpdateAttributeValue(ctx, req)
		if err != nil {
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated

		rsp.Value = &policy.Value{
			Id: id,
		}

		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("value", req.String()))
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func (s *UnsafeService) UnsafeReactivateAttributeValue(ctx context.Context, req *unsafe.UnsafeReactivateAttributeValueRequest) (*unsafe.UnsafeReactivateAttributeValueResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeReactivateAttributeValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeValue,
		ObjectID:   id,
	}

	original, err := s.dbClient.GetAttributeValue(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeReactivateAttributeValue(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: id,
	}
	return rsp, nil
}

func (s *UnsafeService) UnsafeDeleteAttributeValue(ctx context.Context, req *unsafe.UnsafeDeleteAttributeValueRequest) (*unsafe.UnsafeDeleteAttributeValueResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeDeleteAttributeValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeAttributeValue,
		ObjectID:   id,
	}

	existing, err := s.dbClient.GetAttributeValue(ctx, id)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteAttributeValue(ctx, existing, req)
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: id,
	}
	return rsp, nil
}

func (s *UnsafeService) UnsafeUpdateKey(ctx context.Context, req *unsafe.UnsafeUpdateKeyRequest) (*unsafe.UnsafeUpdateKeyResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeUpdateKeyResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeKasRegistryKeys,
		ObjectID:   id,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		existing, err := txClient.GetKey(ctx, &kasregistry.GetKeyRequest_Id{Id: id})
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
		}

		auditParams.Original = unsafeUpdateKeyAuditValue(existing)

		updated, err := txClient.UnsafeUpdateKey(ctx, existing, req)
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextUpdateFailed, slog.String("id", id))
		}

		auditParams.Updated = unsafeUpdateKeyAuditValue(updated)

		rsp.Key = updated
		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, err
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}

func unsafeUpdateKeyAuditValue(kasKey *policy.KasKey) *policy.KasKey {
	if kasKey.GetKey() == nil {
		return nil
	}

	return &policy.KasKey{
		KasUri: kasKey.GetKasUri(),
		Key: &policy.AsymmetricKey{
			KeyId:          kasKey.GetKey().GetKeyId(),
			KeyMode:        kasKey.GetKey().GetKeyMode(),
			ProviderConfig: unsafeUpdateKeyAuditProviderConfig(kasKey.GetKey().GetProviderConfig()),
		},
	}
}

func unsafeUpdateKeyAuditProviderConfig(providerConfig *policy.KeyProviderConfig) *policy.KeyProviderConfig {
	if providerConfig == nil {
		return nil
	}

	return &policy.KeyProviderConfig{
		Id:      providerConfig.GetId(),
		Name:    providerConfig.GetName(),
		Manager: providerConfig.GetManager(),
	}
}

func (s *UnsafeService) UnsafeDeleteKasKey(ctx context.Context, req *unsafe.UnsafeDeleteKasKeyRequest) (*unsafe.UnsafeDeleteKasKeyResponse, error) {
	id := req.GetId()

	rsp := &unsafe.UnsafeDeleteKasKeyResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasRegistryKeys,
		ObjectID:   id,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		existing, err := txClient.GetKey(ctx, &kasregistry.GetKeyRequest_Id{Id: id})
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
		}

		auditParams.Original = &policy.KasKey{
			KasUri: existing.GetKasUri(),
			Key: &policy.AsymmetricKey{
				Id:    existing.GetKey().GetId(),
				KeyId: existing.GetKey().GetKeyId(),
			},
		}

		_, err = txClient.UnsafeDeleteKey(ctx, existing, req)
		if err != nil {
			return db.StatusifyError(ctx, s.logger, err, db.ErrTextDeletionFailed, slog.String("id", id))
		}

		rsp.Key = &policy.KasKey{
			KasUri: existing.GetKasUri(),
			Key: &policy.AsymmetricKey{
				Id:    existing.GetKey().GetId(),
				KeyId: existing.GetKey().GetKeyId(),
			},
		}
		return nil
	})
	if err != nil {
		s.logger.LogPolicyCRUDFailure(ctx, auditParams)
		return nil, err
	}
	s.logger.LogPolicyCRUDSuccess(ctx, auditParams)

	return rsp, nil
}
