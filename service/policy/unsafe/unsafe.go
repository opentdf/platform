package unsafe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/protocol/go/policy/unsafe/unsafeconnect"
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

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[unsafeconnect.UnsafeServiceHandler] {
	unsafeSvc := new(UnsafeService)
	onUpdateConfigHook := OnConfigUpdate(unsafeSvc)
	return &serviceregistry.Service[unsafeconnect.UnsafeServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[unsafeconnect.UnsafeServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &unsafe.UnsafeService_ServiceDesc,
			ConnectRPCFunc: unsafeconnect.NewUnsafeServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (unsafeconnect.UnsafeServiceHandler, serviceregistry.HandlerServer) {
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

//
// Unsafe Namespace RPCs
//

func (s *UnsafeService) UnsafeUpdateNamespace(ctx context.Context, req *connect.Request[unsafe.UnsafeUpdateNamespaceRequest]) (*connect.Response[unsafe.UnsafeUpdateNamespaceResponse], error) {
	id := req.Msg.GetId()
	name := req.Msg.GetName()

	rsp := &unsafe.UnsafeUpdateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   id,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetNamespace(ctx, id)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		updated, err := txClient.UnsafeUpdateNamespace(ctx, id, name)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated

		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Namespace = &policy.Namespace{
			Id: id,
		}

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("namespace", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *UnsafeService) UnsafeReactivateNamespace(ctx context.Context, req *connect.Request[unsafe.UnsafeReactivateNamespaceRequest]) (*connect.Response[unsafe.UnsafeReactivateNamespaceResponse], error) {
	id := req.Msg.GetId()

	rsp := &unsafe.UnsafeReactivateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   id,
	}

	original, err := s.dbClient.GetNamespace(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeReactivateNamespace(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Namespace = &policy.Namespace{
		Id: id,
	}

	return connect.NewResponse(rsp), nil
}

func (s *UnsafeService) UnsafeDeleteNamespace(ctx context.Context, req *connect.Request[unsafe.UnsafeDeleteNamespaceRequest]) (*connect.Response[unsafe.UnsafeDeleteNamespaceResponse], error) {
	id := req.Msg.GetId()

	rsp := &unsafe.UnsafeDeleteNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   id,
	}

	existing, err := s.dbClient.GetNamespace(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteNamespace(ctx, existing, req.Msg.GetFqn())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Namespace = &policy.Namespace{
		Id: id,
	}

	return connect.NewResponse(rsp), nil
}

//
// Unsafe Attribute Definition RPCs
//

func (s *UnsafeService) UnsafeUpdateAttribute(ctx context.Context, req *connect.Request[unsafe.UnsafeUpdateAttributeRequest]) (*connect.Response[unsafe.UnsafeUpdateAttributeResponse], error) {
	id := req.Msg.GetId()

	rsp := &unsafe.UnsafeUpdateAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ObjectID:   id,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetAttribute(ctx, id)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		updated, err := txClient.UnsafeUpdateAttribute(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated

		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Attribute = &policy.Attribute{
			Id: id,
		}

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("attribute", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *UnsafeService) UnsafeReactivateAttribute(ctx context.Context, req *connect.Request[unsafe.UnsafeReactivateAttributeRequest]) (*connect.Response[unsafe.UnsafeReactivateAttributeResponse], error) {
	id := req.Msg.GetId()

	rsp := &unsafe.UnsafeReactivateAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ObjectID:   id,
	}

	original, err := s.dbClient.GetAttribute(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeReactivateAttribute(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: id,
	}

	return connect.NewResponse(rsp), nil
}

func (s *UnsafeService) UnsafeDeleteAttribute(ctx context.Context, req *connect.Request[unsafe.UnsafeDeleteAttributeRequest]) (*connect.Response[unsafe.UnsafeDeleteAttributeResponse], error) {
	id := req.Msg.GetId()

	rsp := &unsafe.UnsafeDeleteAttributeResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeAttributeDefinition,
		ObjectID:   id,
	}

	existing, err := s.dbClient.GetAttribute(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteAttribute(ctx, existing, req.Msg.GetFqn())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: id,
	}

	return connect.NewResponse(rsp), nil
}

//
// Unsafe Attribute Value RPCs
//

func (s *UnsafeService) UnsafeUpdateAttributeValue(ctx context.Context, req *connect.Request[unsafe.UnsafeUpdateAttributeValueRequest]) (*connect.Response[unsafe.UnsafeUpdateAttributeValueResponse], error) {
	id := req.Msg.GetId()

	rsp := &unsafe.UnsafeUpdateAttributeValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeValue,
		ObjectID:   id,
	}

	err := s.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		original, err := txClient.GetAttributeValue(ctx, id)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		updated, err := txClient.UnsafeUpdateAttributeValue(ctx, req.Msg)
		if err != nil {
			s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.Original = original
		auditParams.Updated = updated

		s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		rsp.Value = &policy.Value{
			Id: id,
		}

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("value", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (s *UnsafeService) UnsafeReactivateAttributeValue(ctx context.Context, req *connect.Request[unsafe.UnsafeReactivateAttributeValueRequest]) (*connect.Response[unsafe.UnsafeReactivateAttributeValueResponse], error) {
	id := req.Msg.GetId()

	rsp := &unsafe.UnsafeReactivateAttributeValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeAttributeValue,
		ObjectID:   id,
	}

	original, err := s.dbClient.GetAttributeValue(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeReactivateAttributeValue(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: id,
	}
	return connect.NewResponse(rsp), nil
}

func (s *UnsafeService) UnsafeDeleteAttributeValue(ctx context.Context, req *connect.Request[unsafe.UnsafeDeleteAttributeValueRequest]) (*connect.Response[unsafe.UnsafeDeleteAttributeValueResponse], error) {
	id := req.Msg.GetId()

	rsp := &unsafe.UnsafeDeleteAttributeValueResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeAttributeValue,
		ObjectID:   id,
	}

	existing, err := s.dbClient.GetAttributeValue(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteAttributeValue(ctx, existing, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: id,
	}
	return connect.NewResponse(rsp), nil
}

func (s *UnsafeService) UnsafeDeleteKasKey(context.Context, *connect.Request[unsafe.UnsafeDeleteKasKeyRequest]) (*connect.Response[unsafe.UnsafeDeleteKasKeyResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}
