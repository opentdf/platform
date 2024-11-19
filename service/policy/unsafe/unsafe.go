package unsafe

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/protocol/go/policy/unsafe/unsafeconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
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

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[unsafeconnect.UnsafeServiceHandler] {
	return &serviceregistry.Service[unsafeconnect.UnsafeServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[unsafeconnect.UnsafeServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &unsafe.UnsafeService_ServiceDesc,
			ConnectRPCFunc: unsafeconnect.NewUnsafeServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (unsafeconnect.UnsafeServiceHandler, serviceregistry.HandlerServer) {
				cfg := policyconfig.GetSharedPolicyConfig(srp)
				return &UnsafeService{
					dbClient: policydb.NewClient(srp.DBClient, srp.Logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault)),
					logger:   srp.Logger,
					config:   cfg,
				}, nil
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

	original, err := s.dbClient.GetNamespace(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeUpdateNamespace(ctx, id, name)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("namespace", name))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Namespace = &policy.Namespace{
		Id: id,
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

	original, err := s.dbClient.GetAttribute(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeUpdateAttribute(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("attribute", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: id,
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

	original, err := s.dbClient.GetAttributeValue(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeUpdateAttributeValue(ctx, req.Msg)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("attribute_value", req.Msg.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: id,
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
