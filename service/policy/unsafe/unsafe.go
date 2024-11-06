package unsafe

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type UnsafeService struct { //nolint:revive // UnsafeService is a valid name for this struct
	unsafe.UnimplementedUnsafeServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[UnsafeService] {
	return &serviceregistry.Service[UnsafeService]{
		ServiceOptions: serviceregistry.ServiceOptions[UnsafeService]{
			Namespace:   ns,
			DB:          dbRegister,
			ServiceDesc: &unsafe.UnsafeService_ServiceDesc,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (*UnsafeService, serviceregistry.HandlerServer) {
				unsafeSvc := &UnsafeService{dbClient: policydb.NewClient(srp.DBClient, srp.Logger), logger: srp.Logger}
				return unsafeSvc, func(ctx context.Context, mux *runtime.ServeMux) error {
					return unsafe.RegisterUnsafeServiceHandlerServer(ctx, mux, unsafeSvc)
				}
			},
		},
	}
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
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteNamespace(ctx, existing, req.GetFqn())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

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

	original, err := s.dbClient.GetAttribute(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeUpdateAttribute(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("attribute", req.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Attribute = &policy.Attribute{
		Id: id,
	}

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
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteAttribute(ctx, existing, req.GetFqn())
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

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

	original, err := s.dbClient.GetAttributeValue(ctx, id)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	updated, err := s.dbClient.UnsafeUpdateAttributeValue(ctx, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", id), slog.String("attribute_value", req.String()))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: id,
	}
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
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", id))
	}

	_, err = s.dbClient.UnsafeDeleteAttributeValue(ctx, existing, req)
	if err != nil {
		s.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", id))
	}

	s.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.Value = &policy.Value{
		Id: id,
	}
	return rsp, nil
}
