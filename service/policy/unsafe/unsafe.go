package unsafe

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/protocol/go/policy/unsafe/unsafeconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type UnsafeService struct { //nolint:revive // UnsafeService is a valid name for this struct
	unsafe.UnimplementedUnsafeServiceServer
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
}

func NewRegistration() serviceregistry.Registration {
	return serviceregistry.Registration{
		ServiceDesc: &unsafe.UnsafeService_ServiceDesc,
		RegisterFunc: func(srp serviceregistry.RegistrationParams) (any, serviceregistry.HandlerServer) {
			us := &UnsafeService{dbClient: policydb.NewClient(srp.DBClient, srp.Logger), logger: srp.Logger}
			return us, func(ctx context.Context, mux *http.ServeMux, server any) {
				path, handler := unsafeconnect.NewUnsafeServiceHandler(us)
				mux.Handle(path, handler)
			}
		},
	}
}

//
// Unsafe Namespace RPCs
//

func (s *UnsafeService) UnsafeUpdateNamespace(ctx context.Context, req *connect.Request[unsafe.UnsafeUpdateNamespaceRequest]) (*connect.Response[unsafe.UnsafeUpdateNamespaceResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeUpdateNamespaceResponse{}

	_, err := s.dbClient.GetNamespace(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	item, err := s.dbClient.UnsafeUpdateNamespace(ctx, r.GetId(), r.GetName())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()), slog.String("namespace", r.GetName()))
	}
	rsp.Namespace = item

	return &connect.Response[unsafe.UnsafeUpdateNamespaceResponse]{Msg: rsp}, nil
}

func (s *UnsafeService) UnsafeReactivateNamespace(ctx context.Context, req *connect.Request[unsafe.UnsafeReactivateNamespaceRequest]) (*connect.Response[unsafe.UnsafeReactivateNamespaceResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeReactivateNamespaceResponse{}

	_, err := s.dbClient.GetNamespace(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	item, err := s.dbClient.UnsafeReactivateNamespace(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()))
	}
	rsp.Namespace = item

	return &connect.Response[unsafe.UnsafeReactivateNamespaceResponse]{Msg: rsp}, nil
}

func (s *UnsafeService) UnsafeDeleteNamespace(ctx context.Context, req *connect.Request[unsafe.UnsafeDeleteNamespaceRequest]) (*connect.Response[unsafe.UnsafeDeleteNamespaceResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeDeleteNamespaceResponse{}

	existing, err := s.dbClient.GetNamespace(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	deleted, err := s.dbClient.UnsafeDeleteNamespace(ctx, existing, r.GetFqn())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", r.GetId()))
	}

	rsp.Namespace = deleted

	return &connect.Response[unsafe.UnsafeDeleteNamespaceResponse]{Msg: rsp}, nil
}

//
// Unsafe Attribute Definition RPCs
//

func (s *UnsafeService) UnsafeUpdateAttribute(ctx context.Context, req *connect.Request[unsafe.UnsafeUpdateAttributeRequest]) (*connect.Response[unsafe.UnsafeUpdateAttributeResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeUpdateAttributeResponse{}

	_, err := s.dbClient.GetAttribute(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	item, err := s.dbClient.UnsafeUpdateAttribute(ctx, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()), slog.String("attribute", r.String()))
	}

	rsp.Attribute = item

	return &connect.Response[unsafe.UnsafeUpdateAttributeResponse]{Msg: rsp}, nil
}

func (s *UnsafeService) UnsafeReactivateAttribute(ctx context.Context, req *connect.Request[unsafe.UnsafeReactivateAttributeRequest]) (*connect.Response[unsafe.UnsafeReactivateAttributeResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeReactivateAttributeResponse{}

	_, err := s.dbClient.GetAttribute(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	item, err := s.dbClient.UnsafeReactivateAttribute(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()))
	}

	rsp.Attribute = item

	return &connect.Response[unsafe.UnsafeReactivateAttributeResponse]{Msg: rsp}, nil
}

func (s *UnsafeService) UnsafeDeleteAttribute(ctx context.Context, req *connect.Request[unsafe.UnsafeDeleteAttributeRequest]) (*connect.Response[unsafe.UnsafeDeleteAttributeResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeDeleteAttributeResponse{}

	existing, err := s.dbClient.GetAttribute(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	deleted, err := s.dbClient.UnsafeDeleteAttribute(ctx, existing, r.GetFqn())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", r.GetId()))
	}

	rsp.Attribute = deleted

	return &connect.Response[unsafe.UnsafeDeleteAttributeResponse]{Msg: rsp}, nil
}

//
// Unsafe Attribute Value RPCs
//

func (s *UnsafeService) UnsafeUpdateAttributeValue(ctx context.Context, req *connect.Request[unsafe.UnsafeUpdateAttributeValueRequest]) (*connect.Response[unsafe.UnsafeUpdateAttributeValueResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeUpdateAttributeValueResponse{}
	_, err := s.dbClient.GetAttributeValue(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	item, err := s.dbClient.UnsafeUpdateAttributeValue(ctx, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()), slog.String("attribute_value", r.String()))
	}

	rsp.Value = item
	return &connect.Response[unsafe.UnsafeUpdateAttributeValueResponse]{Msg: rsp}, nil
}

func (s *UnsafeService) UnsafeReactivateAttributeValue(ctx context.Context, req *connect.Request[unsafe.UnsafeReactivateAttributeValueRequest]) (*connect.Response[unsafe.UnsafeReactivateAttributeValueResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeReactivateAttributeValueResponse{}

	_, err := s.dbClient.GetAttributeValue(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	item, err := s.dbClient.UnsafeReactivateAttributeValue(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", r.GetId()))
	}

	rsp.Value = item
	return &connect.Response[unsafe.UnsafeReactivateAttributeValueResponse]{Msg: rsp}, nil
}

func (s *UnsafeService) UnsafeDeleteAttributeValue(ctx context.Context, req *connect.Request[unsafe.UnsafeDeleteAttributeValueRequest]) (*connect.Response[unsafe.UnsafeDeleteAttributeValueResponse], error) {
	r := req.Msg
	rsp := &unsafe.UnsafeDeleteAttributeValueResponse{}
	existing, err := s.dbClient.GetAttributeValue(ctx, r.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", r.GetId()))
	}

	deleted, err := s.dbClient.UnsafeDeleteAttributeValue(ctx, existing, r)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", r.GetId()))
	}

	rsp.Value = deleted
	return &connect.Response[unsafe.UnsafeDeleteAttributeValueResponse]{Msg: rsp}, nil
}
