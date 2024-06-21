package unsafe

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/internal/logger"
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
			return &UnsafeService{dbClient: policydb.NewClient(srp.DBClient), logger: srp.Logger}, func(ctx context.Context, mux *runtime.ServeMux, server any) error {
				if srv, ok := server.(unsafe.UnsafeServiceServer); ok {
					return unsafe.RegisterUnsafeServiceHandlerServer(ctx, mux, srv)
				}
				return fmt.Errorf("failed to assert server as unsafe.UnsafeServiceServer")
			}
		},
	}
}

//
// Unsafe Namespace RPCs
//

func (s *UnsafeService) UpdateNamespace(_ context.Context, req *unsafe.UpdateNamespaceRequest) (*unsafe.UpdateNamespaceResponse, error) {
	// _, err := s.dbClient.GetNamespace(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// item, err := s.dbClient.UnsafeUpdateNamespace(ctx, req.GetId(), req)
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("namespace", req.String()))
	// }

	return &unsafe.UpdateNamespaceResponse{
		Namespace: &policy.Namespace{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

func (s *UnsafeService) ReactivateNamespace(_ context.Context, req *unsafe.ReactivateNamespaceRequest) (*unsafe.ReactivateNamespaceResponse, error) {
	// _, err := s.dbClient.GetNamespace(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// item, err := s.dbClient.UnsafeReactivateNamespace(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()))
	// }

	return &unsafe.ReactivateNamespaceResponse{
		Namespace: &policy.Namespace{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

func (s *UnsafeService) DeleteNamespace(_ context.Context, req *unsafe.DeleteNamespaceRequest) (*unsafe.DeleteNamespaceResponse, error) {
	// _, err := s.dbClient.GetNamespace(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// err = s.dbClient.UnsafeDeleteNamespace(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextDeleteFailed, slog.String("id", req.GetId()))
	// }

	return &unsafe.DeleteNamespaceResponse{
		Namespace: &policy.Namespace{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

//
// Unsafe Attribute Definition RPCs
//

func (s *UnsafeService) UpdateAttribute(ctx context.Context, req *unsafe.UpdateAttributeRequest) (*unsafe.UpdateAttributeResponse, error) {
	rsp := &unsafe.UpdateAttributeResponse{}

	_, err := s.dbClient.GetAttribute(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	item, err := s.dbClient.UnsafeUpdateAttribute(ctx, req.GetId(), req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("attribute", req.String()))
	}

	rsp.Attribute = item

	return rsp, nil
}

func (s *UnsafeService) ReactivateAttribute(ctx context.Context, req *unsafe.ReactivateAttributeRequest) (*unsafe.ReactivateAttributeResponse, error) {
	rsp := &unsafe.ReactivateAttributeResponse{}

	_, err := s.dbClient.GetAttribute(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	item, err := s.dbClient.UnsafeReactivateAttribute(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()))
	}

	rsp.Attribute = item

	return rsp, nil
}

func (s *UnsafeService) DeleteAttribute(ctx context.Context, req *unsafe.DeleteAttributeRequest) (*unsafe.DeleteAttributeResponse, error) {
	rsp := &unsafe.DeleteAttributeResponse{}

	existing, err := s.dbClient.GetAttribute(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	if existing.GetFqn() != req.GetFqn() {
		return nil, db.StatusifyError(db.ErrNotFound, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()), slog.String("fqn", req.GetFqn()))
	}

	deleted, err := s.dbClient.UnsafeDeleteAttribute(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	rsp.Attribute = deleted

	return rsp, nil
}

//
// Unsafe Attribute Value RPCs
//

func (s *UnsafeService) UpdateAttributeValue(_ context.Context, req *unsafe.UpdateAttributeValueRequest) (*unsafe.UpdateAttributeValueResponse, error) {
	// _, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// item, err := s.dbClient.UnsafeUpdateAttributeValue(ctx, req.GetId(), req)
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("attribute_value", req.String()))
	// }

	return &unsafe.UpdateAttributeValueResponse{
		Value: &policy.Value{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

func (s *UnsafeService) ReactivateAttributeValue(_ context.Context, req *unsafe.ReactivateAttributeValueRequest) (*unsafe.ReactivateAttributeValueResponse, error) {
	// _, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// item, err := s.dbClient.UnsafeReactivateAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()))
	// }

	return &unsafe.ReactivateAttributeValueResponse{
		Value: &policy.Value{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

func (s *UnsafeService) DeleteAttributeValue(_ context.Context, req *unsafe.DeleteAttributeValueRequest) (*unsafe.DeleteAttributeValueResponse, error) {
	// _, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// err = s.dbClient.UnsafeDeleteAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextDeleteFailed, slog.String("id", req.GetId()))
	// }

	return &unsafe.DeleteAttributeValueResponse{
		Value: &policy.Value{
			Id: req.GetId(), // stubbed
		},
	}, nil
}
