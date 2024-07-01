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

func (s *UnsafeService) UnsafeUpdateNamespace(ctx context.Context, req *unsafe.UnsafeUpdateNamespaceRequest) (*unsafe.UnsafeUpdateNamespaceResponse, error) {
	rsp := &unsafe.UnsafeUpdateNamespaceResponse{}

	_, err := s.dbClient.GetNamespace(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	item, err := s.dbClient.UnsafeUpdateNamespace(ctx, req.GetId(), req.GetName())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("namespace", req.GetName()))
	}
	rsp.Namespace = item

	return rsp, nil
}

func (s *UnsafeService) UnsafeReactivateNamespace(ctx context.Context, req *unsafe.UnsafeReactivateNamespaceRequest) (*unsafe.UnsafeReactivateNamespaceResponse, error) {
	rsp := &unsafe.UnsafeReactivateNamespaceResponse{}

	_, err := s.dbClient.GetNamespace(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	item, err := s.dbClient.UnsafeReactivateNamespace(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()))
	}
	rsp.Namespace = item

	return rsp, nil
}

func (s *UnsafeService) UnsafeDeleteNamespace(ctx context.Context, req *unsafe.UnsafeDeleteNamespaceRequest) (*unsafe.UnsafeDeleteNamespaceResponse, error) {
	rsp := &unsafe.UnsafeDeleteNamespaceResponse{}

	existing, err := s.dbClient.GetNamespace(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	deleted, err := s.dbClient.UnsafeDeleteNamespace(ctx, existing, req.GetFqn())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	rsp.Namespace = deleted

	return rsp, nil
}

//
// Unsafe Attribute Definition RPCs
//

func (s *UnsafeService) UnsafeUpdateAttribute(ctx context.Context, req *unsafe.UnsafeUpdateAttributeRequest) (*unsafe.UnsafeUpdateAttributeResponse, error) {
	rsp := &unsafe.UnsafeUpdateAttributeResponse{}

	_, err := s.dbClient.GetAttribute(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	item, err := s.dbClient.UnsafeUpdateAttribute(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("attribute", req.String()))
	}

	rsp.Attribute = item

	return rsp, nil
}

func (s *UnsafeService) UnsafeReactivateAttribute(ctx context.Context, req *unsafe.UnsafeReactivateAttributeRequest) (*unsafe.UnsafeReactivateAttributeResponse, error) {
	rsp := &unsafe.UnsafeReactivateAttributeResponse{}

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

func (s *UnsafeService) UnsafeDeleteAttribute(ctx context.Context, req *unsafe.UnsafeDeleteAttributeRequest) (*unsafe.UnsafeDeleteAttributeResponse, error) {
	rsp := &unsafe.UnsafeDeleteAttributeResponse{}

	existing, err := s.dbClient.GetAttribute(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	deleted, err := s.dbClient.UnsafeDeleteAttribute(ctx, existing, req.GetFqn())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	rsp.Attribute = deleted

	return rsp, nil
}

//
// Unsafe Attribute Value RPCs
//

func (s *UnsafeService) UnsafeUpdateAttributeValue(_ context.Context, req *unsafe.UnsafeUpdateAttributeValueRequest) (*unsafe.UnsafeUpdateAttributeValueResponse, error) {
	// _, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// item, err := s.dbClient.UnsafeUpdateAttributeValue(ctx, req.GetId(), req)
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("attribute_value", req.String()))
	// }

	return &unsafe.UnsafeUpdateAttributeValueResponse{
		Value: &policy.Value{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

func (s *UnsafeService) UnsafeReactivateAttributeValue(_ context.Context, req *unsafe.UnsafeReactivateAttributeValueRequest) (*unsafe.UnsafeReactivateAttributeValueResponse, error) {
	// _, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// item, err := s.dbClient.UnsafeReactivateAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()))
	// }

	return &unsafe.UnsafeReactivateAttributeValueResponse{
		Value: &policy.Value{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

func (s *UnsafeService) UnsafeDeleteAttributeValue(_ context.Context, req *unsafe.UnsafeDeleteAttributeValueRequest) (*unsafe.UnsafeDeleteAttributeValueResponse, error) {
	// _, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// err = s.dbClient.UnsafeDeleteAttributeValue(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextDeleteFailed, slog.String("id", req.GetId()))
	// }

	return &unsafe.UnsafeDeleteAttributeValueResponse{
		Value: &policy.Value{
			Id: req.GetId(), // stubbed
		},
	}, nil
}
