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

func (s *UnsafeService) UpdateNamespace(ctx context.Context, req *unsafe.UpdateNamespaceRequest) (*unsafe.UpdateNamespaceResponse, error) {
	rsp := &unsafe.UpdateNamespaceResponse{}

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

func (s *UnsafeService) ReactivateNamespace(ctx context.Context, req *unsafe.ReactivateNamespaceRequest) (*unsafe.ReactivateNamespaceResponse, error) {
	rsp := &unsafe.ReactivateNamespaceResponse{}

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

func (s *UnsafeService) DeleteNamespace(ctx context.Context, req *unsafe.DeleteNamespaceRequest) (*unsafe.DeleteNamespaceResponse, error) {
	rsp := &unsafe.DeleteNamespaceResponse{}

	existing, err := s.dbClient.GetNamespace(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	// validate the provided namespace FQN is a match for the provided namespace ID
	if existing.GetFqn() != req.GetFqn() {
		return nil, db.StatusifyError(db.ErrNotFound, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()), slog.String("fqn", req.GetFqn()))
	}

	deleted, err := s.dbClient.UnsafeDeleteNamespace(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	rsp.Namespace = deleted

	return rsp, nil
}

//
// Unsafe Attribute Definition RPCs
//

func (s *UnsafeService) UpdateAttribute(_ context.Context, req *unsafe.UpdateAttributeRequest) (*unsafe.UpdateAttributeResponse, error) {
	// _, err := s.dbClient.GetAttribute(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// item, err := s.dbClient.UnsafeUpdateAttribute(ctx, req.GetId(), req)
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("attribute", req.String()))
	// }

	return &unsafe.UpdateAttributeResponse{
		Attribute: &policy.Attribute{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

func (s *UnsafeService) ReactivateAttribute(_ context.Context, req *unsafe.ReactivateAttributeRequest) (*unsafe.ReactivateAttributeResponse, error) {
	// _, err := s.dbClient.GetAttribute(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// item, err := s.dbClient.UnsafeReactivateAttribute(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()))
	// }

	return &unsafe.ReactivateAttributeResponse{
		Attribute: &policy.Attribute{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

func (s *UnsafeService) DeleteAttribute(_ context.Context, req *unsafe.DeleteAttributeRequest) (*unsafe.DeleteAttributeResponse, error) {
	// _, err := s.dbClient.GetAttribute(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	// }

	// err = s.dbClient.UnsafeDeleteAttribute(ctx, req.GetId())
	// if err != nil {
	// 	return nil, db.StatusifyError(err, db.ErrTextDeleteFailed, slog.String("id", req.GetId()))
	// }

	return &unsafe.DeleteAttributeResponse{
		Attribute: &policy.Attribute{
			Id: req.GetId(), // stubbed
		},
	}, nil
}

//
// Unsafe Attribute Value RPCs
//

func (s *UnsafeService) UpdateAttributeValue(ctx context.Context, req *unsafe.UpdateAttributeValueRequest) (*unsafe.UpdateAttributeValueResponse, error) {
	rsp := &unsafe.UpdateAttributeValueResponse{}
	_, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	item, err := s.dbClient.UnsafeUpdateAttributeValue(ctx, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()), slog.String("attribute_value", req.String()))
	}

	rsp.Value = item
	return rsp, nil
}

func (s *UnsafeService) ReactivateAttributeValue(ctx context.Context, req *unsafe.ReactivateAttributeValueRequest) (*unsafe.ReactivateAttributeValueResponse, error) {
	rsp := &unsafe.ReactivateAttributeValueResponse{}

	_, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	item, err := s.dbClient.UnsafeReactivateAttributeValue(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextUpdateFailed, slog.String("id", req.GetId()))
	}

	rsp.Value = item
	return rsp, nil
}

func (s *UnsafeService) DeleteAttributeValue(ctx context.Context, req *unsafe.DeleteAttributeValueRequest) (*unsafe.DeleteAttributeValueResponse, error) {
	rsp := &unsafe.DeleteAttributeValueResponse{}
	existing, err := s.dbClient.GetAttributeValue(ctx, req.GetId())
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextGetRetrievalFailed, slog.String("id", req.GetId()))
	}

	deleted, err := s.dbClient.UnsafeDeleteAttributeValue(ctx, existing, req)
	if err != nil {
		return nil, db.StatusifyError(err, db.ErrTextDeletionFailed, slog.String("id", req.GetId()))
	}

	rsp.Value = deleted
	return rsp, nil
}
