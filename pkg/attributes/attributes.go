package attributes

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
)

type attributesServer struct {
	attributesv1.UnimplementedAttributesServiceServer
	dbClient *db.Client
}

func NewAttributesServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) {
	as := &attributesServer{
		dbClient: dbClient,
	}
	attributesv1.RegisterAttributesServiceServer(g, as)
	attributesv1.RegisterAttributesServiceHandlerServer(context.Background(), s, as)
}

func (s *attributesServer) CreateAttribute(ctx context.Context, req *attributesv1.CreateAttributeRequest) (*attributesv1.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Definition.Name))
	var (
		resp = &attributesv1.CreateAttributeResponse{}
		err  error
	)

	// Need to figure out how to handle group by
	args := pgx.NamedArgs{
		"name": req.Definition.Name,
		"rule": req.Definition.Rule,
		// "description":  req.Definition.D,
		"values":       req.Definition.Values,
		"groupByAttr":  nil,
		"groupByAttrV": nil,
	}
	_, err = s.dbClient.Exec(context.TODO(), `
	INSERT INTO opentdf.attribute (
		rule,
		name,
		values_array,
		group_by_attr,
		group_by_attrval
	)
	VALUES (
		@rule,
		@name,
		@values,
		@groupByAttr,
		@groupByAttrVal
	)
	`, args)
	if err != nil {
		slog.Error("error creating attribute", slog.String("error", err.Error()))
		return resp, err
	}
	slog.Debug("created new attribute definition", slog.String("name", req.Definition.Name))

	return resp, err
}

func (s *attributesServer) GetAttribute(ctx context.Context, req *attributesv1.GetAttributeRequest) (*attributesv1.GetAttributeResponse, error) {
	return nil, nil
}

func (s *attributesServer) UpdateAttribute(ctx context.Context, req *attributesv1.UpdateAttributeRequest) (*attributesv1.UpdateAttributeResponse, error) {
	return nil, nil
}

func (s *attributesServer) DeleteAttribute(ctx context.Context, req *attributesv1.DeleteAttributeRequest) (*attributesv1.DeleteAttributeResponse, error) {
	return nil, nil
}
