package attributes

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
)

const (
	policyType = "attribute"
)

type attributesServer struct {
	attributesv1.UnimplementedAttributesServiceServer
	dbClient *db.Client
}

func NewAttributesServer(dbClient *db.Client, g *grpc.Server, s *runtime.ServeMux) error {
	as := &attributesServer{
		dbClient: dbClient,
	}
	attributesv1.RegisterAttributesServiceServer(g, as)
	err := attributesv1.RegisterAttributesServiceHandlerServer(context.Background(), s, as)
	return err
}

func (s *attributesServer) CreateAttribute(ctx context.Context, req *attributesv1.CreateAttributeRequest) (*attributesv1.CreateAttributeResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.Definition.Name))
	var (
		resp = &attributesv1.CreateAttributeResponse{}
		err  error
	)
	jsonAttr, err := json.Marshal(req.Definition)
	if err != nil {
		return resp, err
	}

	// Need to figure out how to handle group by
	args := pgx.NamedArgs{
		"namespace":   req.Definition.Descriptor_.Namespace,
		"version":     req.Definition.Descriptor_.Version,
		"fqn":         req.Definition.Descriptor_.Fqn,
		"label":       req.Definition.Descriptor_.Label,
		"description": req.Definition.Descriptor_.Description,
		"policytype":  policyType,
		"resource":    jsonAttr,
	}
	_, err = s.dbClient.Exec(context.TODO(), `
	INSERT INTO opentdf.resources (
		namespace,
		version,
		fqn,
		label,
		description,
		policytype,
		resource
	)
	VALUES (
		@namespace,
		@version,
		@fqn,
		@label,
		@description,
		@policytype,
		@resource
	)
	`, args)
	if err != nil {
		slog.Error("error creating attribute", slog.String("error", err.Error()))
		return resp, err
	}
	slog.Debug("created new attribute definition", slog.String("name", req.Definition.Name))

	return resp, err
}

func (s *attributesServer) ListAttributes(ctx context.Context, req *attributesv1.ListAttributesRequest) (*attributesv1.ListAttributesResponse, error) {
	attributes := &attributesv1.ListAttributesResponse{}
	args := pgx.NamedArgs{
		"policytype": policyType,
	}
	rows, err := s.dbClient.Query(context.TODO(), `
		SELECT
		  resource
		FROM opentdf.resources
		WHERE policytype = @policytype
	`, args)
	if err != nil {
		slog.Error("error listing attributes", slog.String("error", err.Error()))
		return attributes, err
	}
	defer rows.Close()

	for rows.Next() {
		var definition = new(attributesv1.AttributeDefinition)
		// var tmpDefinition []byte
		err = rows.Scan(&definition)
		if err != nil {
			slog.Error("error listing attributes", slog.String("error", err.Error()))
			return attributes, err
		}
		attributes.Definitions = append(attributes.Definitions, definition)
	}

	// We would need to keep column names in sync with the struct field names or retag the struct fields with protoc plugin
	// definitions, err := pgx.CollectRows(rows, pgx.RowToStructByName[attributesv1.AttributeDefinition])

	return attributes, nil
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
