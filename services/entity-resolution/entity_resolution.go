package entity_resolution

import (
	"context"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	entity_resolution "github.com/opentdf/opentdf-v2-poc/sdk/entity-resolution"
	"log/slog"
)

type EntityService struct {
	entity_resolution.UnimplementedEntityResolutionServiceServer
	dbClient *db.Client
}

func (s EntityService) EntityResolution(ctx context.Context,
	req *entity_resolution.EntityResolutionRequest) (*entity_resolution.EntityResolutionResponse, error) {
	slog.Debug("creating new attribute definition", slog.String("name", req.EntityIdentifiers.Type))

	return &entity_resolution.EntityResolutionResponse{}, nil
}
