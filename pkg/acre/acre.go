package acre

import (
	"context"
	"errors"
	"log/slog"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/jackc/pgx/v5"
	acrev1 "github.com/opentdf/opentdf-v2-poc/gen/acre/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ResourceEncoding struct {
	acrev1.UnimplementedResourcEncodingServiceServer
	dbClient *db.Client
}

func NewResourceEncoding(dbClient *db.Client, grpcServer *grpc.Server, mux *runtime.ServeMux) error {
	as := &ResourceEncoding{
		dbClient: dbClient,
	}
	acrev1.RegisterResourcEncodingServiceServer(grpcServer, as)
	err := acrev1.RegisterResourcEncodingServiceHandlerServer(context.Background(), mux, as)
	return err
}

/*
	Resource Mappings
*/

func (s ResourceEncoding) CreateResourceMapping(ctx context.Context, req *acrev1.CreateResourceMappingRequest) (*acrev1.CreateResourceMappingResponse, error) {
	slog.Debug("creating resource mapping")
	var (
		err error
	)

	// Set the version of the resource to 1 on create
	req.Mapping.Descriptor_.Version = 1

	err = s.dbClient.CreateResource(req.Mapping.Descriptor_, req.Mapping)
	if err != nil {
		slog.Error("issue creating resource mapping", slog.String("error", err.Error()))
		return &acrev1.CreateResourceMappingResponse{}, status.Error(codes.Internal, err.Error())
	}

	return &acrev1.CreateResourceMappingResponse{}, nil
}

func (s ResourceEncoding) ListResourceMappings(ctx context.Context, req *acrev1.ListResourceMappingsRequest) (*acrev1.ListResourceMappingsResponse, error) {
	mappings := &acrev1.ListResourceMappingsResponse{}

	rows, err := s.dbClient.ListResources(
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error("issue listing resource mappings", slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id      int32
			mapping = new(acrev1.ResourceMapping)
		)
		err = rows.Scan(&id, &mapping)
		if err != nil {
			slog.Error("issue listing resource mappings", slog.String("error", err.Error()))
			return mappings, status.Error(codes.Internal, err.Error())
		}

		mapping.Descriptor_.Id = id
		mappings.Mappings = append(mappings.Mappings, mapping)
	}

	if err := rows.Err(); err != nil {
		slog.Error("issue listing resource mappings", slog.String("error", err.Error()))
		return mappings, status.Error(codes.Internal, err.Error())
	}

	return mappings, nil
}

func (s ResourceEncoding) GetResourceMapping(ctx context.Context,
	req *acrev1.GetResourceMappingRequest) (*acrev1.GetResourceMappingResponse, error) {
	var (
		mapping = &acrev1.GetResourceMappingResponse{
			Mapping: new(acrev1.ResourceMapping),
		}
		err error
		id  int32
	)

	row := s.dbClient.GetResource(
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
	)

	err = row.Scan(&id, &mapping.Mapping)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("resource mapping not found", slog.Int("id", int(req.Id)))
			return mapping, status.Error(codes.NotFound, "resource mapping not found")
		}
		slog.Error("issue getting resource mapping", slog.String("error", err.Error()))
		return mapping, status.Error(codes.Internal, err.Error())
	}
	mapping.Mapping.Descriptor_.Id = id

	return mapping, nil
}

func (s ResourceEncoding) UpdateResourceMapping(ctx context.Context, req *acrev1.UpdateResourceMappingRequest) (*acrev1.UpdateResourceMappingResponse, error) {
	err := s.dbClient.UpdateResource(
		req.Mapping.Descriptor_,
		req.Mapping,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
	)
	if err != nil {
		slog.Error("issue updating mapping", slog.String("error", err.Error()))
		return &acrev1.UpdateResourceMappingResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acrev1.UpdateResourceMappingResponse{}, nil
}

func (s ResourceEncoding) DeleteResourceMapping(ctx context.Context, req *acrev1.DeleteResourceMappingRequest) (*acrev1.DeleteResourceMappingResponse, error) {
	if err := s.dbClient.DeleteResource(
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
	); err != nil {
		slog.Error("issue deleting resource mapping", slog.String("error", err.Error()))
		return &acrev1.DeleteResourceMappingResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acrev1.DeleteResourceMappingResponse{}, nil
}

/*
 Resource Groups
*/

func (s ResourceEncoding) CreateResourceGroup(ctx context.Context, req *acrev1.CreateResourceGroupRequest) (*acrev1.CreateResourceGroupResponse, error) {
	slog.Debug("creating resource group")
	var (
		err error
	)

	// Set the version of the resource to 1 on create
	req.Group.Descriptor_.Version = 1

	err = s.dbClient.CreateResource(req.Group.Descriptor_, req.Group)
	if err != nil {
		slog.Error("issue creating resource group", slog.String("error", err.Error()))
		return &acrev1.CreateResourceGroupResponse{}, status.Error(codes.Internal, err.Error())
	}

	return &acrev1.CreateResourceGroupResponse{}, nil
}

func (s ResourceEncoding) ListResourceGroups(ctx context.Context, req *acrev1.ListResourceGroupsRequest) (*acrev1.ListResourceGroupsResponse, error) {
	groups := &acrev1.ListResourceGroupsResponse{}

	rows, err := s.dbClient.ListResources(
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
		req.Selector,
	)
	if err != nil {
		slog.Error("issue listing resource groups", slog.String("error", err.Error()))
		return groups, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id    int32
			group = new(acrev1.ResourceGroup)
		)
		// var tmpDefinition []byte
		err = rows.Scan(&id, &group)
		if err != nil {
			slog.Error("issue listing resource groups", slog.String("error", err.Error()))
			return groups, status.Error(codes.Internal, err.Error())
		}
		group.Descriptor_.Id = id
		groups.Groups = append(groups.Groups, group)
	}

	if err := rows.Err(); err != nil {
		slog.Error("issue listing resource groups", slog.String("error", err.Error()))
		return groups, status.Error(codes.Internal, err.Error())
	}

	return groups, nil
}

func (s ResourceEncoding) GetResourceGroup(ctx context.Context, req *acrev1.GetResourceGroupRequest) (*acrev1.GetResourceGroupResponse, error) {
	var (
		group = &acrev1.GetResourceGroupResponse{
			Group: new(acrev1.ResourceGroup),
		}
		err error
		id  int32
	)

	row := s.dbClient.GetResource(
		req.Id, commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
	)

	err = row.Scan(&id, &group.Group)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("resource group not found", slog.Int("id", int(req.Id)))
			return group, status.Error(codes.NotFound, "resource group not found")
		}
		slog.Error("issue getting resource group", slog.String("error", err.Error()))
		return group, status.Error(codes.Internal, err.Error())
	}

	group.Group.Descriptor_.Id = id

	return group, nil
}

func (s ResourceEncoding) UpdateResourceGroup(ctx context.Context, req *acrev1.UpdateResourceGroupRequest) (*acrev1.UpdateResourceGroupResponse, error) {
	err := s.dbClient.UpdateResource(
		req.Group.Descriptor_, req.Group,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
	)
	if err != nil {
		slog.Error("issue updating group", slog.String("error", err.Error()))
		return &acrev1.UpdateResourceGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acrev1.UpdateResourceGroupResponse{}, nil
}

func (s ResourceEncoding) DeleteResourceGroup(ctx context.Context, req *acrev1.DeleteResourceGroupRequest) (*acrev1.DeleteResourceGroupResponse, error) {
	if err := s.dbClient.DeleteResource(
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
	); err != nil {
		slog.Error("issue deleting resource group", slog.String("error", err.Error()))
		return &acrev1.DeleteResourceGroupResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acrev1.DeleteResourceGroupResponse{}, nil
}

/*
	Synonyms
*/

func (s ResourceEncoding) CreateResourceSynonym(ctx context.Context, req *acrev1.CreateResourceSynonymRequest) (*acrev1.CreateResourceSynonymResponse, error) {
	slog.Debug("creating resource synonym")
	var (
		err error
	)

	// Set the version of the resource to 1 on create
	req.Synonym.Descriptor_.Version = 1

	err = s.dbClient.CreateResource(req.Synonym.Descriptor_, req.Synonym)
	if err != nil {
		slog.Error("issue creating resource group", slog.String("error", err.Error()))
		return &acrev1.CreateResourceSynonymResponse{}, status.Error(codes.Internal, err.Error())
	}

	return &acrev1.CreateResourceSynonymResponse{}, nil
}

func (s ResourceEncoding) ListResourceSynonyms(ctx context.Context, req *acrev1.ListResourceSynonymsRequest) (*acrev1.ListResourceSynonymsResponse, error) {
	synonyms := &acrev1.ListResourceSynonymsResponse{}

	rows, err := s.dbClient.ListResources(
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
		req.Selector)
	if err != nil {
		slog.Error("issue listing resource synonyms", slog.String("error", err.Error()))
		return synonyms, status.Error(codes.Internal, err.Error())
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id      int32
			synonym = new(acrev1.Synonyms)
		)
		err = rows.Scan(&id, &synonym)
		if err != nil {
			slog.Error("issue listing resource synonyms", slog.String("error", err.Error()))
			return synonyms, status.Error(codes.Internal, err.Error())
		}
		synonym.Descriptor_.Id = id
		synonyms.Synonyms = append(synonyms.Synonyms, synonym)
	}

	if err := rows.Err(); err != nil {
		slog.Error("issue listing resource synonyms", slog.String("error", err.Error()))
		return synonyms, status.Error(codes.Internal, err.Error())
	}

	return synonyms, nil
}

func (s ResourceEncoding) GetResourceSynonym(ctx context.Context, req *acrev1.GetResourceSynonymRequest) (*acrev1.GetResourceSynonymResponse, error) {
	var (
		synonym = &acrev1.GetResourceSynonymResponse{
			Synonym: new(acrev1.Synonyms),
		}
		err error
		id  int32
	)

	row := s.dbClient.GetResource(
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
	)

	err = row.Scan(&id, &synonym.Synonym)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			slog.Info("resource synonym not found", slog.Int("id", int(req.Id)))
			return synonym, status.Error(codes.NotFound, "resource synonym not found")
		}
		slog.Error("issue getting resource synonym", slog.String("error", err.Error()))
		return synonym, status.Error(codes.Internal, err.Error())
	}

	synonym.Synonym.Descriptor_.Id = id

	return synonym, nil
}

func (s ResourceEncoding) UpdateResourceSynonym(ctx context.Context, req *acrev1.UpdateResourceSynonymRequest) (*acrev1.UpdateResourceSynonymResponse, error) {
	err := s.dbClient.UpdateResource(
		req.Synonym.Descriptor_,
		req.Synonym,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
	)
	if err != nil {
		slog.Error("issue updating synonym", slog.String("error", err.Error()))
		return &acrev1.UpdateResourceSynonymResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acrev1.UpdateResourceSynonymResponse{}, nil
}

func (s ResourceEncoding) DeleteResourceSynonym(ctx context.Context, req *acrev1.DeleteResourceSynonymRequest) (*acrev1.DeleteResourceSynonymResponse, error) {
	//TODO: Need to check if resource exists before deleting
	if err := s.dbClient.DeleteResource(
		req.Id,
		commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
	); err != nil {
		slog.Error("issue deleting resource synonym", slog.String("error", err.Error()))
		return &acrev1.DeleteResourceSynonymResponse{}, status.Error(codes.Internal, err.Error())
	}
	return &acrev1.DeleteResourceSynonymResponse{}, nil
}
