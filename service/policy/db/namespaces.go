package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/pkg/db"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func (c PolicyDBClient) GetNamespace(ctx context.Context, identifier any) (*policy.Namespace, error) {
	var (
		ns     getNamespaceRow
		err    error
		params getNamespaceParams
	)

	switch i := identifier.(type) {
	case *namespaces.GetNamespaceRequest_NamespaceId:
		id := pgtypeUUID(i.NamespaceId)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getNamespaceParams{ID: id}
	case *namespaces.GetNamespaceRequest_Fqn:
		params = getNamespaceParams{Name: pgtypeText(i.Fqn)}
	case string:
		id := pgtypeUUID(i)
		if !id.Valid {
			return nil, db.ErrUUIDInvalid
		}
		params = getNamespaceParams{ID: id}
	default:
		// unexpected type
		return nil, errors.Join(db.ErrUnknownSelectIdentifier, fmt.Errorf("type [%T] value [%v]", i, i))
	}

	ns, err = c.queries.getNamespace(ctx, params)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(ns.Metadata, metadata); err != nil {
		return nil, err
	}

	var grants []*policy.KeyAccessServer
	if ns.Grants != nil {
		grants, err = db.KeyAccessServerProtoJSON(ns.Grants)
		if err != nil {
			c.logger.Error("could not unmarshal grants", slog.String("error", err.Error()))
			return nil, err
		}
	}

	var keys []*policy.SimpleKasKey
	if len(ns.Keys) > 0 {
		keys, err = db.SimpleKasKeysProtoJSON(ns.Keys)
		if err != nil {
			c.logger.ErrorContext(ctx, "could not unmarshal keys", slog.String("error", err.Error()))
			return nil, err
		}
	}

	var certs []*policy.Certificate
	if len(ns.Certs) > 0 {
		certs, err = db.CertificatesProtoJSON(ns.Certs)
		if err != nil {
			c.logger.ErrorContext(ctx, "could not unmarshal certificates", slog.String("error", err.Error()))
			return nil, err
		}
	}

	return &policy.Namespace{
		Id:        ns.ID,
		Name:      ns.Name,
		Active:    &wrapperspb.BoolValue{Value: ns.Active},
		Grants:    grants,
		Metadata:  metadata,
		Fqn:       ns.Fqn.String,
		KasKeys:   keys,
		RootCerts: certs,
	}, nil
}

func (c PolicyDBClient) ListNamespaces(ctx context.Context, r *namespaces.ListNamespacesRequest) (*namespaces.ListNamespacesResponse, error) {
	limit, offset := c.getRequestedLimitOffset(r.GetPagination())

	maxLimit := c.listCfg.limitMax
	if maxLimit > 0 && limit > maxLimit {
		return nil, db.ErrListLimitTooLarge
	}

	active := pgtype.Bool{
		Valid: false,
	}
	state := getDBStateTypeTransformedEnum(r.GetState())
	if state != stateAny {
		active = pgtypeBool(state == stateActive)
	}

	list, err := c.queries.listNamespaces(ctx, listNamespacesParams{
		Active: active,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	nsList := make([]*policy.Namespace, len(list))

	for i, ns := range list {
		metadata := &common.Metadata{}
		if err = unmarshalMetadata(ns.Metadata, metadata); err != nil {
			return nil, err
		}

		nsList[i] = &policy.Namespace{
			Id:       ns.ID,
			Name:     ns.Name,
			Active:   &wrapperspb.BoolValue{Value: ns.Active},
			Metadata: metadata,
			Fqn:      ns.Fqn.String,
		}
	}

	var total int32
	var nextOffset int32
	if len(list) > 0 {
		total = int32(list[0].Total)
		nextOffset = getNextOffset(offset, limit, total)
	}

	return &namespaces.ListNamespacesResponse{
		Namespaces: nsList,
		Pagination: &policy.PageResponse{
			CurrentOffset: offset,
			Total:         total,
			NextOffset:    nextOffset,
		},
	}, nil
}

// Loads all namespaces into memory by making iterative db roundtrip requests of defaultObjectListAllLimit size
func (c PolicyDBClient) ListAllNamespaces(ctx context.Context) ([]*policy.Namespace, error) {
	var nextOffset int32
	nsList := make([]*policy.Namespace, 0)

	for {
		listed, err := c.ListNamespaces(ctx, &namespaces.ListNamespacesRequest{
			State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			Pagination: &policy.PageRequest{
				Limit:  c.listCfg.limitMax,
				Offset: nextOffset,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list all namespaces: %w", err)
		}

		nextOffset = listed.GetPagination().GetNextOffset()
		nsList = append(nsList, listed.GetNamespaces()...)

		// offset becomes zero when list is exhausted
		if nextOffset <= 0 {
			break
		}
	}
	return nsList, nil
}

func (c PolicyDBClient) CreateNamespace(ctx context.Context, r *namespaces.CreateNamespaceRequest) (*policy.Namespace, error) {
	name := strings.ToLower(r.GetName())
	metadataJSON, _, err := db.MarshalCreateMetadata(r.GetMetadata())
	if err != nil {
		return nil, err
	}

	createdID, err := c.queries.createNamespace(ctx, createNamespaceParams{
		Name:     name,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	// Update FQN
	_, err = c.queries.upsertAttributeNamespaceFqn(ctx, createdID)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetNamespace(ctx, createdID)
}

func (c PolicyDBClient) UpdateNamespace(ctx context.Context, id string, r *namespaces.UpdateNamespaceRequest) (*policy.Namespace, error) {
	// if extend we need to merge the metadata
	metadataJSON, metadata, err := db.MarshalUpdateMetadata(r.GetMetadata(), r.GetMetadataUpdateBehavior(), func() (*common.Metadata, error) {
		n, err := c.GetNamespace(ctx, id)
		if err != nil {
			return nil, err
		}
		if n.GetMetadata() == nil {
			return nil, nil //nolint:nilnil // no metadata does not mean no error
		}
		return n.GetMetadata(), nil
	})
	if err != nil {
		return nil, err
	}

	count, err := c.queries.updateNamespace(ctx, updateNamespaceParams{
		ID:       id,
		Metadata: metadataJSON,
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Namespace{
		Id:       id,
		Metadata: metadata,
	}, nil
}

/*
UNSAFE OPERATIONS
*/
func (c PolicyDBClient) UnsafeUpdateNamespace(ctx context.Context, id string, name string) (*policy.Namespace, error) {
	name = strings.ToLower(name)

	count, err := c.queries.updateNamespace(ctx, updateNamespaceParams{
		ID:   id,
		Name: pgtypeText(name),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	// Update all FQNs that may contain the namespace name
	_, err = c.queries.upsertAttributeNamespaceFqn(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	return c.GetNamespace(ctx, id)
}

func (c PolicyDBClient) DeactivateNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	attrs, err := c.GetAttributesByNamespace(ctx, id)
	if err != nil {
		return nil, err
	}

	allAttrsDeactivated := true
	for _, attr := range attrs {
		if attr.GetActive().GetValue() {
			allAttrsDeactivated = false
			break
		}
	}

	if !allAttrsDeactivated {
		c.logger.Warn("deactivating the namespace with existing attributes can affect access to related data. Please be aware and proceed accordingly.")
	}

	count, err := c.queries.updateNamespace(ctx, updateNamespaceParams{
		ID:     id,
		Active: pgtypeBool(false),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Namespace{
		Id:     id,
		Active: &wrapperspb.BoolValue{Value: false},
	}, nil
}

func (c PolicyDBClient) UnsafeReactivateNamespace(ctx context.Context, id string) (*policy.Namespace, error) {
	attrs, err := c.GetAttributesByNamespace(ctx, id)
	if err != nil {
		return nil, err
	}

	if len(attrs) > 0 {
		c.logger.Warn("reactivating the namespace with existing attributes can affect access to related data. Please be aware and proceed accordingly.")
	}

	count, err := c.queries.updateNamespace(ctx, updateNamespaceParams{
		ID:     id,
		Active: pgtypeBool(true),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Namespace{
		Id:     id,
		Active: &wrapperspb.BoolValue{Value: true},
	}, nil
}

func (c PolicyDBClient) UnsafeDeleteNamespace(ctx context.Context, existing *policy.Namespace, fqn string) (*policy.Namespace, error) {
	if existing == nil {
		return nil, fmt.Errorf("namespace not found: %w", db.ErrNotFound)
	}

	if existing.GetFqn() != fqn {
		return nil, fmt.Errorf("fqn mismatch: %w", db.ErrNotFound)
	}

	id := existing.GetId()

	count, err := c.queries.deleteNamespace(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return &policy.Namespace{
		Id: id,
	}, nil
}

func (c PolicyDBClient) RemoveKeyAccessServerFromNamespace(ctx context.Context, k *namespaces.NamespaceKeyAccessServer) (*namespaces.NamespaceKeyAccessServer, error) {
	count, err := c.queries.removeKeyAccessServerFromNamespace(ctx, removeKeyAccessServerFromNamespaceParams{
		NamespaceID:       k.GetNamespaceId(),
		KeyAccessServerID: k.GetKeyAccessServerId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}

	return k, nil
}

func (c PolicyDBClient) AssignPublicKeyToNamespace(ctx context.Context, k *namespaces.NamespaceKey) (*namespaces.NamespaceKey, error) {
	if err := c.verifyKeyIsActive(ctx, k.GetKeyId()); err != nil {
		return nil, err
	}

	key, err := c.queries.assignPublicKeyToNamespace(ctx, assignPublicKeyToNamespaceParams{
		NamespaceID:          k.GetNamespaceId(),
		KeyAccessServerKeyID: k.GetKeyId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	return &namespaces.NamespaceKey{
		NamespaceId: key.NamespaceID,
		KeyId:       key.KeyAccessServerKeyID,
	}, nil
}

func (c PolicyDBClient) RemovePublicKeyFromNamespace(ctx context.Context, k *namespaces.NamespaceKey) (*namespaces.NamespaceKey, error) {
	count, err := c.queries.removePublicKeyFromNamespace(ctx, removePublicKeyFromNamespaceParams{
		NamespaceID:          k.GetNamespaceId(),
		KeyAccessServerKeyID: k.GetKeyId(),
	})
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return nil, db.ErrNotFound
	}
	return &namespaces.NamespaceKey{
		NamespaceId: k.GetNamespaceId(),
		KeyId:       k.GetKeyId(),
	}, nil
}

// CreateCertificate creates a new certificate in the database
func (c PolicyDBClient) CreateCertificate(ctx context.Context, x5c string, isRoot bool, metadata []byte) (string, error) {
	certID, err := c.queries.createCertificate(ctx, createCertificateParams{
		X5c:      x5c,
		IsRoot:   pgtype.Bool{Bool: isRoot, Valid: true},
		Metadata: metadata,
	})
	if err != nil {
		return "", db.WrapIfKnownInvalidQueryErr(err)
	}
	return certID, nil
}

// GetCertificate retrieves a certificate by ID
func (c PolicyDBClient) GetCertificate(ctx context.Context, id string) (*policy.Certificate, error) {
	cert, err := c.queries.getCertificate(ctx, id)
	if err != nil {
		return nil, db.WrapIfKnownInvalidQueryErr(err)
	}

	metadata := &common.Metadata{}
	if err = unmarshalMetadata(cert.Metadata, metadata); err != nil {
		return nil, err
	}

	return &policy.Certificate{
		Id:  cert.ID,
		X5C: cert.X5c,
	}, nil
}

// DeleteCertificate removes a certificate from the database
func (c PolicyDBClient) DeleteCertificate(ctx context.Context, id string) error {
	count, err := c.queries.deleteCertificate(ctx, id)
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return db.ErrNotFound
	}
	return nil
}

// resolveNamespaceID resolves a namespace identifier to its UUID
func (c PolicyDBClient) resolveNamespaceID(ctx context.Context, identifier *common.IdFqnIdentifier) (string, error) {
	// If ID is provided, use it directly
	if identifier.GetId() != "" {
		return identifier.GetId(), nil
	}

	// If FQN is provided, look up the namespace by FQN to get its ID
	if identifier.GetFqn() != "" {
		ns, err := c.GetNamespace(ctx, identifier.GetFqn())
		if err != nil {
			return "", err
		}
		return ns.GetId(), nil
	}

	return "", fmt.Errorf("namespace identifier must have either id or fqn: %w", db.ErrNotFound)
}

// AssignCertificateToNamespace assigns a certificate to a namespace
func (c PolicyDBClient) AssignCertificateToNamespace(ctx context.Context, namespaceIdentifier *common.IdFqnIdentifier, certificateID string) error {
	namespaceID, err := c.resolveNamespaceID(ctx, namespaceIdentifier)
	if err != nil {
		return err
	}

	_, err = c.queries.assignCertificateToNamespace(ctx, assignCertificateToNamespaceParams{
		NamespaceID:   namespaceID,
		CertificateID: certificateID,
	})
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	return nil
}

// CreateAndAssignCertificateToNamespace creates a certificate and assigns it to a namespace in a transaction
func (c PolicyDBClient) CreateAndAssignCertificateToNamespace(ctx context.Context, namespaceID *common.IdFqnIdentifier, x5c string, isRoot bool, metadata []byte) (string, error) {
	var certID string
	err := c.RunInTx(ctx, func(txClient *PolicyDBClient) error {
		var err error
		certID, err = txClient.CreateCertificate(ctx, x5c, isRoot, metadata)
		if err != nil {
			return err
		}

		err = txClient.AssignCertificateToNamespace(ctx, namespaceID, certID)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return "", err
	}
	return certID, nil
}

// RemoveCertificateFromNamespace removes a certificate from a namespace
func (c PolicyDBClient) RemoveCertificateFromNamespace(ctx context.Context, namespaceIdentifier *common.IdFqnIdentifier, certificateID string) error {
	namespaceID, err := c.resolveNamespaceID(ctx, namespaceIdentifier)
	if err != nil {
		return err
	}

	count, err := c.queries.removeCertificateFromNamespace(ctx, removeCertificateFromNamespaceParams{
		NamespaceID:   namespaceID,
		CertificateID: certificateID,
	})
	if err != nil {
		return db.WrapIfKnownInvalidQueryErr(err)
	}
	if count == 0 {
		return db.ErrNotFound
	}
	return nil
}
