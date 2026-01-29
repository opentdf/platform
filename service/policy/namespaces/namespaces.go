package namespaces

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/namespaces/namespacesconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	policyconfig "github.com/opentdf/platform/service/policy/config"
	policydb "github.com/opentdf/platform/service/policy/db"
)

type NamespacesService struct { //nolint:revive // NamespacesService is a valid name
	dbClient policydb.PolicyDBClient
	logger   *logger.Logger
	config   *policyconfig.Config
}

func OnConfigUpdate(ns *NamespacesService) serviceregistry.OnConfigUpdateHook {
	return func(_ context.Context, cfg config.ServiceConfig) error {
		sharedCfg, err := policyconfig.GetSharedPolicyConfig(cfg)
		if err != nil {
			return fmt.Errorf("failed to get shared policy config: %w", err)
		}
		ns.config = sharedCfg
		ns.dbClient = policydb.NewClient(ns.dbClient.Client, ns.logger, int32(sharedCfg.ListRequestLimitMax), int32(sharedCfg.ListRequestLimitDefault))

		ns.logger.Info("namespace service config reloaded")

		return nil
	}
}

func NewRegistration(ns string, dbRegister serviceregistry.DBRegister) *serviceregistry.Service[namespacesconnect.NamespaceServiceHandler] {
	nsService := new(NamespacesService)
	onUpdateConfigHook := OnConfigUpdate(nsService)

	return &serviceregistry.Service[namespacesconnect.NamespaceServiceHandler]{
		Close: nsService.Close,
		ServiceOptions: serviceregistry.ServiceOptions[namespacesconnect.NamespaceServiceHandler]{
			Namespace:      ns,
			DB:             dbRegister,
			ServiceDesc:    &namespaces.NamespaceService_ServiceDesc,
			ConnectRPCFunc: namespacesconnect.NewNamespaceServiceHandler,
			OnConfigUpdate: onUpdateConfigHook,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (namespacesconnect.NamespaceServiceHandler, serviceregistry.HandlerServer) {
				logger := srp.Logger
				cfg, err := policyconfig.GetSharedPolicyConfig(srp.Config)
				if err != nil {
					logger.Error("error getting namespaces service policy config", slog.String("error", err.Error()))
					panic(err)
				}

				nsService.logger = logger
				nsService.dbClient = policydb.NewClient(srp.DBClient, logger, int32(cfg.ListRequestLimitMax), int32(cfg.ListRequestLimitDefault))
				nsService.config = cfg

				return nsService, nil
			},
		},
	}
}

// IsReady checks if the service is ready to serve requests.
// Without a database connection, the service is not ready.
func (ns NamespacesService) IsReady(ctx context.Context) error {
	ns.logger.TraceContext(ctx, "checking readiness of namespaces service")
	if err := ns.dbClient.PingContext(ctx); err != nil {
		return err
	}

	return nil
}

// Close gracefully shuts down the service, closing the database client.
func (ns *NamespacesService) Close() {
	ns.logger.Info("gracefully shutting down namespaces service")
	ns.dbClient.Close()
}

func (ns NamespacesService) ListNamespaces(ctx context.Context, req *connect.Request[namespaces.ListNamespacesRequest]) (*connect.Response[namespaces.ListNamespacesResponse], error) {
	state := req.Msg.GetState().String()
	ns.logger.DebugContext(ctx, "listing namespaces", slog.String("state", state))

	rsp, err := ns.dbClient.ListNamespaces(ctx, req.Msg)
	if err != nil {
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextListRetrievalFailed)
	}

	ns.logger.DebugContext(ctx, "listed namespaces")

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) GetNamespace(ctx context.Context, req *connect.Request[namespaces.GetNamespaceRequest]) (*connect.Response[namespaces.GetNamespaceResponse], error) {
	rsp := &namespaces.GetNamespaceResponse{}

	var identifier any

	if req.Msg.GetId() != "" { //nolint:staticcheck // Id can still be used until removed
		identifier = req.Msg.GetId() //nolint:staticcheck // Id can still be used until removed
	} else {
		identifier = req.Msg.GetIdentifier()
	}

	ns.logger.DebugContext(ctx, "getting namespace", slog.Any("id", identifier))

	namespace, err := ns.dbClient.GetNamespace(ctx, identifier)
	if err != nil {
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextGetRetrievalFailed, slog.Any("id", identifier))
	}

	rsp.Namespace = namespace

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) CreateNamespace(ctx context.Context, req *connect.Request[namespaces.CreateNamespaceRequest]) (*connect.Response[namespaces.CreateNamespaceResponse], error) {
	ns.logger.DebugContext(ctx, "creating new namespace", slog.String("name", req.Msg.GetName()))
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeNamespace,
	}
	rsp := &namespaces.CreateNamespaceResponse{}

	err := ns.dbClient.RunInTx(ctx, func(txClient *policydb.PolicyDBClient) error {
		n, err := txClient.CreateNamespace(ctx, req.Msg)
		if err != nil {
			ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
			return err
		}

		auditParams.ObjectID = n.GetId()
		auditParams.Original = n
		ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

		ns.logger.DebugContext(ctx, "created new namespace", slog.String("name", req.Msg.GetName()))
		rsp.Namespace = n

		return nil
	})
	if err != nil {
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextCreationFailed, slog.String("namespace", req.Msg.String()))
	}

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) UpdateNamespace(ctx context.Context, req *connect.Request[namespaces.UpdateNamespaceRequest]) (*connect.Response[namespaces.UpdateNamespaceResponse], error) {
	namespaceID := req.Msg.GetId()
	ns.logger.DebugContext(ctx, "updating namespace", slog.String("name", namespaceID))
	rsp := &namespaces.UpdateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   namespaceID,
	}

	original, err := ns.dbClient.GetNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", namespaceID))
	}

	updated, err := ns.dbClient.UpdateNamespace(ctx, namespaceID, req.Msg)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextUpdateFailed, slog.String("id", namespaceID))
	}

	auditParams.Original = original
	auditParams.Updated = updated

	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	ns.logger.DebugContext(ctx, "updated namespace", slog.String("id", namespaceID))

	rsp.Namespace = &policy.Namespace{
		Id: namespaceID,
	}
	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) DeactivateNamespace(ctx context.Context, req *connect.Request[namespaces.DeactivateNamespaceRequest]) (*connect.Response[namespaces.DeactivateNamespaceResponse], error) {
	namespaceID := req.Msg.GetId()

	ns.logger.DebugContext(ctx, "deactivating namespace", slog.String("id", namespaceID))
	rsp := &namespaces.DeactivateNamespaceResponse{}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeUpdate,
		ObjectType: audit.ObjectTypeNamespace,
		ObjectID:   namespaceID,
	}

	original, err := ns.dbClient.GetNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextGetRetrievalFailed, slog.String("id", namespaceID))
	}

	updated, err := ns.dbClient.DeactivateNamespace(ctx, namespaceID)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextDeletionFailed, slog.String("id", namespaceID))
	}

	auditParams.Original = original
	auditParams.Updated = updated
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)
	ns.logger.DebugContext(ctx, "soft-deleted namespace", slog.String("id", namespaceID))

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) AssignKeyAccessServerToNamespace(_ context.Context, _ *connect.Request[namespaces.AssignKeyAccessServerToNamespaceRequest]) (*connect.Response[namespaces.AssignKeyAccessServerToNamespaceResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("this compatibility stub will be removed entirely in the following release"))
}

func (ns NamespacesService) RemoveKeyAccessServerFromNamespace(ctx context.Context, req *connect.Request[namespaces.RemoveKeyAccessServerFromNamespaceRequest]) (*connect.Response[namespaces.RemoveKeyAccessServerFromNamespaceResponse], error) {
	rsp := &namespaces.RemoveKeyAccessServerFromNamespaceResponse{}

	grant := req.Msg.GetNamespaceKeyAccessServer()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeNamespaceAssignment,
		ObjectID:   fmt.Sprintf("%s-%s", grant.GetNamespaceId(), grant.GetKeyAccessServerId()),
	}

	namespaceKas, err := ns.dbClient.RemoveKeyAccessServerFromNamespace(ctx, grant)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextDeletionFailed, slog.String("namespaceKas", grant.String()))
	}
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.NamespaceKeyAccessServer = namespaceKas

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) AssignPublicKeyToNamespace(ctx context.Context, r *connect.Request[namespaces.AssignPublicKeyToNamespaceRequest]) (*connect.Response[namespaces.AssignPublicKeyToNamespaceResponse], error) {
	rsp := &namespaces.AssignPublicKeyToNamespaceResponse{}

	key := r.Msg.GetNamespaceKey()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeKasAttributeNamespaceKeyAssignment,
		ObjectID:   fmt.Sprintf("%s:%s", key.GetNamespaceId(), key.GetKeyId()),
	}

	namespaceKey, err := ns.dbClient.AssignPublicKeyToNamespace(ctx, key)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextCreationFailed, slog.String("namespaceKey", key.String()))
	}
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.NamespaceKey = namespaceKey

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) RemovePublicKeyFromNamespace(ctx context.Context, r *connect.Request[namespaces.RemovePublicKeyFromNamespaceRequest]) (*connect.Response[namespaces.RemovePublicKeyFromNamespaceResponse], error) {
	rsp := &namespaces.RemovePublicKeyFromNamespaceResponse{}

	key := r.Msg.GetNamespaceKey()
	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeKasAttributeNamespaceKeyAssignment,
		ObjectID:   fmt.Sprintf("%s:%s", key.GetNamespaceId(), key.GetKeyId()),
	}

	_, err := ns.dbClient.RemovePublicKeyFromNamespace(ctx, key)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, db.ErrTextDeletionFailed, slog.String("namespaceKey", key.String()))
	}
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) AssignCertificateToNamespace(ctx context.Context, r *connect.Request[namespaces.AssignCertificateToNamespaceRequest]) (*connect.Response[namespaces.AssignCertificateToNamespaceResponse], error) {
	rsp := &namespaces.AssignCertificateToNamespaceResponse{}

	namespaceIdentifier := r.Msg.GetNamespace()
	pem := r.Msg.GetPem()
	metadata := r.Msg.GetMetadata()

	// Get string representation for audit log (either ID or FQN)
	auditObjectID := namespaceIdentifier.GetId()
	if auditObjectID == "" {
		auditObjectID = namespaceIdentifier.GetFqn()
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeCreate,
		ObjectType: audit.ObjectTypeNamespaceCertificate,
		ObjectID:   auditObjectID,
	}

	// Create the certificate metadata
	metadataJSON, _, err := db.MarshalCreateMetadata(metadata)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, "Failed to marshal metadata")
	}

	// Create and assign certificate in a transaction
	// This ensures that if assignment fails, certificate creation is rolled back
	certID, err := ns.dbClient.CreateAndAssignCertificateToNamespace(ctx, namespaceIdentifier, pem, metadataJSON)
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, "Failed to create and assign certificate")
	}

	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.NamespaceCertificate = &namespaces.NamespaceCertificate{
		Namespace:     namespaceIdentifier,
		CertificateId: certID,
	}
	rsp.Certificate = &policy.Certificate{
		Id:  certID,
		Pem: pem,
	}

	return connect.NewResponse(rsp), nil
}

func (ns NamespacesService) RemoveCertificateFromNamespace(ctx context.Context, r *connect.Request[namespaces.RemoveCertificateFromNamespaceRequest]) (*connect.Response[namespaces.RemoveCertificateFromNamespaceResponse], error) {
	rsp := &namespaces.RemoveCertificateFromNamespaceResponse{}

	cert := r.Msg.GetNamespaceCertificate()
	namespaceIdentifier := cert.GetNamespace()

	// Get string representation for audit log (either ID or FQN)
	auditNamespaceID := namespaceIdentifier.GetId()
	if auditNamespaceID == "" {
		auditNamespaceID = namespaceIdentifier.GetFqn()
	}

	auditParams := audit.PolicyEventParams{
		ActionType: audit.ActionTypeDelete,
		ObjectType: audit.ObjectTypeNamespaceCertificate,
		ObjectID:   fmt.Sprintf("%s:%s", auditNamespaceID, cert.GetCertificateId()),
	}

	err := ns.dbClient.RemoveCertificateFromNamespace(ctx, namespaceIdentifier, cert.GetCertificateId())
	if err != nil {
		ns.logger.Audit.PolicyCRUDFailure(ctx, auditParams)
		return nil, db.StatusifyError(ctx, ns.logger, err, "Failed to remove certificate from namespace")
	}
	ns.logger.Audit.PolicyCRUDSuccess(ctx, auditParams)

	rsp.NamespaceCertificate = cert

	return connect.NewResponse(rsp), nil
}
