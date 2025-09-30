package namespaces

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	"github.com/go-jose/go-jose/v4"
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
			Namespace:       ns,
			DB:              dbRegister,
			ServiceDesc:     &namespaces.NamespaceService_ServiceDesc,
			ConnectRPCFunc:  namespacesconnect.NewNamespaceServiceHandler,
			GRPCGatewayFunc: namespaces.RegisterNamespaceServiceHandler,
			OnConfigUpdate:  onUpdateConfigHook,
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
	if err := ns.dbClient.SQLDB.PingContext(ctx); err != nil {
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
	// FIXME for POC only
	UpdateConfigurationRootCACert(namespace)

	rsp.Namespace = namespace

	return connect.NewResponse(rsp), nil
}

func UpdateConfigurationRootCACert(n *policy.Namespace) {
	// FIXME for POC only
	certPEM := `
Bag Attributes: <No Attributes>
subject=C=US, ST=Texas, L=Houston, O=SSL Corporation, CN=SSL.com Root Certification Authority ECC
issuer=C=US, ST=Texas, L=Houston, O=SSL Corporation, CN=SSL.com Root Certification Authority ECC
-----BEGIN CERTIFICATE-----
MIICjTCCAhSgAwIBAgIIdebfy8FoW6gwCgYIKoZIzj0EAwIwfDELMAkGA1UEBhMC
VVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMRgwFgYDVQQKDA9T
U0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20gUm9vdCBDZXJ0aWZpY2F0
aW9uIEF1dGhvcml0eSBFQ0MwHhcNMTYwMjEyMTgxNDAzWhcNNDEwMjEyMTgxNDAz
WjB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0
b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8GA1UEAwwoU1NMLmNvbSBS
b290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IEVDQzB2MBAGByqGSM49AgEGBSuB
BAAiA2IABEVuqVDEpiM2nl8ojRfLliJkP9x6jh3MCLOicSS6jkm5BBtHllirLZXI
7Z4INcgn64mMU1jrYor+8FsPazFSY0E7ic3s7LaNGdM0B9y7xgZ/wkWV7Mt/qCPg
CemB+vNH06NjMGEwHQYDVR0OBBYEFILRhXMw5zUE044CkvvlpNHEIejNMA8GA1Ud
EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUgtGFczDnNQTTjgKS++Wk0cQh6M0wDgYD
VR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA2cAMGQCMG/n61kRpGDPYbCWe+0F+S8T
kdzt5fxQaxFGRrMcIQBiu77D5+jNB5n5DQtdcj7EqgIwH7y6C+IwJPt8bYBVCpk+
gA0z5Wajs6O7pdWLjwkspl1+4vAHCGht0nxpbl/f5Wpl
-----END CERTIFICATE-----
`
	// Parse PEM to DER
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		slog.Error("failed to decode PEM certificate")
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		slog.Error("failed to parse certificate", slog.String("error", err.Error()))
		return
	}

	// Prepare JSON-friendly JWK representation with x5c
	jwkMap := map[string]any{}

	// Derive kty/crv/alg from public key
	switch pk := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		jwkMap["kty"] = "EC"
		// Determine crv from params
		switch pk.Curve.Params().Name {
		case "P-256", "prime256v1", "secp256r1":
			jwkMap["crv"] = "P-256"
			jwkMap["alg"] = "ES256"
		case "P-384", "secp384r1":
			jwkMap["crv"] = "P-384"
			jwkMap["alg"] = "ES384"
		case "P-521", "secp521r1":
			jwkMap["crv"] = "P-521"
			jwkMap["alg"] = "ES512"
		default:
			jwkMap["crv"] = pk.Curve.Params().Name
		}
		// Set x and y as base64url (no padding)
		xBytes := pk.X.Bytes()
		yBytes := pk.Y.Bytes()
		// Left-pad to field size
		fieldLen := (pk.Curve.Params().BitSize + 7) / 8
		if len(xBytes) < fieldLen {
			p := make([]byte, fieldLen-len(xBytes))
			xBytes = append(p, xBytes...)
		}
		if len(yBytes) < fieldLen {
			p := make([]byte, fieldLen-len(yBytes))
			yBytes = append(p, yBytes...)
		}
		jwkMap["x"] = base64.RawURLEncoding.EncodeToString(xBytes)
		jwkMap["y"] = base64.RawURLEncoding.EncodeToString(yBytes)
	case *rsa.PublicKey:
		jwkMap["kty"] = "RSA"
		jwkMap["alg"] = "RS256"
		n := pk.N.Bytes()
		e := pk.E
		jwkMap["n"] = base64.RawURLEncoding.EncodeToString(n)
		// encode e as minimal big-endian bytes
		var eBytes []byte
		if e > 0 {
			for v := e; v > 0; v >>= 8 {
				eBytes = append([]byte{byte(v & 0xff)}, eBytes...)
			}
		} else {
			eBytes = []byte{0x01, 0x00, 0x01} // fallback 65537
		}
		jwkMap["e"] = base64.RawURLEncoding.EncodeToString(eBytes)
	default:
		// Fallback using go-jose to make a JSON-friendly map
		j := jose.JSONWebKey{Key: cert.PublicKey}
		pub := j.Public()
		jwkMap["pub"] = pub.Key
		// Marshal to JSON then unmarshal to map if needed, but here keep minimal fields
		jwkMap["kty"] = "oct"
	}

	// Use for signatures
	jwkMap["use"] = "sig"

	// kid from SKI if present
	if len(cert.SubjectKeyId) > 0 {
		jwkMap["kid"] = base64.RawURLEncoding.EncodeToString(cert.SubjectKeyId)
	}

	// x5c: base64 DER (no headers)
	x5c := []any{base64.StdEncoding.EncodeToString(cert.Raw)}
	jwkMap["x5c"] = x5c

	// x5t (SHA-1) and x5t#S256 optional, but skipped here
	certificate := policy.Certificate{
		X5C: base64.StdEncoding.EncodeToString(cert.Raw),
	}
	n.RootCerts = append(n.RootCerts, &certificate)

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
