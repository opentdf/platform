package access

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/authorization"
	"go.opentelemetry.io/otel/trace"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/kas/recrypt"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SignedRequestBody struct {
	RequestBody string `json:"requestBody"`
}

type RequestBody struct {
	AuthToken       string      `json:"authToken"`
	KeyAccess       KeyAccess   `json:"keyAccess"`
	Policy          string      `json:"policy,omitempty"`
	Algorithm       string      `json:"algorithm,omitempty"`
	ClientPublicKey string      `json:"clientPublicKey"`
	PublicKey       interface{} `json:"-"`
	SchemaVersion   string      `json:"schemaVersion,omitempty"`
}

type entityInfo struct {
	EntityID string `json:"sub"`
	ClientID string `json:"clientId"`
	Token    string `json:"-"`
}

const (
	kNanoTDFGMACLength = 8
	ErrUser            = Error("request error")
	ErrInternal        = Error("internal error")
)

func err400(s string) error {
	return connect.NewError(connect.CodeInvalidArgument, errors.Join(ErrUser, status.Error(codes.InvalidArgument, s)))
}

func err401(s string) error {
	return connect.NewError(connect.CodeUnauthenticated, errors.Join(ErrUser, status.Error(codes.Unauthenticated, s)))
}

func err403(s string) error {
	return connect.NewError(connect.CodePermissionDenied, errors.Join(ErrUser, status.Error(codes.PermissionDenied, s)))
}

var acceptableSkew = 30 * time.Second

func verifySRT(ctx context.Context, srt string, dpopJWK jwk.Key, logger logger.Logger) (string, error) {
	token, err := jwt.Parse([]byte(srt), jwt.WithKey(jwa.RS256, dpopJWK), jwt.WithAcceptableSkew(acceptableSkew))
	if err != nil {
		logger.WarnContext(ctx, "unable to verify request token", "err", err, "srt", srt, "jwk", dpopJWK)
		return "", err401("unable to verify request token")
	}
	return justRequestBody(ctx, token, logger)
}

func noverify(ctx context.Context, srt string, logger logger.Logger) (string, error) {
	token, err := jwt.Parse([]byte(srt), jwt.WithVerify(false), jwt.WithAcceptableSkew(acceptableSkew))
	if err != nil {
		logger.WarnContext(ctx, "unable to validate or parse token", "err", err)
		return "", err401("could not parse token")
	}
	return justRequestBody(ctx, token, logger)
}

func justRequestBody(ctx context.Context, token jwt.Token, logger logger.Logger) (string, error) {
	rb, exists := token.Get("requestBody")
	if !exists {
		logger.WarnContext(ctx, "missing request body")
		return "", err400("missing request body")
	}

	rbString, ok := rb.(string)
	if !ok {
		logger.WarnContext(ctx, "invalid request body")
		return "", err400("invalid request body")
	}
	return rbString, nil
}

func extractSRTBody(ctx context.Context, headers http.Header, in *kaspb.RewrapRequest, logger logger.Logger) (*RequestBody, error) {
	// First load legacy method for verifying SRT
	if vpk, ok := headers["X-Virtrupubkey"]; ok && len(vpk) == 1 {
		logger.InfoContext(ctx, "Legacy Client: Processing X-Virtrupubkey")
	}

	// get dpop public key from context
	dpopJWK := ctxAuth.GetJWKFromContext(ctx, &logger)

	var err error
	var rbString string
	srt := in.GetSignedRequestToken()
	if dpopJWK == nil {
		logger.InfoContext(ctx, "no DPoP key provided")
		// if we have no DPoP key it's for one of two reasons:
		// 1. auth is disabled so we can't get a DPoP JWK
		// 2. auth is enabled _but_ we aren't requiring DPoP
		// in either case letting the request through makes sense
		rbString, err = noverify(ctx, srt, logger)
		if err != nil {
			logger.ErrorContext(ctx, "unable to load RSA verifier", "err", err)
			return nil, err
		}
	} else {
		// verify and validate the request token
		var err error
		rbString, err = verifySRT(ctx, srt, dpopJWK, logger)
		if err != nil {
			return nil, err
		}
	}

	var requestBody RequestBody
	err = json.Unmarshal([]byte(rbString), &requestBody)
	if err != nil {
		logger.WarnContext(ctx, "invalid request body")
		return nil, err400("invalid request body")
	}
	logger.DebugContext(ctx, "extracted request body", slog.Any("requestBody", requestBody))

	logger.DebugContext(ctx, "extract public key", "requestBody.ClientPublicKey", requestBody.ClientPublicKey)
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		logger.WarnContext(ctx, "missing clientPublicKey")
		return nil, err400("clientPublicKey failure")
	}

	// Try to parse the clientPublicKey
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.WarnContext(ctx, "failure to parse clientPublicKey", "err", err)
		return nil, err400("clientPublicKey parse failure")
	}
	// Check to make sure the clientPublicKey is a supported key type
	switch publicKey := clientPublicKey.(type) {
	case *rsa.PublicKey:
		requestBody.PublicKey = publicKey
		return &requestBody, nil
	case *ecdsa.PublicKey:
		requestBody.PublicKey = publicKey
		return &requestBody, nil
	default:
		logger.WarnContext(ctx, fmt.Sprintf("clientPublicKey not a supported key, was [%T]", clientPublicKey))
		return nil, err400("clientPublicKey unsupported type")
	}
}

func extractPolicyBinding(policyBinding interface{}) (string, error) {
	switch v := policyBinding.(type) {
	case string:
		return v, nil
	case map[string]interface{}:
		if hash, ok := v["hash"].(string); ok {
			return hash, nil
		}
		return "", fmt.Errorf("invalid policy binding object, missing 'hash' field")
	default:
		return "", fmt.Errorf("unsupported policy binding type")
	}
}

func verifyAndParsePolicy(ctx context.Context, requestBody *RequestBody, k recrypt.UnwrappedKey, logger logger.Logger) (*Policy, error) {
	actualHMAC, err := k.Digest([]byte(requestBody.Policy))
	if err != nil {
		logger.WarnContext(ctx, "unable to generate policy hmac", "err", err)
		return nil, err400("bad request")
	}

	policyBinding, err := extractPolicyBinding(requestBody.KeyAccess.PolicyBinding)
	if err != nil {
		logger.WarnContext(ctx, "invalid policy binding", "err", err)
		return nil, err400("bad request")
	}

	expectedHMAC := make([]byte, base64.StdEncoding.DecodedLen(len(policyBinding)))
	n, err := base64.StdEncoding.Decode(expectedHMAC, []byte(policyBinding))
	if err == nil {
		n, err = hex.Decode(expectedHMAC, expectedHMAC[:n])
	}
	expectedHMAC = expectedHMAC[:n]
	if err != nil {
		logger.WarnContext(ctx, "invalid policy binding", "err", err)
		return nil, err400("bad request")
	}
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		logger.WarnContext(ctx, "policy hmac mismatch", "policyBinding", policyBinding)
		return nil, err400("bad request")
	}
	sDecPolicy, err := base64.StdEncoding.DecodeString(requestBody.Policy)
	if err != nil {
		logger.WarnContext(ctx, "unable to decode policy", "err", err)
		return nil, err400("bad request")
	}
	decoder := json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		logger.WarnContext(ctx, "unable to decode policy", "err", err)
		return nil, err400("bad request")
	}
	return &policy, nil
}

func getEntityInfo(ctx context.Context, logger *logger.Logger) (*entityInfo, error) {
	info := new(entityInfo)

	token := ctxAuth.GetAccessTokenFromContext(ctx, logger)
	if token == nil {
		return nil, err401("missing access token")
	}

	sub, found := token.Get("sub")
	if found {
		var subAssert bool
		info.EntityID, subAssert = sub.(string)
		if !subAssert {
			logger.WarnContext(ctx, "sub not a string")
		}
	} else {
		logger.WarnContext(ctx, "missing sub")
	}

	info.Token = ctxAuth.GetRawAccessTokenFromContext(ctx, logger)

	return info, nil
}

func (p *Provider) Rewrap(ctx context.Context, req *connect.Request[kaspb.RewrapRequest]) (*connect.Response[kaspb.RewrapResponse], error) {
	in := req.Msg
	p.Logger.DebugContext(ctx, "REWRAP")

	body, err := extractSRTBody(ctx, req.Header(), in, *p.Logger)
	if err != nil {
		p.Logger.DebugContext(ctx, "unverifiable srt", "err", err)
		return nil, err
	}

	entityInfo, err := getEntityInfo(ctx, p.Logger)
	if err != nil {
		p.Logger.DebugContext(ctx, "no entity info", "err", err)
		return nil, err
	}

	if body.Algorithm == "" {
		p.Logger.DebugContext(ctx, "default rewrap algorithm")
		body.Algorithm = "rsa:2048"
	}

	if body.Algorithm == "ec:secp256r1" {
		rsp, err := p.nanoTDFRewrap(ctx, body, entityInfo)
		if err != nil {
			p.Logger.ErrorContext(ctx, "rewrap nano", "err", err)
		}
		p.Logger.DebugContext(ctx, "rewrap nano", "rsp", rsp)
		return connect.NewResponse(rsp), err
	}
	rsp, err := p.tdf3Rewrap(ctx, body, entityInfo)
	if err != nil {
		p.Logger.ErrorContext(ctx, "rewrap tdf3", "err", err)
	}
	return connect.NewResponse(rsp), err
}

func (p *Provider) tdf3Rewrap(ctx context.Context, body *RequestBody, entity *entityInfo) (*kaspb.RewrapResponse, error) {
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Tracer.Start(ctx, "rewrap-tdf3")
		defer span.End()
	}

	var kidsToCheck []recrypt.KeyIdentifier
	if body.KeyAccess.KID != "" {
		kidsToCheck = []recrypt.KeyIdentifier{recrypt.KeyIdentifier(body.KeyAccess.KID)}
	} else {
		p.Logger.InfoContext(ctx, "kid free kao")
		for _, k := range p.KASConfig.Keyring {
			if k.Algorithm == recrypt.AlgorithmRSA2048 {
				kidsToCheck = append(kidsToCheck, k.KID)
			}
		}
		if len(kidsToCheck) == 0 {
			p.Logger.WarnContext(ctx, "failure to find legacy kids for rsa")
			return nil, err400("bad request")
		}
	}
	symmetricKey, err := p.CryptoProvider.Unwrap(kidsToCheck[0], body.KeyAccess.WrappedKey)
	for _, kid := range kidsToCheck[1:] {
		if err == nil {
			break
		}
		p.Logger.DebugContext(ctx, "continue paging through legacy KIDs for kid free kao", "err", err)
		symmetricKey, err = p.CryptoProvider.Unwrap(kid, body.KeyAccess.WrappedKey)
	}
	if err != nil {
		p.Logger.WarnContext(ctx, "failure to decrypt dek", "err", err)
		return nil, err400("bad request")
	}
	p.Logger.DebugContext(ctx, "verifying policy binding", "requestBody.policy", body.Policy)
	policy, err := verifyAndParsePolicy(ctx, body, symmetricKey, *p.Logger)
	if err != nil {
		return nil, err
	}

	p.Logger.DebugContext(ctx, "extracting policy", "requestBody.policy", body.Policy)
	// changed use the entities in the token to get the decisions
	tok := &authorization.Token{
		Id:  "rewrap-tok",
		Jwt: entity.Token,
	}

	access, err := p.canAccess(ctx, tok, *policy)

	// Audit the TDF3 Rewrap
	kasPolicy := ConvertToAuditKasPolicy(*policy)

	policyBinding, _ := extractPolicyBinding(body.KeyAccess.PolicyBinding)

	auditEventParams := audit.RewrapAuditEventParams{
		Policy:        kasPolicy,
		IsSuccess:     access,
		TDFFormat:     "tdf3",
		Algorithm:     body.Algorithm,
		PolicyBinding: policyBinding,
	}

	if err != nil {
		p.Logger.WarnContext(ctx, "Could not perform access decision!", "err", err)
		p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
		return nil, err403("forbidden")
	}

	if !access {
		p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
		return nil, err403("forbidden")
	}

	asymEncrypt, err := ocrypto.NewAsymEncryption(body.ClientPublicKey)
	if err != nil {
		p.Logger.WarnContext(ctx, "ocrypto.NewAsymEncryption:", "err", err)
	}

	rewrappedKey, err := symmetricKey.Wrap(asymEncrypt)
	if err != nil {
		p.Logger.WarnContext(ctx, "rewrap: ocrypto.AsymEncryption.encrypt failed", "err", err, "clientPublicKey", &body.ClientPublicKey)
		p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
		return nil, err400("bad key for rewrap")
	}

	p.Logger.Audit.RewrapSuccess(ctx, auditEventParams)
	return &kaspb.RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SessionPublicKey: "",
		SchemaVersion:    schemaVersion,
	}, nil
}

func (p *Provider) nanoTDFRewrap(ctx context.Context, body *RequestBody, entity *entityInfo) (*kaspb.RewrapResponse, error) {
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Tracer.Start(ctx, "rewrap-nanotdf")
		defer span.End()
	}

	headerReader := bytes.NewReader(body.KeyAccess.Header)

	header, _, err := sdk.NewNanoTDFHeaderFromReader(headerReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NanoTDF header: %w", err)
	}
	ecCurve, err := header.ECCurve()
	if err != nil {
		return nil, fmt.Errorf("ECCurve failed: %w", err)
	}

	var a recrypt.Algorithm
	switch ecCurve {
	case elliptic.P256():
		a = recrypt.AlgorithmECP256R1
	case elliptic.P384():
		a = recrypt.AlgorithmECP384R1
	case elliptic.P521():
		a = recrypt.AlgorithmECP521R1
	default:
		return nil, fmt.Errorf("unsupported curve: %s", ecCurve)
	}

	// Lookup KID from nano header, or infer if not found
	kid, err := p.extractKasKID(ctx, header, a)
	if err != nil {
		return nil, err
	}
	p.Logger.DebugContext(ctx, "nanoTDFRewrap", "kid", kid)

	symmetricKey, err := p.CryptoProvider.Derive(kid, header.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// extract the policy
	policy, err := extractNanoPolicy(symmetricKey, header)
	if err != nil {
		return nil, fmt.Errorf("Error extracting policy: %w", err)
	}

	// check the policy binding
	verify, err := header.VerifyPolicyBinding()
	if err != nil {
		return nil, fmt.Errorf("failed to verify policy binding: %w", err)
	}

	if !verify {
		return nil, fmt.Errorf("policy binding verification failed")
	}

	// do the access check
	tok := &authorization.Token{
		Id:  "rewrap-tok",
		Jwt: entity.Token,
	}

	access, err := p.canAccess(ctx, tok, *policy)

	// Audit the rewrap
	kasPolicy := ConvertToAuditKasPolicy(*policy)
	auditEventParams := audit.RewrapAuditEventParams{
		Policy:    kasPolicy,
		TDFFormat: "nano",
		Algorithm: body.Algorithm,
	}

	if err != nil {
		p.Logger.WarnContext(ctx, "Could not perform access decision!", "err", err)
		p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
		return nil, err403("forbidden")
	}

	if !access {
		p.Logger.WarnContext(ctx, "Access Denied; no reason given")
		p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
		return nil, err403("forbidden")
	}

	wrappedKey, err := symmetricKey.NanoWrap([]byte(body.ClientPublicKey))
	if err != nil {
		p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
		return nil, fmt.Errorf("failed to wrap key: %w", err)
	}
	p.Logger.Audit.RewrapSuccess(ctx, auditEventParams)

	return &kaspb.RewrapResponse{
		EntityWrappedKey: wrappedKey.EntityWrappedKey,
		SessionPublicKey: wrappedKey.SessionPublicKey,
		SchemaVersion:    schemaVersion,
	}, nil
}

func (p *Provider) extractKasKID(ctx context.Context, header sdk.NanoTDFHeader, a recrypt.Algorithm) (recrypt.KeyIdentifier, error) {
	kidStr, err := header.GetKasURL().GetIdentifier()
	if err == nil {
		kid, err := p.ParseKeyIdentifier(kidStr)
		if err != nil {
			p.Logger.ErrorContext(ctx, "invalid kid", "kid", kidStr, "err", err)
			return "", err400("bad request")
		}
		return kid, nil
	}
	if strings.Contains(err.Error(), "legacy") {
		// legacy nano without KID
		kids, err := p.LegacyKIDs(a)
		if err != nil {
			return "", fmt.Errorf("failure looking up legacy KID: %w", err)
		}
		if len(kids) == 0 {
			p.Logger.ErrorContext(ctx, "failure to find legacy kids for ec", "err", err)
			return "", err400("bad request")
		}
		if len(kids) > 1 {
			p.Logger.WarnContext(ctx, "multiple legacy kids for ec; only trying one")
		}
		return kids[0], nil
	}
	return "", fmt.Errorf("failed to get KID: %w", err)
}

func extractNanoPolicy(symmetricKey recrypt.UnwrappedKey, header sdk.NanoTDFHeader) (*Policy, error) {
	tagSize, err := sdk.SizeOfAuthTagForCipher(header.GetCipher())
	if err != nil {
		return nil, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	policyData, err := symmetricKey.DecryptNanoPolicy(header.EncryptedPolicyBody, tagSize)
	if err != nil {
		return nil, fmt.Errorf("Error decrypting policy body:%w", err)
	}

	var policy Policy
	err = json.Unmarshal(policyData, &policy)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling policy:%w", err)
	}
	return &policy, nil
}
