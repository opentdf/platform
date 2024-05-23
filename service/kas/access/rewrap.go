package access

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/authorization"

	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/auth"
	"github.com/opentdf/platform/service/internal/logger"
	"github.com/opentdf/platform/service/kas/tdf3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type SignedRequestBody struct {
	RequestBody string `json:"requestBody"`
}

type RequestBody struct {
	AuthToken       string         `json:"authToken"`
	KeyAccess       tdf3.KeyAccess `json:"keyAccess"`
	Policy          string         `json:"policy,omitempty"`
	Algorithm       string         `json:"algorithm,omitempty"`
	ClientPublicKey string         `json:"clientPublicKey"`
	PublicKey       interface{}    `json:"-"`
	SchemaVersion   string         `json:"schemaVersion,omitempty"`
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
	return errors.Join(ErrUser, status.Error(codes.InvalidArgument, s))
}

func err401(s string) error {
	return errors.Join(ErrUser, status.Error(codes.Unauthenticated, s))
}

func err403(s string) error {
	return errors.Join(ErrUser, status.Error(codes.PermissionDenied, s))
}

func generateHMACDigest(ctx context.Context, msg, key []byte, logger logger.Logger) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write(msg)
	if err != nil {
		logger.WarnContext(ctx, "failed to compute hmac")
		return nil, errors.Join(ErrUser, status.Error(codes.InvalidArgument, "policy hmac"))
	}
	return mac.Sum(nil), nil
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

func extractSRTBody(ctx context.Context, in *kaspb.RewrapRequest, logger logger.Logger) (*RequestBody, error) {
	// First load legacy method for verifying SRT
	md, exists := metadata.FromIncomingContext(ctx)
	if !exists {
		logger.WarnContext(ctx, "missing metadata for srt validation")
		return nil, errors.New("missing metadata")
	}
	if vpk, ok := md["X-Virtrupubkey"]; ok && len(vpk) == 1 {
		logger.InfoContext(ctx, "Legacy Client: Processing X-Virtrupubkey")
	}

	// get dpop public key from context
	dpopJWK := auth.GetJWKFromContext(ctx)

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

func verifyAndParsePolicy(ctx context.Context, requestBody *RequestBody, k []byte, logger logger.Logger) (*Policy, error) {
	actualHMAC, err := generateHMACDigest(ctx, []byte(requestBody.Policy), k, logger)
	if err != nil {
		logger.WarnContext(ctx, "unable to generate policy hmac", "err", err)
		return nil, err400("bad request")
	}
	expectedHMAC := make([]byte, base64.StdEncoding.DecodedLen(len(requestBody.KeyAccess.PolicyBinding)))
	n, err := base64.StdEncoding.Decode(expectedHMAC, []byte(requestBody.KeyAccess.PolicyBinding))
	if err == nil {
		n, err = hex.Decode(expectedHMAC, expectedHMAC[:n])
	}
	expectedHMAC = expectedHMAC[:n]
	if err != nil {
		logger.WarnContext(ctx, "invalid policy binding", "err", err)
		return nil, err400("bad request")
	}
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		logger.WarnContext(ctx, "policy hmac mismatch", "actual", actualHMAC, "expected", expectedHMAC, "policyBinding", requestBody.KeyAccess.PolicyBinding)
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

func getEntityInfo(ctx context.Context, logger logger.Logger) (*entityInfo, error) {
	var info = new(entityInfo)

	token := auth.GetAccessTokenFromContext(ctx)
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

	info.Token = auth.GetRawAccessTokenFromContext(ctx)

	return info, nil
}

func (p *Provider) Rewrap(ctx context.Context, in *kaspb.RewrapRequest) (*kaspb.RewrapResponse, error) {
	p.Logger.DebugContext(ctx, "REWRAP")

	body, err := extractSRTBody(ctx, in, *p.Logger)
	if err != nil {
		p.Logger.DebugContext(ctx, "unverifiable srt", "err", err)
		return nil, err
	}

	entityInfo, err := getEntityInfo(ctx, *p.Logger)
	if err != nil {
		p.Logger.DebugContext(ctx, "no entity info", "err", err)
		return nil, err
	}

	if !strings.HasPrefix(body.KeyAccess.URL, p.URI.String()) {
		p.Logger.InfoContext(ctx, "mismatched key access url", "keyAccessURL", body.KeyAccess.URL, "kasURL", p.URI.String())
	}

	if body.Algorithm == "" {
		p.Logger.DebugContext(ctx, "default rewrap algorithm")
		body.Algorithm = "rsa:2048"
	}

	if body.Algorithm == "ec:secp256r1" {
		rsp, err := p.nanoTDFRewrap(ctx, body, entityInfo)
		if err != nil {
			slog.ErrorContext(ctx, "rewrap nano", "err", err)
		}
		p.Logger.DebugContext(ctx, "rewrap nano", "rsp", rsp)
		return rsp, err
	}
	rsp, err := p.tdf3Rewrap(ctx, body, entityInfo)
	if err != nil {
		slog.ErrorContext(ctx, "rewrap tdf3", "err", err)
	}
	return rsp, err
}

func (p *Provider) tdf3Rewrap(ctx context.Context, body *RequestBody, entity *entityInfo) (*kaspb.RewrapResponse, error) {
	symmetricKey, err := p.CryptoProvider.RSADecrypt(crypto.SHA1, "UnKnown", "", body.KeyAccess.WrappedKey)
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

	access, err := canAccess(ctx, tok, *policy, p.SDK)

	auditPolicy := transformAuditPolicy(policy, entity.Token, *p.Logger)

	if err != nil {
		p.Logger.WarnContext(ctx, "Could not perform access decision!", "err", err)
		err := p.Logger.Audit.RewrapFailure(ctx, *auditPolicy)
		if err != nil {
			p.Logger.ErrorContext(ctx, "failed to audit rewrap failure", "err", err)
		}
		return nil, err403("forbidden")
	}

	if !access {
		p.Logger.WarnContext(ctx, "Access Denied; no reason given")
		err := p.Logger.Audit.RewrapFailure(ctx, *auditPolicy)
		if err != nil {
			p.Logger.ErrorContext(ctx, "failed to audit rewrap failure", "err", err)
		}
		return nil, err403("forbidden")
	}

	asymEncrypt, err := ocrypto.NewAsymEncryption(body.ClientPublicKey)
	if err != nil {
		p.Logger.WarnContext(ctx, "ocrypto.NewAsymEncryption:", "err", err)
	}

	rewrappedKey, err := asymEncrypt.Encrypt(symmetricKey)
	if err != nil {
		p.Logger.WarnContext(ctx, "rewrap: ocrypto.AsymEncryption.encrypt failed", "err", err, "clientPublicKey", &body.ClientPublicKey)
		err = p.Logger.Audit.RewrapFailure(ctx, *auditPolicy)
		if err != nil {
			p.Logger.ErrorContext(ctx, "failed to audit rewrap failure", "err", err)
		}
		return nil, err400("bad key for rewrap")
	}

	err = p.Logger.Audit.RewrapSuccess(ctx, *auditPolicy)
	if err != nil {
		p.Logger.ErrorContext(ctx, "failed to audit rewrap success", "err", err)
	}
	return &kaspb.RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SessionPublicKey: "",
		SchemaVersion:    schemaVersion,
	}, nil
}

func (p *Provider) nanoTDFRewrap(ctx context.Context, body *RequestBody, entity *entityInfo) (*kaspb.RewrapResponse, error) {
	headerReader := bytes.NewReader(body.KeyAccess.Header)

	header, _, err := sdk.NewNanoTDFHeaderFromReader(headerReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NanoTDF header: %w", err)
	}

	symmetricKey, err := p.CryptoProvider.GenerateNanoTDFSymmetricKey(header.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// check the policy binding
	digest := ocrypto.CalculateSHA256(header.EncryptedPolicyBody)
	binding := digest[len(digest)-kNanoTDFGMACLength:]
	if !bytes.Equal(binding, header.PolicyBinding) {
		return nil, fmt.Errorf("policy binding check failed")
	}

	// extract the policy
	policy, err := extractNanoPolicy(symmetricKey, header)
	if err != nil {
		return nil, fmt.Errorf("Error extracting policy: %w", err)
	}

	// do the access check
	tok := &authorization.Token{
		Id:  "rewrap-tok",
		Jwt: entity.Token,
	}

	access, err := canAccess(ctx, tok, *policy, p.SDK)

	auditPolicy := transformAuditPolicy(policy, entity.Token, *p.Logger)

	if err != nil {
		p.Logger.WarnContext(ctx, "Could not perform access decision!", "err", err)
		err := p.Logger.Audit.RewrapFailure(ctx, *auditPolicy)
		if err != nil {
			p.Logger.ErrorContext(ctx, "failed to audit rewrap failure", "err", err)
		}
		return nil, err403("forbidden")
	}

	if !access {
		p.Logger.WarnContext(ctx, "Access Denied; no reason given")
		err := p.Logger.Audit.RewrapFailure(ctx, *auditPolicy)
		if err != nil {
			p.Logger.ErrorContext(ctx, "failed to audit rewrap failure", "err", err)
		}
		return nil, err403("forbidden")
	}

	pub, ok := body.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Convert public key to 65-bytes format
	pubKeyBytes := make([]byte, 1+len(pub.X.Bytes())+len(pub.Y.Bytes()))
	pubKeyBytes[0] = 0x4 // ID for uncompressed format
	if copy(pubKeyBytes[1:33], pub.X.Bytes()) != 32 || copy(pubKeyBytes[33:], pub.Y.Bytes()) != 32 {
		return nil, fmt.Errorf("failed to serialize keypair: %v", pub)
	}

	privateKeyHandle, publicKeyHandle, err := p.CryptoProvider.GenerateEphemeralKasKeys()

	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	sessionKey, err := p.CryptoProvider.GenerateNanoTDFSessionKey(privateKeyHandle, []byte(body.ClientPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	cipherText, err := wrapKeyAES(sessionKey, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	return &kaspb.RewrapResponse{
		EntityWrappedKey: cipherText,
		SessionPublicKey: string(publicKeyHandle),
		SchemaVersion:    schemaVersion,
	}, nil
}

func extractNanoPolicy(symmetricKey []byte, header sdk.NanoTDFHeader) (*Policy, error) {
	gcm, err := ocrypto.NewAESGcm(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewAESGcm:%w", err)
	}

	const (
		kIvLen = 12
	)
	iv := make([]byte, kIvLen)
	tagSize, err := sdk.SizeOfAuthTagForCipher(header.GetCipher())
	if err != nil {
		return nil, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
	}

	policyData, err := gcm.DecryptWithIVAndTagSize(iv, header.EncryptedPolicyBody, tagSize)
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

func wrapKeyAES(sessionKey, dek []byte) ([]byte, error) {
	gcm, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewAESGcm:%w", err)
	}

	cipherText, err := gcm.Encrypt(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto.AsymEncryption.encrypt:%w", err)
	}

	return cipherText, nil
}

func transformAuditPolicy(policy *Policy, entityToken string, lg logger.Logger) *logger.AuditPolicy {
	var token, err = jwt.Parse([]byte(entityToken), jwt.WithVerify(false))
	if err != nil {
		lg.Warn("unable to parse entity token", "err", err)
	}

	var dataAttributes []logger.AuditPolicySimpleAttribute
	for _, attr := range policy.Body.DataAttributes {
		dataAttributes = append(dataAttributes, logger.AuditPolicySimpleAttribute{URI: attr.URI})
	}
	return logger.CreateAuditPolicy(policy.UUID, dataAttributes, policy.Body.Dissem, token)
}
