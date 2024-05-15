package access

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
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
	ErrUser     = Error("request error")
	ErrInternal = Error("internal error")
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

func generateHMACDigest(ctx context.Context, msg, key []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write(msg)
	if err != nil {
		slog.WarnContext(ctx, "failed to compute hmac")
		return nil, errors.Join(ErrUser, status.Error(codes.InvalidArgument, "policy hmac"))
	}
	return mac.Sum(nil), nil
}

var acceptableSkew = 30 * time.Second

func verifySRT(ctx context.Context, srt string, dpopJWK jwk.Key) (string, error) {
	token, err := jwt.Parse([]byte(srt), jwt.WithKey(jwa.RS256, dpopJWK), jwt.WithAcceptableSkew(acceptableSkew))
	if err != nil {
		slog.WarnContext(ctx, "unable to verify request token", "err", err, "srt", srt, "jwk", dpopJWK)
		return "", err401("unable to verify request token")
	}
	return justRequestBody(ctx, token)
}

func noverify(ctx context.Context, srt string) (string, error) {
	token, err := jwt.Parse([]byte(srt), jwt.WithVerify(false), jwt.WithAcceptableSkew(acceptableSkew))
	if err != nil {
		slog.WarnContext(ctx, "unable to validate or parse token", "err", err)
		return "", err401("could not parse token")
	}
	return justRequestBody(ctx, token)
}

func justRequestBody(ctx context.Context, token jwt.Token) (string, error) {
	rb, exists := token.Get("requestBody")
	if !exists {
		slog.WarnContext(ctx, "missing request body")
		return "", err400("missing request body")
	}

	rbString, ok := rb.(string)
	if !ok {
		slog.WarnContext(ctx, "invalid request body")
		return "", err400("invalid request body")
	}
	return rbString, nil
}

func extractSRTBody(ctx context.Context, in *kaspb.RewrapRequest) (*RequestBody, error) {
	// First load legacy method for verifying SRT
	md, exists := metadata.FromIncomingContext(ctx)
	if !exists {
		slog.WarnContext(ctx, "missing metadata for srt validation")
		return nil, errors.New("missing metadata")
	}
	if vpk, ok := md["X-Virtrupubkey"]; ok && len(vpk) == 1 {
		slog.InfoContext(ctx, "Legacy Client: Processing X-Virtrupubkey")
	}

	// get dpop public key from context
	dpopJWK := auth.GetJWKFromContext(ctx)

	var err error
	var rbString string
	srt := in.GetSignedRequestToken()
	if dpopJWK == nil {
		slog.InfoContext(ctx, "no DPoP key provided")
		// if we have no DPoP key it's for one of two reasons:
		// 1. auth is disabled so we can't get a DPoP JWK
		// 2. auth is enabled _but_ we aren't requiring DPoP
		// in either case letting the request through makes sense
		rbString, err = noverify(ctx, srt)
		if err != nil {
			slog.ErrorContext(ctx, "unable to load RSA verifier", "err", err)
			return nil, err
		}
	} else {
		// verify and validate the request token
		var err error
		rbString, err = verifySRT(ctx, srt, dpopJWK)
		if err != nil {
			return nil, err
		}
	}

	var requestBody RequestBody
	err = json.Unmarshal([]byte(rbString), &requestBody)
	if err != nil {
		slog.WarnContext(ctx, "invalid request body")
		return nil, err400("invalid request body")
	}

	slog.DebugContext(ctx, "extract public key", "requestBody.ClientPublicKey", requestBody.ClientPublicKey)
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		slog.WarnContext(ctx, "missing clientPublicKey")
		return nil, err400("clientPublicKey failure")
	}

	// Try to parse the clientPublicKey
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.WarnContext(ctx, "failure to parse clientPublicKey", "err", err)
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
		slog.WarnContext(ctx, fmt.Sprintf("clientPublicKey not a supported key, was [%T]", clientPublicKey))
		return nil, err400("clientPublicKey unsupported type")
	}
}

func verifyAndParsePolicy(ctx context.Context, requestBody *RequestBody, k []byte) (*Policy, error) {
	actualHMAC, err := generateHMACDigest(ctx, []byte(requestBody.Policy), k)
	if err != nil {
		slog.WarnContext(ctx, "unable to generate policy hmac", "err", err)
		return nil, err400("bad request")
	}
	expectedHMAC := make([]byte, base64.StdEncoding.DecodedLen(len(requestBody.KeyAccess.PolicyBinding)))
	n, err := base64.StdEncoding.Decode(expectedHMAC, []byte(requestBody.KeyAccess.PolicyBinding))
	if err == nil {
		n, err = hex.Decode(expectedHMAC, expectedHMAC[:n])
	}
	expectedHMAC = expectedHMAC[:n]
	if err != nil {
		slog.WarnContext(ctx, "invalid policy binding", "err", err)
		return nil, err400("bad request")
	}
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		slog.WarnContext(ctx, "policy hmac mismatch", "actual", actualHMAC, "expected", expectedHMAC, "policyBinding", requestBody.KeyAccess.PolicyBinding)
		return nil, err400("bad request")
	}
	sDecPolicy, err := base64.StdEncoding.DecodeString(requestBody.Policy)
	if err != nil {
		slog.WarnContext(ctx, "unable to decode policy", "err", err)
		return nil, err400("bad request")
	}
	decoder := json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		slog.WarnContext(ctx, "unable to decode policy", "err", err)
		return nil, err400("bad request")
	}
	return &policy, nil
}

func getEntityInfo(ctx context.Context) (*entityInfo, error) {
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
			slog.WarnContext(ctx, "sub not a string")
		}
	} else {
		slog.WarnContext(ctx, "missing sub")
	}

	info.Token = auth.GetRawAccessTokenFromContext(ctx)

	return info, nil
}

func (p *Provider) Rewrap(ctx context.Context, in *kaspb.RewrapRequest) (*kaspb.RewrapResponse, error) {
	slog.DebugContext(ctx, "REWRAP")

	body, err := extractSRTBody(ctx, in)
	if err != nil {
		slog.DebugContext(ctx, "unverifiable srt", "err", err)
		return nil, err
	}

	entityInfo, err := getEntityInfo(ctx)
	if err != nil {
		slog.DebugContext(ctx, "no entity info", "err", err)
		return nil, err
	}

	if !strings.HasPrefix(body.KeyAccess.URL, p.URI.String()) {
		slog.InfoContext(ctx, "mismatched key access url", "keyAccessURL", body.KeyAccess.URL, "kasURL", p.URI.String())
	}

	if body.Algorithm == "" {
		slog.DebugContext(ctx, "default rewrap algorithm")
		body.Algorithm = "rsa:2048"
	}

	if body.Algorithm == "ec:secp256r1" {
		return p.nanoTDFRewrap(body)
	}
	return p.tdf3Rewrap(ctx, body, entityInfo)
}

func (p *Provider) tdf3Rewrap(ctx context.Context, body *RequestBody, entity *entityInfo) (*kaspb.RewrapResponse, error) {
	symmetricKey, err := p.CryptoProvider.RSADecrypt(crypto.SHA1, "UnKnown", "", body.KeyAccess.WrappedKey)
	if err != nil {
		slog.WarnContext(ctx, "failure to decrypt dek", "err", err)
		return nil, err400("bad request")
	}

	slog.DebugContext(ctx, "verifying policy binding", "requestBody.policy", body.Policy)
	policy, err := verifyAndParsePolicy(ctx, body, symmetricKey)
	if err != nil {
		return nil, err
	}

	slog.DebugContext(ctx, "extracting policy", "requestBody.policy", body.Policy)
	// changed use the entities in the token to get the decisions
	tok := &authorization.Token{
		Id:  "rewrap-tok",
		Jwt: entity.Token,
	}

	access, err := canAccess(ctx, tok, *policy, p.SDK)

	if err != nil {
		slog.WarnContext(ctx, "Could not perform access decision!", "err", err)
		return nil, err403("forbidden")
	}

	if !access {
		slog.WarnContext(ctx, "Access Denied; no reason given")
		return nil, err403("forbidden")
	}

	asymEncrypt, err := ocrypto.NewAsymEncryption(body.ClientPublicKey)
	if err != nil {
		slog.WarnContext(ctx, "ocrypto.NewAsymEncryption:", "err", err)
	}

	rewrappedKey, err := asymEncrypt.Encrypt(symmetricKey)
	if err != nil {
		slog.WarnContext(ctx, "rewrap: ocrypto.AsymEncryption.encrypt failed", "err", err, "clientPublicKey", &body.ClientPublicKey)
		return nil, err400("bad key for rewrap")
	}

	return &kaspb.RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SessionPublicKey: "",
		SchemaVersion:    schemaVersion,
	}, nil
}

func (p *Provider) nanoTDFRewrap(body *RequestBody) (*kaspb.RewrapResponse, error) {
	headerReader := bytes.NewReader(body.KeyAccess.Header)

	header, err := sdk.ReadNanoTDFHeader(headerReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NanoTDF header: %w", err)
	}

	symmetricKey, err := p.CryptoProvider.GenerateNanoTDFSymmetricKey(header.EphemeralPublicKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
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
	sessionKey, err := p.CryptoProvider.GenerateNanoTDFSessionKey(privateKeyHandle, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	cipherText, err := wrapKeyAES(sessionKey, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	// see explanation why Public Key starts at position 2
	//https://github.com/wqx0532/hyperledger-fabric-gm-1/blob/master/bccsp/pkcs11/pkcs11.go#L480
	pubGoKey, err := ecdh.P256().NewPublicKey(publicKeyHandle[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to make public key") // Handle error, e.g., invalid public key format
	}

	pbk, err := x509.MarshalPKIXPublicKey(pubGoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public Key to PKIX")
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pbk,
	}
	pemString := string(pem.EncodeToMemory(pemBlock))

	return &kaspb.RewrapResponse{
		EntityWrappedKey: cipherText,
		SessionPublicKey: pemString,
		SchemaVersion:    schemaVersion,
	}, nil
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
