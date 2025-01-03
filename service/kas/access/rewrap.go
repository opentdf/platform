package access

import (
	"bytes"
	// "bytes"
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
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/kas/request"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const kTDF3Algorithm = "rsa:2048"
const kNanoAlgorithm = "ec:secp256r1"
const kFailedStatus = "fail"
const kPermitStatus = "permit"

type SignedRequestBody struct {
	RequestBody string `json:"requestBody"`
}

type RequestBody struct {
	AuthToken       string            `json:"authToken"`
	KeyAccess       request.KeyAccess `json:"keyAccess"`
	Policy          string            `json:"policy,omitempty"`
	Algorithm       string            `json:"algorithm,omitempty"`
	ClientPublicKey string            `json:"clientPublicKey"`
	PublicKey       interface{}       `json:"-"`
	SchemaVersion   string            `json:"schemaVersion,omitempty"`
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

func extractAndConvertV1SRTBody(body []byte) (request.Body, error) {
	var requestBody RequestBody
	if err := json.Unmarshal(body, &requestBody); err != nil {
		return request.Body{}, err
	}

	reqs := []*request.RewrapRequests{
		{
			KeyAccessObjectRequests: []*request.KeyAccessObjectRequest{
				{KeyAccessObjectID: "kao-0", KeyAccess: requestBody.KeyAccess},
			},
			Algorithm: requestBody.Algorithm,
			Policy: request.PolicyRequest{
				ID:   "policy-1",
				Body: requestBody.Policy,
			},
		},
	}

	return request.Body{
		ClientPublicKey: requestBody.ClientPublicKey,
		Requests:        reqs,
	}, nil
}

func extractSRTBody(ctx context.Context, headers http.Header, in *kaspb.RewrapRequest, logger logger.Logger) (*request.Body, bool, error) {
	isV1 := false
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
			return nil, false, err
		}
	} else {
		// verify and validate the request token
		var err error
		rbString, err = verifySRT(ctx, srt, dpopJWK, logger)
		if err != nil {
			return nil, false, err
		}
	}

	var requestBody request.Body
	err = json.Unmarshal([]byte(rbString), &requestBody)
	// if there are no requests then it could be a v1 request
	if err != nil || len(requestBody.Requests) == 0 {
		logger.WarnContext(ctx, "invalid request body! checking v1 SRT")
		requestBody, err = extractAndConvertV1SRTBody([]byte(rbString))
		if err != nil {
			return nil, false, err400("invalid request body")
		}
		isV1 = true
	}
	logger.DebugContext(ctx, "extracted request body", slog.Any("requestBody", requestBody))

	logger.DebugContext(ctx, "extract public key", "requestBody.ClientPublicKey", requestBody.ClientPublicKey)
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		logger.WarnContext(ctx, "missing clientPublicKey")
		return nil, isV1, err400("clientPublicKey failure")
	}

	// Try to parse the clientPublicKey
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.WarnContext(ctx, "failure to parse clientPublicKey", "err", err)
		return nil, isV1, err400("clientPublicKey parse failure")
	}
	// Check to make sure the clientPublicKey is a supported key type
	switch clientPublicKey.(type) {
	case *rsa.PublicKey:
		return &requestBody, isV1, nil
	case *ecdsa.PublicKey:
		return &requestBody, isV1, nil
	default:
		logger.WarnContext(ctx, fmt.Sprintf("clientPublicKey not a supported key, was [%T]", clientPublicKey))
		return nil, isV1, err400("clientPublicKey unsupported type")
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

func verifyAndParsePolicy(ctx context.Context, req *request.RewrapRequests, logger logger.Logger) (*request.Policy, error) {
	failed := false
	sDecPolicy, err := base64.StdEncoding.DecodeString(req.Policy.Body)
	if err != nil {
		logger.WarnContext(ctx, "unable to decode policy", "err", err)
		failed = true
	}
	decoder := json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy request.Policy
	err = decoder.Decode(&policy)
	if err != nil {
		logger.WarnContext(ctx, "unable to decode policy", "err", err)
		failed = true
	}
	req.Results.PolicyId = policy.UUID.String()

	for _, kao := range req.KeyAccessObjectRequests {
		if failed {
			failedKAORewrap(req.Results, kao, err400("bad request"))
			continue
		}
		actualHMAC, err := generateHMACDigest(ctx, []byte(req.Policy.Body), kao.SymmetricKey, logger)
		if err != nil {
			logger.WarnContext(ctx, "unable to generate policy hmac", "err", err)
			failedKAORewrap(req.Results, kao, err400("bad request"))
			continue
		}
		policyBinding, ok := kao.PolicyBinding.(string)
		if !ok {
			logger.WarnContext(ctx, "bad policy binding")
			failedKAORewrap(req.Results, kao, err400("bad request"))
			continue
		}

		expectedHMAC := make([]byte, base64.StdEncoding.DecodedLen(len(policyBinding)))
		n, err := base64.StdEncoding.Decode(expectedHMAC, []byte(policyBinding))
		if err == nil {
			n, err = hex.Decode(expectedHMAC, expectedHMAC[:n])
		}
		expectedHMAC = expectedHMAC[:n]
		if err != nil {
			logger.WarnContext(ctx, "invalid policy binding", "err", err)
			failedKAORewrap(req.Results, kao, err400("bad request"))
			continue
		}
		if !hmac.Equal(actualHMAC, expectedHMAC) {
			logger.WarnContext(ctx, "policy hmac mismatch", "policyBinding", policyBinding)
			failedKAORewrap(req.Results, kao, err400("bad request"))
			continue
		}
	}

	if failed {
		return nil, fmt.Errorf("invalid policy")
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
func failedKAORewrap(res *kaspb.RewrapResult, kao *request.KeyAccessObjectRequest, err error) *kaspb.KAORewrapResult {
	if kao.Processed {
		return nil
	}
	kao.Processed = true
	kaoRes := &kaspb.KAORewrapResult{
		KeyAccessObjectId: kao.KeyAccessObjectID,
		Status:            kFailedStatus,
		Result:            &kaspb.KAORewrapResult_Error{Error: err.Error()},
	}
	kao.Err = err
	res.Results = append(res.Results, kaoRes)
	return kaoRes
}

func markUnproccessedRequests(reqs []*request.RewrapRequests) {
	for _, req := range reqs {
		for _, kao := range req.KeyAccessObjectRequests {
			failedKAORewrap(req.Results, kao, err400("could not process request"))
		}
	}
}

func (p *Provider) Rewrap(ctx context.Context, req *connect.Request[kaspb.RewrapRequest]) (*connect.Response[kaspb.RewrapResponse], error) {
	in := req.Msg
	p.Logger.DebugContext(ctx, "REWRAP")

	body, isV1, err := extractSRTBody(ctx, req.Header(), in, *p.Logger)
	if err != nil {
		p.Logger.DebugContext(ctx, "unverifiable srt", "err", err)
		return nil, err
	}

	entityInfo, err := getEntityInfo(ctx, p.Logger)
	if err != nil {
		p.Logger.DebugContext(ctx, "no entity info", "err", err)
		return nil, err
	}

	resp := &kaspb.RewrapResponse{}

	var nanoReqs []*request.RewrapRequests
	var tdf3Reqs []*request.RewrapRequests
	for _, req := range body.Requests {
		switch {
		case req.Algorithm == kNanoAlgorithm:
			nanoReqs = append(nanoReqs, req)
		case req.Algorithm == "" || req.Algorithm == kTDF3Algorithm:
			tdf3Reqs = append(tdf3Reqs, req)
		default:
			// No algorithm: fail all Policy's KAOs
			var failedKAOs []*kaspb.KAORewrapResult
			for _, kao := range req.KeyAccessObjectRequests {
				failedKAOs = append(failedKAOs,
					failedKAORewrap(req.Results, kao, err400(fmt.Sprintf("invalid algorithm: %s", req.Algorithm))))
			}
			rewrapResult := &kaspb.RewrapResult{
				Results: failedKAOs,
			}
			resp.Responses = append(resp.Responses, rewrapResult)
		}
	}
	var requests []*request.RewrapRequests
	if len(tdf3Reqs) > 0 {
		p.tdf3Rewrap(ctx, tdf3Reqs, body.ClientPublicKey, entityInfo)
		requests = append(requests, tdf3Reqs...)
	}

	if len(nanoReqs) > 0 {
		resp.SessionPublicKey = p.nanoTDFRewrap(ctx, nanoReqs, body.ClientPublicKey, entityInfo)
		requests = append(requests, nanoReqs...)
	}

	markUnproccessedRequests(requests)
	for _, req := range requests {
		resp.Responses = append(resp.Responses, req.Results)
	}

	if isV1 {
		if len(resp.GetResponses()) != 1 || len(resp.GetResponses()[0].GetResults()) != 1 {
			return nil, fmt.Errorf("invalid request")
		}
		res := resp.GetResponses()[0].GetResults()[0]
		if res.GetStatus() == kFailedStatus {
			return nil, tdf3Reqs[0].KeyAccessObjectRequests[0].Err
		}
		resp.EntityWrappedKey = res.GetKasWrappedKey()
		resp.Metadata = res.GetMetadata()
	}

	return connect.NewResponse(resp), err
}

func (p *Provider) verifyRewrapRequests(ctx context.Context, req *request.RewrapRequests) (*request.Policy, error) {
	anyValidKAOs := false
	p.Logger.DebugContext(ctx, "extracting policy", "requestBody.policy", req.Policy)
	sDecPolicy, policyErr := base64.StdEncoding.DecodeString(req.Policy.Body)
	req.Results = &kaspb.RewrapResult{
		PolicyId: req.Policy.ID,
	}
	policy := &request.Policy{}
	if policyErr == nil {
		policyErr = json.Unmarshal(sDecPolicy, policy)
	}

	for _, kao := range req.KeyAccessObjectRequests {
		if policyErr != nil {
			failedKAORewrap(req.Results, kao, err400("bad request"))
			continue
		}
		var kidsToCheck []string
		if kao.KID != "" {
			kidsToCheck = []string{kao.KID}
		} else {
			p.Logger.InfoContext(ctx, "kid free kao")
			for _, k := range p.KASConfig.Keyring {
				if k.Algorithm == security.AlgorithmRSA2048 && k.Legacy {
					kidsToCheck = append(kidsToCheck, k.KID)
				}
			}
			if len(kidsToCheck) == 0 {
				p.Logger.WarnContext(ctx, "failure to find legacy kids for rsa")
				failedKAORewrap(req.Results, kao, err400("bad request"))
				continue
			}
		}

		var err error
		kao.SymmetricKey, err = p.CryptoProvider.RSADecrypt(crypto.SHA1, kidsToCheck[0], "", kao.WrappedKey)
		for _, kid := range kidsToCheck[1:] {
			p.Logger.WarnContext(ctx, "continue paging through legacy KIDs for kid free kao", "err", err)
			if err == nil {
				break
			}
			kao.SymmetricKey, err = p.CryptoProvider.RSADecrypt(crypto.SHA1, kid, "", kao.WrappedKey)
		}
		if err != nil {
			p.Logger.WarnContext(ctx, "failure to decrypt dek", "err", err)
			failedKAORewrap(req.Results, kao, err400("bad request"))
			continue
		}
		anyValidKAOs = true
	}

	if policyErr != nil {
		return nil, policyErr
	}

	if !anyValidKAOs {
		p.Logger.WarnContext(ctx, "no valid KAOs found")
		return policy, fmt.Errorf("no valid KAOs")
	}
	return policy, nil
}

func (p *Provider) tdf3Rewrap(ctx context.Context, requests []*request.RewrapRequests, clientPublicKey string, entity *entityInfo) {
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Tracer.Start(ctx, "rewrap-tdf3")
		defer span.End()
	}

	var policies []*request.Policy
	policyReqs := make(map[*request.Policy]*request.RewrapRequests)
	for _, req := range requests {
		policy, err := p.verifyRewrapRequests(ctx, req)
		if err != nil {
			continue
		}
		policies = append(policies, policy)
		policyReqs[policy] = req
	}

	tok := &authorization.Token{
		Id:  "rewrap-token",
		Jwt: entity.Token,
	}
	pdpAccessResults, accessErr := p.canAccess(ctx, tok, policies)
	if accessErr != nil {
		failAllKaos(requests, err403("could not perform access"))
		return
	}

	asymEncrypt, err := ocrypto.NewAsymEncryption(clientPublicKey)
	if err != nil {
		p.Logger.WarnContext(ctx, "ocrypto.NewAsymEncryption:", "err", err)
	}

	for _, pdpAccess := range pdpAccessResults {
		policy := pdpAccess.Policy
		req, ok := policyReqs[policy]
		if !ok { // this should not happen
			continue
		}
		access := pdpAccess.Access

		// Audit the TDF3 Rewrap
		kasPolicy := request.ConvertToAuditKasPolicy(*policy)

		for _, kao := range req.KeyAccessObjectRequests {
			policyBinding, _ := extractPolicyBinding(kao.PolicyBinding)
			auditEventParams := audit.RewrapAuditEventParams{
				Policy:        kasPolicy,
				IsSuccess:     access,
				TDFFormat:     "tdf3",
				Algorithm:     req.Algorithm,
				PolicyBinding: policyBinding,
			}

			if !access {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(req.Results, kao, err403("forbidden"))
				continue
			}

			rewrappedKey, err := asymEncrypt.Encrypt(kao.SymmetricKey)
			if err != nil {
				p.Logger.WarnContext(ctx, "rewrap: ocrypto.AsymEncryption.encrypt failed", "err", err, "clientPublicKey", clientPublicKey)
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(req.Results, kao, err400("bad key for rewrap"))
				continue
			}
			req.Results.Results = append(req.Results.Results, &kaspb.KAORewrapResult{
				KeyAccessObjectId: kao.KeyAccessObjectID,
				Status:            kPermitStatus,
				Result:            &kaspb.KAORewrapResult_KasWrappedKey{KasWrappedKey: rewrappedKey},
			})

			kao.Processed = true
			p.Logger.Audit.RewrapSuccess(ctx, auditEventParams)
		}
	}
}

func (p *Provider) nanoTDFRewrap(ctx context.Context, requests []*request.RewrapRequests, clientPublicKey string, entity *entityInfo) string {
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Tracer.Start(ctx, "rewrap-nanotdf")
		defer span.End()
	}

	var policies []*request.Policy
	policyReqs := make(map[*request.Policy]*request.RewrapRequests)

	for _, req := range requests {
		policy := p.verifyNanoRewrapRequests(ctx, req)
		if policy != nil {
			policies = append(policies, policy)
			policyReqs[policy] = req
		}
	}
	// do the access check
	tok := &authorization.Token{
		Id:  "rewrap-tok",
		Jwt: entity.Token,
	}

	pdpAccessResults, accessErr := p.canAccess(ctx, tok, policies)
	if accessErr != nil {
		failAllKaos(requests, err403("could not perform access"))
		return ""
	}

	privateKeyHandle, publicKeyHandle, err := p.CryptoProvider.GenerateEphemeralKasKeys()
	if err != nil {
		failAllKaos(requests, fmt.Errorf("failed to generate keypair: %w", err))
		return ""
	}
	sessionKey, err := p.CryptoProvider.GenerateNanoTDFSessionKey(privateKeyHandle, []byte(clientPublicKey))
	if err != nil {
		failAllKaos(requests, fmt.Errorf("failed to generate session key: %w", err))
		return ""
	}

	for _, pdpAccess := range pdpAccessResults {
		policy := pdpAccess.Policy
		req, ok := policyReqs[policy]
		if !ok { // this should not happen
			continue
		}
		access := pdpAccess.Access

		// Audit the Nano Rewrap
		kasPolicy := request.ConvertToAuditKasPolicy(*policy)

		for _, kao := range req.KeyAccessObjectRequests {
			auditEventParams := audit.RewrapAuditEventParams{
				Policy:    kasPolicy,
				IsSuccess: access,
				TDFFormat: "Nano",
				Algorithm: req.Algorithm,
			}

			if !access {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(req.Results, kao, err403("forbidden"))
				continue
			}
			cipherText, err := wrapKeyAES(sessionKey, kao.SymmetricKey)
			if err != nil {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(req.Results, kao, err403("forbidden"))
				continue
			}

			req.Results.Results = append(req.Results.Results, &kaspb.KAORewrapResult{
				KeyAccessObjectId: kao.KeyAccessObjectID,
				Status:            kPermitStatus,
				Result:            &kaspb.KAORewrapResult_KasWrappedKey{KasWrappedKey: cipherText},
			})

			kao.Processed = true
			p.Logger.Audit.RewrapSuccess(ctx, auditEventParams)
		}
	}
	return string(publicKeyHandle)
}

func (p *Provider) verifyNanoRewrapRequests(ctx context.Context, req *request.RewrapRequests) *request.Policy {
	for _, kao := range req.KeyAccessObjectRequests {
		// there should never be multiple KAOs in policy
		if len(req.KeyAccessObjectRequests) != 1 {
			failedKAORewrap(req.Results, kao, err400("NanoTDFs should not have multiple KAOs per Policy"))
			continue
		}

		headerReader := bytes.NewReader(kao.Header)
		header, _, err := sdk.NewNanoTDFHeaderFromReader(headerReader)
		if err != nil {
			failedKAORewrap(req.Results, kao, fmt.Errorf("failed to parse NanoTDF header: %w", err))
			return nil
		}
		// Lookup KID from nano header
		kid, err := header.GetKasURL().GetIdentifier()
		if err != nil {
			p.Logger.DebugContext(ctx, "nanoTDFRewrap GetIdentifier", "kid", kid, "err", err)
			// legacy nano with KID
			kid, err = p.lookupKid(ctx, security.AlgorithmECP256R1)
			if err != nil {
				p.Logger.ErrorContext(ctx, "failure to find default kid for ec", "err", err)
				failedKAORewrap(req.Results, kao, err400("bad request"))
				continue
			}
			p.Logger.DebugContext(ctx, "nanoTDFRewrap lookupKid", "kid", kid)
		}
		p.Logger.DebugContext(ctx, "nanoTDFRewrap", "kid", kid)
		ecCurve, err := header.ECCurve()
		if err != nil {
			failedKAORewrap(req.Results, kao, fmt.Errorf("ECCurve failed: %w", err))
			return nil
		}

		symmetricKey, err := p.CryptoProvider.GenerateNanoTDFSymmetricKey(kid, header.EphemeralKey, ecCurve)
		if err != nil {
			failedKAORewrap(req.Results, kao, fmt.Errorf("failed to generate symmetric key: %w", err))
			return nil
		}

		// extract the policy
		policy, err := extractNanoPolicy(symmetricKey, header)
		if err != nil {
			failedKAORewrap(req.Results, kao, fmt.Errorf("Error extracting policy: %w", err))
			return nil
		}

		// check the policy binding
		verify, err := header.VerifyPolicyBinding()
		if err != nil {
			failedKAORewrap(req.Results, kao, fmt.Errorf("failed to verify policy binding: %w", err))
			return nil
		}

		if !verify {
			failedKAORewrap(req.Results, kao, fmt.Errorf("policy binding verification failed"))
			return nil
		}
		kao.SymmetricKey = symmetricKey
		return policy
	}
	return nil
}

func extractNanoPolicy(symmetricKey []byte, header sdk.NanoTDFHeader) (*request.Policy, error) {
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

	var policy request.Policy
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

func failAllKaos(requests []*request.RewrapRequests, err error) {
	for _, req := range requests {
		for _, kao := range req.KeyAccessObjectRequests {
			failedKAORewrap(req.Results, kao, err)
		}
	}
}
