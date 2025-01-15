package access

import (
	"bytes"

	"google.golang.org/protobuf/encoding/protojson"

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

type kaoResult struct {
	ID    string
	Key   []byte
	Error error
}

type policyKAOResults map[string]map[string]kaoResult

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

func extractAndConvertV1SRTBody(body []byte) (kaspb.UnsignedRewrapRequest, error) {
	var requestBody RequestBody
	if err := json.Unmarshal(body, &requestBody); err != nil {
		return kaspb.UnsignedRewrapRequest{}, err
	}

	kao := requestBody.KeyAccess
	binding, err := json.Marshal(kao.PolicyBinding)
	if err != nil {
		return kaspb.UnsignedRewrapRequest{}, err
	}

	reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		{
			KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
				{KeyAccessObjectId: "kao-0", KeyAccessObject: &kaspb.KeyAccess{
					EncryptedMetadata: kao.EncryptedMetadata,
					PolicyBinding:     binding,
					Protocol:          kao.Protocol,
					KeyType:           kao.Type,
					KasUrl:            kao.URL,
					Kid:               kao.KID,
					SplitId:           kao.SID,
					WrappedKey:        kao.WrappedKey,
					Header:            kao.Header,
					Algorithm:         kao.Algorithm,
				}},
			},
			Algorithm: requestBody.Algorithm,
			Policy: &kaspb.UnsignedRewrapRequest_WithPolicy{
				Id:   "policy-1",
				Body: requestBody.Policy,
			},
		},
	}

	return kaspb.UnsignedRewrapRequest{
		ClientPublicKey: requestBody.ClientPublicKey,
		Requests:        reqs,
	}, nil
}

func extractSRTBody(ctx context.Context, headers http.Header, in *kaspb.RewrapRequest, logger logger.Logger) (*kaspb.UnsignedRewrapRequest, bool, error) {
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

	var requestBody kaspb.UnsignedRewrapRequest
	err = protojson.Unmarshal([]byte(rbString), &requestBody)
	// if there are no requests then it could be a v1 request
	if err != nil || len(requestBody.GetRequests()) == 0 {
		logger.WarnContext(ctx, "invalid request body! checking v1 SRT")
		requestBody, err = extractAndConvertV1SRTBody([]byte(rbString))
		if err != nil {
			return nil, false, err400("invalid request body")
		}
		isV1 = true
	}
	logger.DebugContext(ctx, "extracted request body", slog.Any("requestBody", requestBody.String()))

	logger.DebugContext(ctx, "extract public key", "requestBody.ClientPublicKey", requestBody.GetClientPublicKey())
	block, _ := pem.Decode([]byte(requestBody.GetClientPublicKey()))
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

func verifyPolicyBinding(ctx context.Context, policy []byte, kao *kaspb.UnsignedRewrapRequest_WithKeyAccessObject, symKey []byte, logger logger.Logger) error {
	actualHMAC, err := generateHMACDigest(ctx, policy, symKey, logger)
	if err != nil {
		logger.WarnContext(ctx, "unable to generate policy hmac", "err", err)
		return err400("bad request")
	}
	policyBinding, err := extractPolicyBinding(kao.GetKeyAccessObject().GetPolicyBinding())
	if err != nil {
		logger.WarnContext(ctx, "bad policy binding")
		return err400("bad request")
	}

	expectedHMAC := make([]byte, base64.StdEncoding.DecodedLen(len(policyBinding)))
	n, err := base64.StdEncoding.Decode(expectedHMAC, []byte(policyBinding))
	if err == nil {
		n, err = hex.Decode(expectedHMAC, expectedHMAC[:n])
	}
	expectedHMAC = expectedHMAC[:n]
	if err != nil {
		logger.WarnContext(ctx, "invalid policy binding", "err", err)
		return err400("bad request")
	}
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		logger.WarnContext(ctx, "policy hmac mismatch", "policyBinding", policyBinding)
		return err400("bad request")
	}

	return nil
}

func extractPolicyBinding(policyBindingBytes []byte) (string, error) {
	var policyBinding interface{}
	if err := json.Unmarshal(policyBindingBytes, &policyBinding); err != nil {
		return "", fmt.Errorf("could not decode binding")
	}
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
func failedKAORewrap(res map[string]kaoResult, kao *kaspb.UnsignedRewrapRequest_WithKeyAccessObject, err error) {
	res[kao.GetKeyAccessObjectId()] = kaoResult{
		ID:    kao.GetKeyAccessObjectId(),
		Error: err,
	}
}

func addResultsToResponse(response *kaspb.RewrapResponse, result policyKAOResults) {
	for policyID, policyMap := range result {
		policyResults := &kaspb.PolicyRewrapResult{
			PolicyId: policyID,
		}
		for kaoID, kaoRes := range policyMap {
			kaoResult := &kaspb.KeyAccessRewrapResult{
				KeyAccessObjectId: kaoID,
			}
			switch {
			case kaoRes.Error != nil:
				kaoResult.Status = kFailedStatus
				kaoResult.Result = &kaspb.KeyAccessRewrapResult_Error{Error: kaoRes.Error.Error()}
			case kaoRes.Key != nil:
				kaoResult.Status = kPermitStatus
				kaoResult.Result = &kaspb.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: kaoRes.Key}
			default:
				kaoResult.Status = kFailedStatus
				kaoResult.Result = &kaspb.KeyAccessRewrapResult_Error{Error: "kao not processed by kas"}
			}
			policyResults.Results = append(policyResults.Results, kaoResult)
		}
		response.Responses = append(response.Responses, policyResults)
	}
}
func getMapValue[Map ~map[K]V, K comparable, V any](m Map) *V {
	for _, v := range m {
		return &v
	}
	return nil
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

	var nanoReqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest
	var tdf3Reqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest
	for _, req := range body.GetRequests() {
		switch {
		case req.GetAlgorithm() == kNanoAlgorithm:
			nanoReqs = append(nanoReqs, req)
		case req.GetAlgorithm() == "":
			req.Algorithm = kTDF3Algorithm
			tdf3Reqs = append(tdf3Reqs, req)
		default:
			tdf3Reqs = append(tdf3Reqs, req)
		}
	}
	var results policyKAOResults
	if len(tdf3Reqs) > 0 {
		results = p.tdf3Rewrap(ctx, tdf3Reqs, body.GetClientPublicKey(), entityInfo)
		addResultsToResponse(resp, results)
	} else {
		resp.SessionPublicKey, results = p.nanoTDFRewrap(ctx, nanoReqs, body.GetClientPublicKey(), entityInfo)
		addResultsToResponse(resp, results)
	}

	if isV1 {
		if len(results) != 1 {
			return nil, fmt.Errorf("invalid request")
		}
		kaoResults := *getMapValue(results)
		if len(kaoResults) != 1 {
			return nil, fmt.Errorf("invalid request")
		}
		kao := *getMapValue(kaoResults)

		if kao.Error != nil {
			return nil, kao.Error
		}
		resp.EntityWrappedKey = kao.Key //nolint:staticcheck // deprecated but keeping behavior for backwards compatibility
	}

	return connect.NewResponse(resp), err
}

func (p *Provider) verifyRewrapRequests(ctx context.Context, req *kaspb.UnsignedRewrapRequest_WithPolicyRequest) (*Policy, map[string]kaoResult, error) {
	results := make(map[string]kaoResult)
	anyValidKAOs := false
	p.Logger.DebugContext(ctx, "extracting policy", "requestBody.policy", req.GetPolicy())
	sDecPolicy, policyErr := base64.StdEncoding.DecodeString(req.GetPolicy().GetBody())
	policy := &Policy{}
	if policyErr == nil {
		policyErr = json.Unmarshal(sDecPolicy, policy)
	}

	for _, kao := range req.GetKeyAccessObjects() {
		if policyErr != nil {
			failedKAORewrap(results, kao, err400("bad request"))
			continue
		}
		var kidsToCheck []string
		if kao.GetKeyAccessObject().GetKid() != "" {
			kidsToCheck = []string{kao.GetKeyAccessObject().GetKid()}
		} else {
			p.Logger.InfoContext(ctx, "kid free kao")
			for _, k := range p.KASConfig.Keyring {
				if k.Algorithm == security.AlgorithmRSA2048 && k.Legacy {
					kidsToCheck = append(kidsToCheck, k.KID)
				}
			}
			if len(kidsToCheck) == 0 {
				p.Logger.WarnContext(ctx, "failure to find legacy kids for rsa")
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}
		}

		symKey, err := p.CryptoProvider.RSADecrypt(crypto.SHA1, kidsToCheck[0], "", kao.GetKeyAccessObject().GetWrappedKey())
		for _, kid := range kidsToCheck[1:] {
			p.Logger.WarnContext(ctx, "continue paging through legacy KIDs for kid free kao", "err", err)
			if err == nil {
				break
			}
			symKey, err = p.CryptoProvider.RSADecrypt(crypto.SHA1, kid, "", kao.GetKeyAccessObject().GetWrappedKey())
		}
		if err != nil {
			p.Logger.WarnContext(ctx, "failure to decrypt dek", "err", err)
			failedKAORewrap(results, kao, err400("bad request"))
			continue
		}

		err = verifyPolicyBinding(ctx, []byte(req.GetPolicy().GetBody()), kao, symKey, *p.Logger)
		if err != nil {
			failedKAORewrap(results, kao, err)
			continue
		}
		results[kao.GetKeyAccessObjectId()] = kaoResult{
			ID:  kao.GetKeyAccessObjectId(),
			Key: symKey,
		}

		anyValidKAOs = true
	}

	if policyErr != nil {
		return nil, results, policyErr
	}

	if !anyValidKAOs {
		p.Logger.WarnContext(ctx, "no valid KAOs found")
		return policy, results, fmt.Errorf("no valid KAOs")
	}

	return policy, results, nil
}

func (p *Provider) tdf3Rewrap(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, clientPublicKey string, entity *entityInfo) policyKAOResults {
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Tracer.Start(ctx, "rewrap-tdf3")
		defer span.End()
	}

	results := make(policyKAOResults)
	var policies []*Policy
	policyReqs := make(map[*Policy]*kaspb.UnsignedRewrapRequest_WithPolicyRequest)
	for _, req := range requests {
		policy, kaoResults, err := p.verifyRewrapRequests(ctx, req)
		results[req.GetPolicy().GetId()] = kaoResults
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
		failAllKaos(requests, results, err403("could not perform access"))
		return results
	}

	asymEncrypt, err := ocrypto.NewAsymEncryption(clientPublicKey)
	if err != nil {
		p.Logger.WarnContext(ctx, "ocrypto.NewAsymEncryption:", "err", err)
	}

	for _, pdpAccess := range pdpAccessResults {
		policy := pdpAccess.Policy
		req, ok := policyReqs[policy]
		kaoResults := results[req.GetPolicy().GetId()]
		if !ok { // this should not happen
			continue
		}
		access := pdpAccess.Access

		// Audit the TDF3 Rewrap
		kasPolicy := ConvertToAuditKasPolicy(*policy)

		for _, kao := range req.GetKeyAccessObjects() {
			kaoRes := kaoResults[kao.GetKeyAccessObjectId()]
			if kaoRes.Error != nil {
				continue
			}

			policyBinding, _ := extractPolicyBinding(kao.GetKeyAccessObject().GetPolicyBinding())
			auditEventParams := audit.RewrapAuditEventParams{
				Policy:        kasPolicy,
				IsSuccess:     access,
				TDFFormat:     "tdf3",
				Algorithm:     req.GetAlgorithm(),
				PolicyBinding: policyBinding,
			}

			if !access {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(kaoResults, kao, err403("forbidden"))
				continue
			}

			rewrappedKey, err := asymEncrypt.Encrypt(kaoRes.Key)
			if err != nil {
				p.Logger.WarnContext(ctx, "rewrap: ocrypto.AsymEncryption.encrypt failed", "err", err, "clientPublicKey", clientPublicKey)
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(kaoResults, kao, err400("bad key for rewrap"))
				continue
			}
			kaoResults[kao.GetKeyAccessObjectId()] = kaoResult{
				ID:  kao.GetKeyAccessObjectId(),
				Key: rewrappedKey,
			}

			p.Logger.Audit.RewrapSuccess(ctx, auditEventParams)
		}
	}
	return results
}

func (p *Provider) nanoTDFRewrap(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, clientPublicKey string, entity *entityInfo) (string, policyKAOResults) {
	results := make(policyKAOResults)
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Tracer.Start(ctx, "rewrap-nanotdf")
		defer span.End()
	}

	var policies []*Policy
	policyReqs := make(map[*Policy]*kaspb.UnsignedRewrapRequest_WithPolicyRequest)

	for _, req := range requests {
		policy, kaoResults := p.verifyNanoRewrapRequests(ctx, req)
		results[req.GetPolicy().GetId()] = kaoResults
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
		failAllKaos(requests, results, err403("could not perform access"))
		return "", results
	}

	privateKeyHandle, publicKeyHandle, err := p.CryptoProvider.GenerateEphemeralKasKeys()
	if err != nil {
		failAllKaos(requests, results, fmt.Errorf("failed to generate keypair: %w", err))
		return "", results
	}
	sessionKey, err := p.CryptoProvider.GenerateNanoTDFSessionKey(privateKeyHandle, []byte(clientPublicKey))
	if err != nil {
		p.Logger.DebugContext(ctx, "GenerateNanoTDFSessionKey", "err", err)
		failAllKaos(requests, results, fmt.Errorf("failed to generate session key: %w", err))
		return "", results
	}

	for _, pdpAccess := range pdpAccessResults {
		policy := pdpAccess.Policy
		req, ok := policyReqs[policy]
		if !ok { // this should not happen
			continue
		}
		kaoResults := results[req.GetPolicy().GetId()]
		access := pdpAccess.Access

		// Audit the Nano Rewrap
		kasPolicy := ConvertToAuditKasPolicy(*policy)

		for _, kao := range req.GetKeyAccessObjects() {
			kaoInfo := kaoResults[kao.GetKeyAccessObjectId()]
			if kaoInfo.Error != nil {
				continue
			}

			auditEventParams := audit.RewrapAuditEventParams{
				Policy:    kasPolicy,
				IsSuccess: access,
				TDFFormat: "Nano",
				Algorithm: req.GetAlgorithm(),
			}

			if !access {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(kaoResults, kao, err403("forbidden"))
				continue
			}
			cipherText, err := wrapKeyAES(sessionKey, kaoInfo.Key)
			if err != nil {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(kaoResults, kao, err403("forbidden"))
				continue
			}

			kaoResults[kao.GetKeyAccessObjectId()] = kaoResult{
				ID:  kao.GetKeyAccessObjectId(),
				Key: cipherText,
			}

			p.Logger.Audit.RewrapSuccess(ctx, auditEventParams)
		}
	}
	return string(publicKeyHandle), results
}

func (p *Provider) verifyNanoRewrapRequests(ctx context.Context, req *kaspb.UnsignedRewrapRequest_WithPolicyRequest) (*Policy, map[string]kaoResult) {
	results := make(map[string]kaoResult)

	for _, kao := range req.GetKeyAccessObjects() {
		// there should never be multiple KAOs in policy
		if len(req.GetKeyAccessObjects()) != 1 {
			failedKAORewrap(results, kao, err400("NanoTDFs should not have multiple KAOs per Policy"))
			continue
		}

		headerReader := bytes.NewReader(kao.GetKeyAccessObject().GetHeader())
		header, _, err := sdk.NewNanoTDFHeaderFromReader(headerReader)
		if err != nil {
			failedKAORewrap(results, kao, fmt.Errorf("failed to parse NanoTDF header: %w", err))
			return nil, results
		}
		// Lookup KID from nano header
		kid, err := header.GetKasURL().GetIdentifier()
		if err != nil {
			p.Logger.DebugContext(ctx, "nanoTDFRewrap GetIdentifier", "kid", kid, "err", err)
			// legacy nano with KID
			kid, err = p.lookupKid(ctx, security.AlgorithmECP256R1)
			if err != nil {
				p.Logger.ErrorContext(ctx, "failure to find default kid for ec", "err", err)
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}
			p.Logger.DebugContext(ctx, "nanoTDFRewrap lookupKid", "kid", kid)
		}
		p.Logger.DebugContext(ctx, "nanoTDFRewrap", "kid", kid)
		ecCurve, err := header.ECCurve()
		if err != nil {
			failedKAORewrap(results, kao, fmt.Errorf("ECCurve failed: %w", err))
			return nil, results
		}

		symmetricKey, err := p.CryptoProvider.GenerateNanoTDFSymmetricKey(kid, header.EphemeralKey, ecCurve)
		if err != nil {
			failedKAORewrap(results, kao, fmt.Errorf("failed to generate symmetric key: %w", err))
			return nil, results
		}

		// extract the policy
		policy, err := extractNanoPolicy(symmetricKey, header)
		if err != nil {
			failedKAORewrap(results, kao, fmt.Errorf("Error extracting policy: %w", err))
			return nil, results
		}

		// check the policy binding
		verify, err := header.VerifyPolicyBinding()
		if err != nil {
			failedKAORewrap(results, kao, fmt.Errorf("failed to verify policy binding: %w", err))
			return nil, results
		}

		if !verify {
			failedKAORewrap(results, kao, fmt.Errorf("policy binding verification failed"))
			return nil, results
		}
		results[kao.GetKeyAccessObjectId()] = kaoResult{
			ID:  kao.GetKeyAccessObjectId(),
			Key: symmetricKey,
		}
		return policy, results
	}
	return nil, results
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

func failAllKaos(reqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, results policyKAOResults, err error) {
	for _, req := range reqs {
		for _, kao := range req.GetKeyAccessObjects() {
			failedKAORewrap(results[req.GetPolicy().GetId()], kao, err)
		}
	}
}
