package access

import (
	"bytes"
	"context"
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
	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/entity"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/internal/security"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/logger/audit"
	ctxAuth "github.com/opentdf/platform/service/pkg/auth"
	"github.com/opentdf/platform/service/trust"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	kTDF3Algorithm                = "rsa:2048"
	kNanoAlgorithm                = "ec:secp256r1"
	kFailedStatus                 = "fail"
	kPermitStatus                 = "permit"
	additionalRewrapContextHeader = "X-Rewrap-Additional-Context"
	requiredObligationsHeader     = "X-Required-Obligations"
)

var (
	ErrDecodingRewrapContext     = errors.New("failed to decode additional rewrap context")
	ErrUnmarshalingRewrapContext = errors.New("failed to unmarshal additional rewrap context")
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

type kaoResult struct {
	ID       string
	DEK      ocrypto.ProtectedKey
	Encapped []byte
	Error    error

	// Optional: Present for EC wrapped responses
	EphemeralPublicKey  []byte
	RequiredObligations []string

	// Only populated for Nano auditing
	KeyID         string
	PolicyBinding string
}

// From policy ID to KAO ID to result
type policyKAOResults map[string]map[string]kaoResult

type ObligationCtx struct {
	FulfillableFQNs []string `json:"fulfillableFQNs,omitempty"`
}

type AdditionalRewrapContext struct {
	Obligations ObligationCtx `json:"obligations"`
}

const (
	kNanoTDFGMACLength = 8
	ErrUser            = Error("request error")
	ErrInternal        = Error("internal error")

	ErrNanoTDFPolicyModeUnsupported = Error("unsupported policy mode")
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

func err500(s string) error {
	return connect.NewError(connect.CodeInternal, errors.Join(ErrInternal, status.Error(codes.Internal, s)))
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
		logger.WarnContext(ctx,
			"unable to verify request token",
			slog.String("srt", srt),
			slog.Any("jwk", dpopJWK),
			slog.Any("err", err),
		)
		return "", err401("unable to verify request token")
	}
	return justRequestBody(ctx, token, logger)
}

func noverify(ctx context.Context, srt string, logger logger.Logger) (string, error) {
	token, err := jwt.Parse([]byte(srt), jwt.WithVerify(false), jwt.WithAcceptableSkew(acceptableSkew))
	if err != nil {
		logger.WarnContext(ctx, "unable to validate or parse token", slog.Any("error", err))
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
	// ignore errors, maybe nanoTDF
	binding, _ := extractPolicyBinding(kao.PolicyBinding)

	reqs := []*kaspb.UnsignedRewrapRequest_WithPolicyRequest{
		{
			KeyAccessObjects: []*kaspb.UnsignedRewrapRequest_WithKeyAccessObject{
				{
					KeyAccessObjectId: "kao-0",
					KeyAccessObject: &kaspb.KeyAccess{
						EncryptedMetadata:  kao.EncryptedMetadata,
						PolicyBinding:      &kaspb.PolicyBinding{Hash: binding, Algorithm: kao.Algorithm},
						Protocol:           kao.Protocol,
						KeyType:            kao.Type,
						KasUrl:             kao.URL,
						Kid:                kao.KID,
						SplitId:            kao.SID,
						WrappedKey:         kao.WrappedKey,
						Header:             kao.Header,
						EphemeralPublicKey: kao.EphemeralPublicKey,
					},
				},
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
		logger.InfoContext(ctx, "legacy Client: Processing X-Virtrupubkey")
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
			logger.ErrorContext(ctx, "unable to load RSA verifier", slog.Any("error", err))
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
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal([]byte(rbString), &requestBody)
	// if there are no requests then it could be a v1 request
	if err != nil {
		logger.WarnContext(ctx,
			"invalid SRT",
			slog.Any("err_v2", err),
			slog.String("srt", rbString),
		)
		return nil, false, err400("invalid request body")
	}
	if len(requestBody.GetRequests()) == 0 {
		logger.DebugContext(ctx, "legacy v1 SRT")
		var errv1 error

		if requestBody, errv1 = extractAndConvertV1SRTBody([]byte(rbString)); errv1 != nil {
			logger.WarnContext(ctx,
				"invalid SRT",
				slog.Any("err_v1", errv1),
				slog.String("srt", rbString),
				slog.String("rewrap.body", requestBody.String()),
			)
			return nil, false, err400("invalid request body")
		}
		isV1 = true
	}
	// TODO: this log is too big and should be reconsidered or removed
	logger.DebugContext(ctx,
		"extracted request body",
		slog.String("rewrap_body", requestBody.String()),
		slog.String("rewrap_srt", rbString),
	)

	block, _ := pem.Decode([]byte(requestBody.GetClientPublicKey()))
	if block == nil {
		logger.WarnContext(ctx, "missing clientPublicKey")
		return nil, isV1, err400("clientPublicKey failure")
	}

	// Try to parse the clientPublicKey
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		logger.WarnContext(ctx, "failure to parse clientPublicKey", slog.Any("error", err))
		return nil, isV1, err400("clientPublicKey parse failure")
	}
	// Check to make sure the clientPublicKey is a supported key type
	switch clientPublicKey.(type) {
	case *rsa.PublicKey:
		return &requestBody, isV1, nil
	case *ecdsa.PublicKey:
		return &requestBody, isV1, nil
	default:
		logger.WarnContext(ctx, "unsupported clientPublicKey type", slog.String("type", fmt.Sprintf("%T", clientPublicKey)))
		return nil, isV1, err400("clientPublicKey unsupported type")
	}
}

func verifyPolicyBinding(ctx context.Context, policy []byte, kao *kaspb.UnsignedRewrapRequest_WithKeyAccessObject, symKey []byte, logger logger.Logger) error {
	actualHMAC, err := generateHMACDigest(ctx, policy, symKey, logger)
	if err != nil {
		logger.WarnContext(ctx, "unable to generate policy hmac", slog.Any("error", err))
		return err400("bad request")
	}

	policyBinding := kao.GetKeyAccessObject().GetPolicyBinding().GetHash()
	expectedHMAC := make([]byte, base64.StdEncoding.DecodedLen(len(policyBinding)))
	n, err := base64.StdEncoding.Decode(expectedHMAC, []byte(policyBinding))
	if err == nil {
		n, err = hex.Decode(expectedHMAC, expectedHMAC[:n])
	}
	expectedHMAC = expectedHMAC[:n]
	if err != nil {
		logger.WarnContext(ctx, "invalid policy binding", slog.Any("error", err))
		return err400("bad request")
	}
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		//nolint:sloglint // usage of camelCase is intentional
		logger.WarnContext(ctx, "policy hmac mismatch", slog.String("policyBinding", policyBinding))
		return err400("bad request")
	}

	return nil
}

func extractPolicyBinding(policyBinding interface{}) (string, error) {
	switch v := policyBinding.(type) {
	case string:
		if v == "" {
			return "", errors.New("empty policy binding")
		}
		return v, nil
	case map[string]interface{}:
		if hash, ok := v["hash"].(string); ok {
			if hash == "" {
				return "", errors.New("empty policy binding hash field")
			}
			return hash, nil
		}
		return "", errors.New("invalid policy binding object, missing 'hash' field")
	default:
		return "", errors.New("unsupported policy binding type")
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

func failedKAORewrapWithObligations(res map[string]kaoResult, kao *kaspb.UnsignedRewrapRequest_WithKeyAccessObject, err error, requiredObligations []string) {
	res[kao.GetKeyAccessObjectId()] = kaoResult{
		ID:                  kao.GetKeyAccessObjectId(),
		Error:               err,
		RequiredObligations: requiredObligations,
	}
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
			// Add metadata
			kaoResult := &kaspb.KeyAccessRewrapResult{
				KeyAccessObjectId: kaoID,
			}
			switch {
			case kaoRes.Error != nil:
				kaoResult.Status = kFailedStatus
				kaoResult.Result = &kaspb.KeyAccessRewrapResult_Error{Error: kaoRes.Error.Error()}
			case kaoRes.Encapped != nil:
				kaoResult.Status = kPermitStatus
				kaoResult.Result = &kaspb.KeyAccessRewrapResult_KasWrappedKey{KasWrappedKey: kaoRes.Encapped}
			default:
				kaoResult.Status = kFailedStatus
				kaoResult.Result = &kaspb.KeyAccessRewrapResult_Error{Error: "kao not processed by kas"}
			}
			kaoResult.Metadata = createKAOMetadata(kaoRes.RequiredObligations)
			policyResults.Results = append(policyResults.Results, kaoResult)
		}
		response.Responses = append(response.Responses, policyResults)
	}
}

// Gets the only value in a singleton map, or an arbitrary value from a map with multiple values.
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
		p.Logger.DebugContext(ctx, "unverifiable srt", slog.Any("error", err))
		return nil, err
	}

	entityInfo, err := getEntityInfo(ctx, p.Logger)
	if err != nil {
		p.Logger.DebugContext(ctx, "no entity info", slog.Any("error", err))
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
	additionalRewrapContext, err := getAdditionalRewrapContext(req.Header())
	if err != nil {
		p.Logger.WarnContext(ctx, "failed to get additional rewrap context", slog.Any("error", err))
		return nil, err400(err.Error())
	}
	if len(tdf3Reqs) > 0 {
		resp.SessionPublicKey, results = p.tdf3Rewrap(ctx, tdf3Reqs, body.GetClientPublicKey(), entityInfo, additionalRewrapContext)
		addResultsToResponse(resp, results)
	} else {
		resp.SessionPublicKey, results = p.nanoTDFRewrap(ctx, nanoReqs, body.GetClientPublicKey(), entityInfo, additionalRewrapContext)
		addResultsToResponse(resp, results)
	}

	if isV1 {
		if len(results) != 1 {
			p.Logger.WarnContext(ctx, "status 400 due to wrong result set size", slog.Any("results", results))
			return nil, err400("invalid request")
		}
		kaoResults := *getMapValue(results)
		if len(kaoResults) != 1 {
			p.Logger.WarnContext(ctx,
				"status 400 due to wrong result set size",
				slog.Any("kao_results", kaoResults),
				slog.Any("results", results),
			)
			return nil, err400("invalid request")
		}
		kao := *getMapValue(kaoResults)

		if kao.Error != nil {
			p.Logger.DebugContext(ctx, "forwarding legacy err", slog.Any("error", kao.Error))
			return nil, kao.Error
		}
		resp.EntityWrappedKey = kao.Encapped //nolint:staticcheck // deprecated but keeping behavior for backwards compatibility
	}

	return connect.NewResponse(resp), nil
}

func (p *Provider) verifyRewrapRequests(ctx context.Context, req *kaspb.UnsignedRewrapRequest_WithPolicyRequest) (*Policy, map[string]kaoResult, error) {
	ctx, span := p.Start(ctx, "tdf3Rewrap")
	defer span.End()

	results := make(map[string]kaoResult)
	anyValidKAOs := false

	p.Logger.DebugContext(ctx, "extracting policy", slog.Any("policy", req.GetPolicy()))
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

		var dek ocrypto.ProtectedKey
		var err error
		switch kao.GetKeyAccessObject().GetKeyType() {
		case "ec-wrapped":

			if !p.ECTDFEnabled && !p.Preview.ECTDFEnabled {
				p.Logger.WarnContext(ctx, "ec-wrapped not enabled")
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}

			// Get the ephemeral public key in PEM format
			ephemeralPubKeyPEM := kao.GetKeyAccessObject().GetEphemeralPublicKey()

			// Get EC key size and convert to mode
			keySize, err := ocrypto.GetECKeySize([]byte(ephemeralPubKeyPEM))
			if err != nil {
				p.Logger.WarnContext(ctx,
					"failed to get EC key size",
					slog.Any("kao", kao),
					slog.Any("error", err),
				)
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}

			mode, err := ocrypto.ECSizeToMode(keySize)
			if err != nil {
				p.Logger.WarnContext(ctx,
					"failed to convert key size to mode",
					slog.Any("kao", kao),
					slog.Any("error", err),
				)
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}

			// Parse the PEM public key
			block, _ := pem.Decode([]byte(ephemeralPubKeyPEM))
			if block == nil {
				p.Logger.WarnContext(ctx,
					"failed to decode PEM block",
					slog.Any("kao", kao),
					slog.Any("error", err),
				)
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				p.Logger.WarnContext(ctx,
					"failed to parse public key",
					slog.Any("kao", kao),
					slog.Any("error", err),
				)
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}

			ecPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				p.Logger.WarnContext(ctx, "not an EC public key", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}

			// Compress the public key
			compressedKey, err := ocrypto.CompressedECPublicKey(mode, *ecPub)
			if err != nil {
				p.Logger.WarnContext(ctx, "failed to compress public key", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}

			kid := trust.KeyIdentifier(kao.GetKeyAccessObject().GetKid())
			dek, err = p.KeyDelegator.Decrypt(ctx, kid, kao.GetKeyAccessObject().GetWrappedKey(), compressedKey)
			if err != nil {
				p.Logger.WarnContext(ctx, "failed to decrypt EC key", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}
		case "wrapped":
			var kidsToCheck []trust.KeyIdentifier
			if kao.GetKeyAccessObject().GetKid() != "" {
				kid := trust.KeyIdentifier(kao.GetKeyAccessObject().GetKid())
				kidsToCheck = []trust.KeyIdentifier{kid}
			} else {
				kidsToCheck = p.listLegacyKeys(ctx)
				if len(kidsToCheck) == 0 {
					p.Logger.WarnContext(ctx, "failure to find legacy kids for rsa")
					failedKAORewrap(results, kao, err400("bad request"))
					continue
				}
			}

			dek, err = p.KeyDelegator.Decrypt(ctx, kidsToCheck[0], kao.GetKeyAccessObject().GetWrappedKey(), nil)
			for _, kid := range kidsToCheck[1:] {
				p.Logger.WarnContext(ctx, "continue paging through legacy KIDs for kid free kao", slog.Any("error", err))
				if err == nil {
					break
				}
				dek, err = p.KeyDelegator.Decrypt(ctx, kid, kao.GetKeyAccessObject().GetWrappedKey(), nil)
			}
		}
		if err != nil {
			p.Logger.WarnContext(ctx, "failure to decrypt dek", slog.Any("error", err))
			failedKAORewrap(results, kao, err400("bad request"))
			continue
		}

		// Store policy binding in context for verification
		policyBindingB64Encoded := kao.GetKeyAccessObject().GetPolicyBinding().GetHash()
		policyBinding := make([]byte, base64.StdEncoding.DecodedLen(len(policyBindingB64Encoded)))
		n, err := base64.StdEncoding.Decode(policyBinding, []byte(policyBindingB64Encoded))
		if err != nil {
			p.Logger.WarnContext(ctx, "invalid policy binding encoding", slog.Any("error", err))
			failedKAORewrap(results, kao, err400("bad request"))
			continue
		}
		if n == 64 { //nolint:mnd // 32 bytes of hex encoded data = 256 bit sha-2
			// Sometimes the policy binding is a b64 encoded hex encoded string
			// Decode it again if so.
			dehexed := make([]byte, hex.DecodedLen(n))
			_, err = hex.Decode(dehexed, policyBinding[:n])
			if err == nil {
				policyBinding = dehexed
			}
		}

		// Verify policy binding using the UnwrappedKeyData interface
		if err := dek.VerifyBinding(ctx, []byte(req.GetPolicy().GetBody()), policyBinding); err != nil {
			p.Logger.WarnContext(ctx, "failure to verify policy binding", slog.Any("error", err))
			failedKAORewrap(results, kao, err400("bad request"))
			continue
		}

		results[kao.GetKeyAccessObjectId()] = kaoResult{
			ID:  kao.GetKeyAccessObjectId(),
			DEK: dek,
		}

		anyValidKAOs = true
	}

	if policyErr != nil {
		return nil, results, policyErr
	}

	if !anyValidKAOs {
		p.Logger.WarnContext(ctx, "no valid KAOs found")
		return policy, results, errors.New("no valid KAOs")
	}

	return policy, results, nil
}

func (p *Provider) listLegacyKeys(ctx context.Context) []trust.KeyIdentifier {
	var kidsToCheck []trust.KeyIdentifier
	p.Logger.InfoContext(ctx, "kid free kao")
	if len(p.Keyring) > 0 {
		// Using deprecated 'keyring' feature for lookup
		for _, k := range p.Keyring {
			if k.Algorithm == security.AlgorithmRSA2048 && k.Legacy {
				kidsToCheck = append(kidsToCheck, trust.KeyIdentifier(k.KID))
			}
		}
		return kidsToCheck
	}

	k, err := p.KeyDelegator.ListKeysWith(ctx, trust.ListKeyOptions{LegacyOnly: true})
	if err != nil {
		p.Logger.WarnContext(ctx, "checkpoint KeyIndex.ListKeys failed", slog.Any("error", err))
	} else {
		for _, key := range k {
			if key.Algorithm() == ocrypto.RSA2048Key && key.IsLegacy() {
				kidsToCheck = append(kidsToCheck, key.ID())
			}
		}
	}
	return kidsToCheck
}

func (p *Provider) tdf3Rewrap(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, clientPublicKey string, entityInfo *entityInfo, additionalRewrapContext *AdditionalRewrapContext) (string, policyKAOResults) {
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Start(ctx, "rewrap-tdf3")
		defer span.End()
	}

	results := make(policyKAOResults)
	var policies []*Policy
	policyReqs := make(map[*Policy]*kaspb.UnsignedRewrapRequest_WithPolicyRequest)
	for _, req := range requests {
		policy, kaoResults, err := p.verifyRewrapRequests(ctx, req)
		policyID := req.GetPolicy().GetId()
		results[policyID] = kaoResults
		if err != nil {
			p.Logger.WarnContext(ctx,
				"rewrap: verifyRewrapRequests failed",
				slog.String("policy_id", policyID),
				slog.Any("error", err),
			)
			continue
		}
		policies = append(policies, policy)
		policyReqs[policy] = req
	}

	tok := &entity.Token{
		EphemeralId: "rewrap-token",
		Jwt:         entityInfo.Token,
	}

	pdpAccessResults, accessErr := p.canAccess(ctx, tok, policies, additionalRewrapContext.Obligations.FulfillableFQNs)
	if accessErr != nil {
		p.Logger.DebugContext(ctx,
			"tdf3rewrap: cannot access policy",
			slog.Any("policies", policies),
			slog.Any("error", accessErr),
		)
		failAllKaos(requests, results, err500("could not perform access"))
		return "", results
	}

	asymEncrypt, err := ocrypto.FromPublicPEMWithSalt(clientPublicKey, security.TDFSalt(), nil)
	if err != nil {
		p.Logger.WarnContext(ctx, "ocrypto.NewAsymEncryption", slog.Any("error", err))
		failAllKaos(requests, results, err400("invalid request"))
		return "", results
	}
	encap := security.OCEncapsulator{PublicKeyEncryptor: asymEncrypt}

	var sessionKey string
	if e, ok := asymEncrypt.(ocrypto.ECEncryptor); ok {
		sessionKey, err = e.PublicKeyInPemFormat()
		if err != nil {
			p.Logger.ErrorContext(ctx, "unable to serialize ephemeral key", slog.Any("error", err))
			// This may be a 500, but could also be caused by a bad clientPublicKey
			failAllKaos(requests, results, err400("invalid request"))
			return "", results
		}
		if !p.ECTDFEnabled && !p.Preview.ECTDFEnabled {
			p.Logger.ErrorContext(ctx, "ec rewrap not enabled")
			failAllKaos(requests, results, err400("invalid request"))
			return "", results
		}
	}

	for _, pdpAccess := range pdpAccessResults {
		policy := pdpAccess.Policy
		requiredObligationsForPolicy := pdpAccess.RequiredObligations
		req, ok := policyReqs[policy]
		if !ok {
			//nolint:sloglint // reference to key is intentional
			p.Logger.WarnContext(ctx, "policy not found in policyReqs", "policy.uuid", policy.UUID)
			continue
		}

		kaoResults, ok := results[req.GetPolicy().GetId()]
		if !ok { // this should not happen
			//nolint:sloglint // reference to key is intentional
			p.Logger.WarnContext(ctx, "policy not found in policyReq response", "policy.uuid", policy.UUID)
			continue
		}
		access := pdpAccess.Access

		// Audit the TDF3 Rewrap
		kasPolicy := ConvertToAuditKasPolicy(*policy)

		for _, kao := range req.GetKeyAccessObjects() {
			kaoID := kao.GetKeyAccessObjectId()
			kaoRes := kaoResults[kaoID]
			if kaoRes.Error != nil {
				continue
			}

			policyBinding := kao.GetKeyAccessObject().GetPolicyBinding().GetHash()
			auditEventParams := audit.RewrapAuditEventParams{
				Policy:        kasPolicy,
				IsSuccess:     access,
				TDFFormat:     "tdf3",
				Algorithm:     req.GetAlgorithm(),
				PolicyBinding: policyBinding,
				KeyID:         kao.GetKeyAccessObject().GetKid(),
			}

			if !access {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrapWithObligations(kaoResults, kao, err403("forbidden"), requiredObligationsForPolicy)
				continue
			}

			// Use the Export method with the asymEncrypt encryptor
			encryptedKey, err := encap.Encapsulate(kaoRes.DEK)
			if err != nil {
				//nolint:sloglint // reference to camelcase key is intentional
				p.Logger.WarnContext(ctx, "rewrap: Export with encryptor failed", slog.String("clientPublicKey", clientPublicKey), slog.Any("error", err))
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(kaoResults, kao, err400("bad key for rewrap"))
				continue
			}
			kaoResults[kaoID] = kaoResult{
				ID:                  kaoID,
				Encapped:            encryptedKey,
				EphemeralPublicKey:  asymEncrypt.EphemeralKey(),
				RequiredObligations: requiredObligationsForPolicy,
			}

			p.Logger.Audit.RewrapSuccess(ctx, auditEventParams)
		}
	}
	return sessionKey, results
}

func (p *Provider) nanoTDFRewrap(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, clientPublicKey string, entityInfo *entityInfo, additionalRewrapContext *AdditionalRewrapContext) (string, policyKAOResults) {
	ctx, span := p.Start(ctx, "nanoTDFRewrap")
	defer span.End()

	results := make(policyKAOResults)

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
	tok := &entity.Token{
		EphemeralId: "rewrap-tok",
		Jwt:         entityInfo.Token,
	}

	pdpAccessResults, accessErr := p.canAccess(ctx, tok, policies, additionalRewrapContext.Obligations.FulfillableFQNs)
	if accessErr != nil {
		failAllKaos(requests, results, err500("could not perform access"))
		return "", results
	}

	sessionKey, err := p.KeyDelegator.GenerateECSessionKey(ctx, clientPublicKey)
	if err != nil {
		p.Logger.WarnContext(ctx, "failure in GenerateNanoTDFSessionKey", slog.Any("error", err))
		failAllKaos(requests, results, err400("keypair mismatch"))
		return "", results
	}
	sessionKeyPEM, err := sessionKey.PublicKeyAsPEM()
	if err != nil {
		p.Logger.WarnContext(ctx, "failure in PublicKeyToPem", slog.Any("error", err))
		failAllKaos(requests, results, err500(""))
		return "", results
	}

	for _, pdpAccess := range pdpAccessResults {
		policy := pdpAccess.Policy
		requiredObligationsForPolicy := pdpAccess.RequiredObligations
		req, ok := policyReqs[policy]
		if !ok { // this should not happen
			continue
		}
		kaoResults, ok := results[req.GetPolicy().GetId()]
		if !ok { // this should not happen
			//nolint:sloglint // reference to key is intentional
			p.Logger.WarnContext(ctx, "policy not found in policyReq response", "policy.uuid", policy.UUID)
			continue
		}
		access := pdpAccess.Access

		// Audit the Nano Rewrap
		kasPolicy := ConvertToAuditKasPolicy(*policy)

		for _, kao := range req.GetKeyAccessObjects() {
			kaoInfo := kaoResults[kao.GetKeyAccessObjectId()]
			if kaoInfo.Error != nil {
				continue
			}

			auditEventParams := audit.RewrapAuditEventParams{
				Policy:        kasPolicy,
				IsSuccess:     access,
				TDFFormat:     "Nano",
				Algorithm:     req.GetAlgorithm(),
				KeyID:         kaoInfo.KeyID,
				PolicyBinding: kaoInfo.PolicyBinding,
			}

			if !access {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrapWithObligations(kaoResults, kao, err403("forbidden"), requiredObligationsForPolicy)
				continue
			}
			cipherText, err := kaoInfo.DEK.Export(sessionKey)
			if err != nil {
				p.Logger.Audit.RewrapFailure(ctx, auditEventParams)
				failedKAORewrap(kaoResults, kao, err403("forbidden"))
				continue
			}

			kaoResults[kao.GetKeyAccessObjectId()] = kaoResult{
				ID:                  kao.GetKeyAccessObjectId(),
				Encapped:            cipherText,
				RequiredObligations: requiredObligationsForPolicy,
			}

			p.Logger.Audit.RewrapSuccess(ctx, auditEventParams)
		}
	}
	return sessionKeyPEM, results
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
			p.Logger.DebugContext(ctx,
				"nanoTDFRewrap GetIdentifier",
				slog.String("kid", kid),
				slog.Any("error", err),
			)
			// legacy nano with KID
			kid, err = p.lookupKid(ctx, security.AlgorithmECP256R1)
			if err != nil {
				p.Logger.ErrorContext(ctx, "failure to find default kid for ec", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("bad request"))
				continue
			}
			p.Logger.DebugContext(ctx, "nanoTDFRewrap lookupKid", slog.String("kid", kid))
		}
		p.Logger.DebugContext(ctx, "nanoTDFRewrap", slog.String("kid", kid))
		ecCurve, err := header.ECCurve()
		if err != nil {
			failedKAORewrap(results, kao, fmt.Errorf("ECCurve failed: %w", err))
			return nil, results
		}

		symmetricKey, err := p.KeyDelegator.DeriveKey(ctx, trust.KeyIdentifier(kid), header.EphemeralKey, ecCurve)
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
		binding, err := header.PolicyBinding()
		if err != nil {
			failedKAORewrap(results, kao, fmt.Errorf("failed to retrieve policy binding: %w", err))
			return nil, results
		}

		verify, err := binding.Verify()
		if err != nil {
			failedKAORewrap(results, kao, fmt.Errorf("error verifying policy binding: %w", err))
			return nil, results
		}

		if !verify {
			failedKAORewrap(results, kao, errors.New("policy binding verification failed"))
			return nil, results
		}
		results[kao.GetKeyAccessObjectId()] = kaoResult{
			ID:            kao.GetKeyAccessObjectId(),
			DEK:           symmetricKey,
			KeyID:         kid,
			PolicyBinding: binding.String(),
		}
		return policy, results
	}
	return nil, results
}

func extractNanoPolicy(symmetricKey ocrypto.ProtectedKey, header sdk.NanoTDFHeader) (*Policy, error) {
	const (
		kIvLen = 12
	)

	var policy Policy
	switch header.PolicyMode {
	case sdk.NanoTDFPolicyModePlainText:
		err := json.Unmarshal(header.PolicyBody, &policy)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling plaintext policy: %w", err)
		}
		return &policy, nil

	case sdk.NanoTDFPolicyModeEncrypted:
		iv := make([]byte, kIvLen)
		tagSize, err := sdk.SizeOfAuthTagForCipher(header.GetCipher())
		if err != nil {
			return nil, fmt.Errorf("SizeOfAuthTagForCipher failed: %w", err)
		}

		policyData, err := symmetricKey.DecryptAESGCM(iv, header.PolicyBody, tagSize)
		if err != nil {
			return nil, fmt.Errorf("error decrypting policy body: %w", err)
		}

		err = json.Unmarshal(policyData, &policy)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling encrypted policy: %w", err)
		}
		return &policy, nil
	case sdk.NanoTDFPolicyModeRemote, sdk.NanoTDFPolicyModeEncryptedPolicyKeyAccess:
	default:
		// noop
	}
	return nil, errors.Join(fmt.Errorf("unsupported policy mode: %d", header.PolicyMode), ErrNanoTDFPolicyModeUnsupported)
}

func failAllKaos(reqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, results policyKAOResults, err error) {
	for _, req := range reqs {
		for _, kao := range req.GetKeyAccessObjects() {
			failedKAORewrap(results[req.GetPolicy().GetId()], kao, err)
		}
	}
}

// Populate response metadata with required obligations for each key access object response
// Result will look like:
/*
      {
        "responses": [
			{
		        policy_id: "policy-uuid",
				results: [
					{
						"metadata": {
						    "X-Required-Obligations": [<required obligations>]
						},
						"key_access_object_id": "kao-uuid",
					},
					{
						"metadata": {
						    "X-Required-Obligations": [<required obligations>]
						},
						"key_access_object_id": "kao-uuid",
					},
				]
			}
		]
      }
*/
func createKAOMetadata(obligations []string) map[string]*structpb.Value {
	metadata := make(map[string]*structpb.Value)

	values := make([]*structpb.Value, len(obligations))
	for i, obligation := range obligations {
		values[i] = structpb.NewStringValue(obligation)
	}
	metadata[requiredObligationsHeader] = structpb.NewListValue(&structpb.ListValue{
		Values: values,
	})

	return metadata
}

// Retrieve additional request context needed for rewrap processing
// Header is json encoded AdditionalRewrapContext struct
/*
Example:

{
	"obligations": {"fulfillableFQNs": ["https://demo.com/obl/test/value/watermark","https://demo.com/obl/test/value/geofence"]}
}

*/
func getAdditionalRewrapContext(header http.Header) (*AdditionalRewrapContext, error) {
	rewrapContext := &AdditionalRewrapContext{
		Obligations: ObligationCtx{
			FulfillableFQNs: []string{},
		},
	}
	if header == nil {
		return rewrapContext, nil
	}
	if val := header.Get(additionalRewrapContextHeader); val != "" {
		decoded, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, errors.Join(ErrDecodingRewrapContext, err)
		}

		err = json.Unmarshal(decoded, rewrapContext)
		if err != nil {
			return nil, errors.Join(ErrUnmarshalingRewrapContext, err)
		}

		validObligations := make([]string, 0)
		for _, r := range rewrapContext.Obligations.FulfillableFQNs {
			normalizedObligation := strings.TrimSpace(r)
			if len(normalizedObligation) == 0 {
				continue
			}
			_, err = identifier.Parse[*identifier.FullyQualifiedObligation](normalizedObligation)
			if err != nil {
				return nil, fmt.Errorf("%w, for obligation %s", err, normalizedObligation)
			}
			validObligations = append(validObligations, normalizedObligation)
		}
		rewrapContext.Obligations.FulfillableFQNs = validObligations
	}
	return rewrapContext, nil
}
