package access

import (
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
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/lib/identifier"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/entity"
	kaspb "github.com/opentdf/platform/protocol/go/kas"
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
	kTDF3Format                   = "tdf3"
	kFailedStatus                 = "fail"
	kPermitStatus                 = "permit"
	additionalRewrapContextHeader = "X-Rewrap-Additional-Context"
	requiredObligationsHeader     = "X-Required-Obligations"

	rewrapReasonPolicyBindingMismatch  = "policy_binding_mismatch"
	rewrapReasonPolicyBindingMissing   = "policy_binding_missing"
	rewrapReasonPolicyBindingMalformed = "policy_binding_malformed"
	rewrapReasonPolicyBodyInvalid      = "policy_body_invalid"
	rewrapReasonDEKDecryptFailed       = "dek_decrypt_failed"
	rewrapReasonKAOInvalid             = "kao_invalid"
	rewrapReasonUnsupportedKeyType     = "unsupported_key_type"
	rewrapReasonKeyTypeDisabled        = "key_type_disabled"
	rewrapReasonInvalidEphemeralKey    = "invalid_ephemeral_key"
	rewrapReasonPolicyDenied           = "policy_denied"
	rewrapReasonAuthzUnavailable       = "authz_unavailable"
	rewrapReasonContextCancelled       = "context_cancelled"
	rewrapReasonAuthzRejected          = "authz_rejected"
	rewrapReasonInvalidClientPublicKey = "invalid_client_public_key"
	rewrapReasonECRewrapDisabled       = "ec_rewrap_disabled"
	rewrapReasonSessionKeyError        = "session_key_error"
	rewrapReasonEncapsulationFailed    = "encapsulation_failed"
	rewrapReasonSRTInvalid             = "srt_invalid"
	rewrapReasonSRTSignatureInvalid    = "srt_signature_invalid"
	rewrapReasonRequestBodyInvalid     = "request_body_invalid"
	rewrapReasonMissingAccessToken     = "missing_access_token"
	rewrapReasonInvalidRewrapContext   = "invalid_rewrap_context"
	rewrapReasonInvalidRequest         = "invalid_request"
	rewrapReasonIncomplete             = "rewrap_incomplete"
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
	Audit               rewrapAuditOutcome
}

type rewrapAuditOutcome struct {
	Result          audit.ActionResult
	FailureReason   string
	SuspectedTamper bool
	PolicyVerified  bool
	Classified      bool
}

type requestRewrapAuditOutcome struct {
	PolicyID string
	Outcome  rewrapAuditOutcome
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
	ErrUser                    = Error("request error")
	ErrInternal                = Error("internal error")
	errNoValidKeyAccessObjects = Error("no valid KAOs")
)

// Error helpers for KAS rewrap responses.
//
// SECURITY: Policy binding verification and DEK decryption failures MUST use the
// generic "bad request" message to avoid leaking information about computations
// involving secret key material. Non-secret failures (malformed input, unsupported
// key types, missing fields) SHOULD use descriptive messages so the SDK can
// distinguish misconfiguration from potential tamper.
//
// The SDK matches on the substring "desc = bad request" in serialized per-KAO
// errors to identify potential tamper (see sdk/tdferrors.go kasGenericBadRequest).
// Do not change the generic "bad request" message without updating the SDK
// constant, and do not use "bad request" in descriptive error messages.
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

func jwkThumbprintAttr(key jwk.Key) slog.Attr {
	if key == nil {
		return slog.String("jwk_thumbprint", "none")
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return slog.String("jwk_thumbprint_error", err.Error())
	}
	return slog.String("jwk_thumbprint", base64.RawURLEncoding.EncodeToString(thumbprint))
}

// parseSRT parses the JWT payload without validation, returning the token and embedded
// request body string while translating parse errors into client-facing status codes.
func (p *Provider) parseSRT(ctx context.Context, srt string) (jwt.Token, string, error) {
	token, err := jwt.Parse([]byte(srt), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		p.Logger.WarnContext(
			ctx,
			"unable to validate or parse token",
			slog.Any("error", err),
			slog.Int("srt_length", len(srt)),
			jwkThumbprintAttr(ctxAuth.GetJWKFromContext(ctx, p.Logger)),
		)
		return nil, "", err401("could not parse token")
	}

	rbString, err := justRequestBody(ctx, token, *p.Logger)
	if err != nil {
		return nil, "", err
	}

	return token, rbString, nil
}

// logSRTValidationFailure collects claim timestamps and skew details to aid debugging when
// validation fails after parsing the SRT.
func (p *Provider) logSRTValidationFailure(ctx context.Context, token jwt.Token, message string, err error) {
	now := time.Now().UTC()

	fields := []any{
		slog.Any("error", err),
		slog.Time("server_time", now),
		slog.Duration("acceptable_skew", p.acceptableSkew()),
	}

	failureClaims := map[string]struct{}{}

	issuedAt := token.IssuedAt()
	if !issuedAt.IsZero() {
		fields = append(
			fields,
			slog.Time("iat", issuedAt),
			slog.Duration("iat_delta", issuedAt.Sub(now)),
		)
		if errors.Is(err, jwt.ErrInvalidIssuedAt()) {
			failureClaims["iat"] = struct{}{}
		}
	}

	expires := token.Expiration()
	if !expires.IsZero() {
		fields = append(
			fields,
			slog.Time("exp", expires),
			slog.Duration("exp_delta", now.Sub(expires)),
		)
		if errors.Is(err, jwt.ErrTokenExpired()) {
			failureClaims["exp"] = struct{}{}
		}
	}

	notBefore := token.NotBefore()
	if !notBefore.IsZero() {
		fields = append(
			fields,
			slog.Time("nbf", notBefore),
			slog.Duration("nbf_delta", notBefore.Sub(now)),
		)
	}

	if errors.Is(err, jwt.ErrTokenNotYetValid()) {
		failureClaims["nbf"] = struct{}{}
	}

	if len(failureClaims) > 0 {
		names := make([]string, 0, len(failureClaims))
		for claim := range failureClaims {
			names = append(names, claim)
		}
		sort.Strings(names)
		fields = append(fields, slog.Any("validation_failure_claims", names))
	}

	fields = append(fields, slog.String("failure_reason", message))
	p.Logger.WarnContext(ctx, "srt validation failure", fields...)
}

// validateSRTClaims enforces temporal constraints on the parsed SRT, incorporating the
// configured acceptable skew and translating failures into user-friendly errors.
func (p *Provider) validateSRTClaims(ctx context.Context, token jwt.Token, requireVerification bool) error {
	err := jwt.Validate(token, jwt.WithAcceptableSkew(p.acceptableSkew()))
	if err == nil {
		return nil
	}

	message := "unable to validate or parse token"
	userErr := err401("could not parse token")
	if requireVerification {
		message = "unable to verify request token"
		userErr = err401("unable to verify request token")
	}

	p.logSRTValidationFailure(ctx, token, message, err)
	return userErr
}

// srtSignatureAlgorithms enumerates the asymmetric JWS algorithms accepted for
// the signed request token. The SRT is signed with the client's DPoP key, so its
// algorithm follows the key type (RS256/PS* for RSA, ES256/384/512 for EC).
// Mirrors the DPoP proof allowlist in the auth package.
var srtSignatureAlgorithms = map[jwa.SignatureAlgorithm]bool{ //nolint:exhaustive // only asymmetric algorithms
	jwa.RS256: true,
	jwa.RS384: true,
	jwa.RS512: true,
	jwa.ES256: true,
	jwa.ES384: true,
	jwa.ES512: true,
	jwa.PS256: true,
	jwa.PS384: true,
	jwa.PS512: true,
}

// verifySRTSignature validates the SRT signature against the supplied DPoP key when
// verification is required.
func (p *Provider) verifySRTSignature(ctx context.Context, srt string, dpopJWK jwk.Key) error {
	// The SRT is signed with the client's DPoP key, whose JWS algorithm depends on
	// the key type. Read the algorithm from the SRT header (validated against an
	// asymmetric allowlist) instead of assuming RS256, so EC DPoP keys (e.g.
	// ES256) verify.
	alg := jwa.RS256
	if parsed, perr := jws.Parse([]byte(srt)); perr == nil {
		if sigs := parsed.Signatures(); len(sigs) > 0 {
			if headers := sigs[0].ProtectedHeaders(); headers != nil {
				alg = headers.Algorithm()
			}
		}
	}
	var err error
	if !srtSignatureAlgorithms[alg] {
		err = fmt.Errorf("unsupported request token algorithm: %q", alg)
	} else {
		_, err = jwt.Parse(
			[]byte(srt),
			jwt.WithKey(alg, dpopJWK),
			jwt.WithValidate(false),
		)
	}
	if err != nil {
		if p.Logger != nil {
			p.Logger.WarnContext(
				ctx,
				"unable to verify request token",
				slog.Int("srt_length", len(srt)),
				jwkThumbprintAttr(dpopJWK),
				slog.Any("error", err),
			)
		}
		return err401("unable to verify request token")
	}
	return nil
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
	// Ignore errors: legacy requests may omit or use non-standard policy binding formats.
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

func (p *Provider) extractSRTBody(ctx context.Context, headers http.Header, in *kaspb.RewrapRequest) (*kaspb.UnsignedRewrapRequest, bool, rewrapAuditOutcome, error) {
	isV1 := false
	// First load legacy method for verifying SRT
	if vpk, ok := headers["X-Virtrupubkey"]; ok && len(vpk) == 1 {
		p.Logger.InfoContext(ctx, "legacy Client: Processing X-Virtrupubkey")
	}

	// get dpop public key from context
	dpopJWK := ctxAuth.GetJWKFromContext(ctx, p.Logger)

	srt := in.GetSignedRequestToken()
	requireVerification := dpopJWK != nil
	if !requireVerification {
		p.Logger.InfoContext(ctx, "no DPoP key provided")
		// if we have no DPoP key it's for one of two reasons:
		// 1. auth is disabled so we can't get a DPoP JWK
		// 2. auth is enabled _but_ we aren't requiring DPoP
		// in either case letting the request through makes sense
	}

	token, rbString, parseErr := p.parseSRT(ctx, srt)
	if parseErr != nil {
		return nil, false, rejectedRewrapOutcome(rewrapReasonSRTInvalid, false), parseErr
	}

	if validateErr := p.validateSRTClaims(ctx, token, requireVerification); validateErr != nil {
		return nil, false, rejectedRewrapOutcome(rewrapReasonSRTInvalid, false), validateErr
	}

	if requireVerification {
		if err := p.verifySRTSignature(ctx, srt, dpopJWK); err != nil {
			return nil, false, rejectedRewrapOutcome(rewrapReasonSRTSignatureInvalid, true), err
		}
	}

	var requestBody kaspb.UnsignedRewrapRequest
	err := protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal([]byte(rbString), &requestBody)
	// if there are no requests then it could be a v1 request
	if err != nil {
		p.Logger.WarnContext(
			ctx,
			"invalid SRT",
			slog.Any("err_v2", err),
			slog.Int("rb_string_length", len(rbString)),
		)
		return nil, false, rejectedRewrapOutcome(rewrapReasonRequestBodyInvalid, false), err400("invalid request body")
	}
	if len(requestBody.GetRequests()) == 0 {
		p.Logger.DebugContext(ctx, "legacy v1 SRT")
		var errv1 error

		if requestBody, errv1 = extractAndConvertV1SRTBody([]byte(rbString)); errv1 != nil {
			p.Logger.WarnContext(
				ctx,
				"invalid SRT",
				slog.Any("err_v1", errv1),
				slog.Int("rb_string_length", len(rbString)),
				slog.Int("rewrap_body_length", len(requestBody.String())),
			)
			return nil, false, rejectedRewrapOutcome(rewrapReasonRequestBodyInvalid, false), err400("invalid request body")
		}
		isV1 = true
	}
	// TODO: this log is too big and should be reconsidered or removed
	p.Logger.DebugContext(
		ctx,
		"extracted request body",
		slog.String("rewrap_body", requestBody.String()),
		slog.String("rewrap_srt", rbString),
	)

	block, _ := pem.Decode([]byte(requestBody.GetClientPublicKey()))
	if block == nil {
		p.Logger.WarnContext(ctx, "missing clientPublicKey")
		return nil, isV1, rejectedRewrapOutcome(rewrapReasonInvalidClientPublicKey, false), err400("clientPublicKey failure")
	}

	// Pure ML-KEM client session keys are SPKI-wrapped under the NIST ML-KEM
	// OIDs (FIPS 203), which x509.ParsePKIXPublicKey does not recognize.
	// Hybrid SPKIs are not matched here and are rejected by the x509 fallback.
	// The key length is validated later, when the wrapping key is built in
	// tdf3Rewrap.
	if oid, _, kemErr := ocrypto.ParseKEMPublicSPKI(block.Bytes); kemErr == nil &&
		(oid.Equal(ocrypto.OIDMLKEM768) || oid.Equal(ocrypto.OIDMLKEM1024)) {
		if !p.Preview.MLKEMTDFEnabled {
			p.Logger.ErrorContext(ctx, "ml-kem session key rewrap not enabled", slog.String("key_type", oid.String()))
			return nil, isV1, rejectedRewrapOutcome(rewrapReasonInvalidClientPublicKey, false), err400("clientPublicKey unsupported type")
		}
		return &requestBody, isV1, rewrapAuditOutcome{}, nil
	}

	// Try to parse the clientPublicKey
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		p.Logger.WarnContext(ctx, "failure to parse clientPublicKey", slog.Any("error", err))
		return nil, isV1, rejectedRewrapOutcome(rewrapReasonInvalidClientPublicKey, false), err400("clientPublicKey parse failure")
	}
	// Check to make sure the clientPublicKey is a supported key type
	switch clientPublicKey.(type) {
	case *rsa.PublicKey:
		return &requestBody, isV1, rewrapAuditOutcome{}, nil
	case *ecdsa.PublicKey:
		return &requestBody, isV1, rewrapAuditOutcome{}, nil
	default:
		p.Logger.WarnContext(ctx, "unsupported clientPublicKey type", slog.String("type", fmt.Sprintf("%T", clientPublicKey)))
		return nil, isV1, rejectedRewrapOutcome(rewrapReasonInvalidClientPublicKey, false), err400("clientPublicKey unsupported type")
	}
}

func rejectedRewrapOutcome(reason string, suspectedTamper bool) rewrapAuditOutcome {
	return rewrapAuditOutcome{
		Result:          audit.ActionResultFailure,
		FailureReason:   reason,
		SuspectedTamper: suspectedTamper,
		Classified:      true,
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
		return err400("bad request") // Generic: involves secret key material
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

func failedKAORewrapWithObligations(res map[string]kaoResult, kao *kaspb.UnsignedRewrapRequest_WithKeyAccessObject, err error, requiredObligations []string, reason string) {
	res[kao.GetKeyAccessObjectId()] = kaoResult{
		ID:                  kao.GetKeyAccessObjectId(),
		Error:               err,
		RequiredObligations: requiredObligations,
		Audit: rewrapAuditOutcome{
			Result:         audit.ActionResultFailure,
			FailureReason:  reason,
			PolicyVerified: true,
			Classified:     true,
		},
	}
}

func failedKAORewrap(res map[string]kaoResult, kao *kaspb.UnsignedRewrapRequest_WithKeyAccessObject, err error, reason string, suspectedTamper bool) {
	res[kao.GetKeyAccessObjectId()] = kaoResult{
		ID:    kao.GetKeyAccessObjectId(),
		Error: err,
		Audit: rewrapAuditOutcome{
			Result:          audit.ActionResultFailure,
			FailureReason:   reason,
			SuspectedTamper: suspectedTamper,
			Classified:      true,
		},
	}
}

func erroredKAORewrap(res map[string]kaoResult, kao *kaspb.UnsignedRewrapRequest_WithKeyAccessObject, err error, reason string) {
	current := res[kao.GetKeyAccessObjectId()]
	current.ID = kao.GetKeyAccessObjectId()
	current.Error = err
	current.Audit.Result = audit.ActionResultError
	current.Audit.FailureReason = reason
	current.Audit.Classified = true
	res[kao.GetKeyAccessObjectId()] = current
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

	body, isV1, requestOutcome, err := p.extractSRTBody(ctx, req.Header(), in)
	if err != nil {
		p.Logger.TraceContext(ctx, "srt extraction failure", slog.Any("srt", body), slog.Any("error", err))
		p.Logger.DebugContext(ctx, "unverifiable srt", slog.Any("error", err))
		p.recordRewrapAuditEvent(ctx, audit.RewrapAuditEventParams{
			Result:          requestOutcome.Result,
			FailureReason:   requestOutcome.FailureReason,
			SuspectedTamper: requestOutcome.SuspectedTamper,
			TDFFormat:       kTDF3Format,
		})
		return nil, err
	}

	entityInfo, err := getEntityInfo(ctx, p.Logger)
	if err != nil {
		p.Logger.DebugContext(ctx, "no entity info", slog.Any("error", err))
		p.recordRewrapAuditEvent(ctx, audit.RewrapAuditEventParams{
			Result:        audit.ActionResultFailure,
			FailureReason: rewrapReasonMissingAccessToken,
			TDFFormat:     kTDF3Format,
		})
		return nil, err
	}

	resp := &kaspb.RewrapResponse{}

	var tdf3Reqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest
	for _, req := range body.GetRequests() {
		switch {
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
		p.recordRewrapAuditEvent(ctx, audit.RewrapAuditEventParams{
			Result:        audit.ActionResultFailure,
			FailureReason: rewrapReasonInvalidRewrapContext,
			TDFFormat:     kTDF3Format,
		})
		return nil, err400("failed to get additional rewrap context")
	}
	resp.SessionPublicKey, results, err = p.tdf3Rewrap(ctx, tdf3Reqs, body.GetClientPublicKey(), entityInfo, additionalRewrapContext)
	if err != nil {
		p.Logger.WarnContext(ctx, "status 400, tdf3 rewrap failure", slog.Any("error", err))
		p.recordRewrapAuditEvent(ctx, audit.RewrapAuditEventParams{
			Result:        audit.ActionResultError,
			FailureReason: rewrapReasonIncomplete,
			TDFFormat:     kTDF3Format,
		})
		return nil, err
	}
	addResultsToResponse(resp, results)

	if isV1 {
		if len(results) != 1 {
			p.Logger.WarnContext(ctx, "status 400 due to wrong result set size", slog.Any("results", results))
			p.recordRewrapAuditEvent(ctx, audit.RewrapAuditEventParams{
				Result:        audit.ActionResultFailure,
				FailureReason: rewrapReasonInvalidRequest,
				TDFFormat:     kTDF3Format,
			})
			return nil, err400("invalid request")
		}
		kaoResults := *getMapValue(results)
		if len(kaoResults) != 1 {
			p.Logger.WarnContext(
				ctx,
				"status 400 due to wrong result set size",
				slog.Any("kao_results", kaoResults),
				slog.Any("results", results),
			)
			p.recordRewrapAuditEvent(ctx, audit.RewrapAuditEventParams{
				Result:        audit.ActionResultFailure,
				FailureReason: rewrapReasonInvalidRequest,
				TDFFormat:     kTDF3Format,
			})
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
	// Safe tracer handling - only start span if tracer is available
	var span trace.Span
	if p.Tracer != nil {
		ctx, span = p.Start(ctx, "tdf3Rewrap")
		defer span.End()
	}

	results := make(map[string]kaoResult)
	anyValidKAOs := false
	policy := &Policy{}

	// Check if req is nil
	if req == nil {
		p.Logger.WarnContext(ctx, "request is nil")
		return nil, results, errors.New("request is nil")
	}

	// Check if policy is nil
	if req.GetPolicy() == nil {
		p.Logger.WarnContext(ctx, "policy is nil")
		return nil, results, errors.New("policy is nil")
	}

	p.Logger.DebugContext(ctx, "extracting policy", slog.Any("policy", req.GetPolicy()))
	sDecPolicy, policyErr := base64.StdEncoding.DecodeString(req.GetPolicy().GetBody())
	if policyErr == nil {
		policyErr = json.Unmarshal(sDecPolicy, policy)
	}

	for _, kao := range req.GetKeyAccessObjects() {
		if policyErr != nil {
			failedKAORewrap(results, kao, err400("bad request"), rewrapReasonPolicyBodyInvalid, true) // Generic: corrupted policy body may indicate tamper
			continue
		}

		// Check if KeyAccessObject is nil
		if kao.GetKeyAccessObject() == nil {
			p.Logger.WarnContext(ctx, "key access object is nil", slog.String("kao_id", kao.GetKeyAccessObjectId()))
			failedKAORewrap(results, kao, err400("key access object is nil"), rewrapReasonKAOInvalid, false)
			continue
		}

		// Check if wrapped key is empty
		wrappedKey := kao.GetKeyAccessObject().GetWrappedKey()
		if len(wrappedKey) == 0 {
			p.Logger.WarnContext(ctx, "wrapped key is empty", slog.String("kao_id", kao.GetKeyAccessObjectId()))
			failedKAORewrap(results, kao, err400("wrapped key is empty"), rewrapReasonKAOInvalid, false)
			continue
		}

		var dek ocrypto.ProtectedKey
		var err error
		switch kao.GetKeyAccessObject().GetKeyType() {
		case "ec-wrapped":

			if !p.Preview.ECTDFEnabled {
				p.Logger.WarnContext(ctx, "ec-wrapped not enabled")
				failedKAORewrap(results, kao, err400("ec-wrapped not enabled"), rewrapReasonKeyTypeDisabled, false)
				continue
			}

			// Get the ephemeral public key in PEM format
			ephemeralPubKeyPEM := kao.GetKeyAccessObject().GetEphemeralPublicKey()

			// Get EC key size and convert to mode
			keySize, err := ocrypto.GetECKeySize([]byte(ephemeralPubKeyPEM))
			if err != nil {
				p.Logger.WarnContext(
					ctx,
					"failed to get EC key size",
					slog.Any("kao", kao),
					slog.Any("error", err),
				)
				failedKAORewrap(results, kao, err400("invalid ephemeral public key"), rewrapReasonInvalidEphemeralKey, false)
				continue
			}

			mode, err := ocrypto.ECSizeToMode(keySize)
			if err != nil {
				p.Logger.WarnContext(
					ctx,
					"failed to convert key size to mode",
					slog.Any("kao", kao),
					slog.Any("error", err),
				)
				failedKAORewrap(results, kao, err400("unsupported EC key size"), rewrapReasonInvalidEphemeralKey, false)
				continue
			}

			// Parse the PEM public key
			block, _ := pem.Decode([]byte(ephemeralPubKeyPEM))
			if block == nil {
				p.Logger.WarnContext(
					ctx,
					"failed to decode PEM block",
					slog.Any("kao", kao),
					slog.Any("error", err),
				)
				failedKAORewrap(results, kao, err400("invalid ephemeral public key PEM"), rewrapReasonInvalidEphemeralKey, false)
				continue
			}

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				p.Logger.WarnContext(
					ctx,
					"failed to parse public key",
					slog.Any("kao", kao),
					slog.Any("error", err),
				)
				failedKAORewrap(results, kao, err400("invalid ephemeral public key"), rewrapReasonInvalidEphemeralKey, false)
				continue
			}

			ecPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				p.Logger.WarnContext(ctx, "not an EC public key", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("ephemeral key is not EC"), rewrapReasonInvalidEphemeralKey, false)
				continue
			}

			// Compress the public key
			compressedKey, err := ocrypto.CompressedECPublicKey(mode, *ecPub)
			if err != nil {
				p.Logger.WarnContext(ctx, "failed to compress public key", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("invalid EC public key"), rewrapReasonInvalidEphemeralKey, false)
				continue
			}

			kid := trust.KeyIdentifier(kao.GetKeyAccessObject().GetKid())
			dek, err = p.KeyDelegator.Decrypt(ctx, kid, kao.GetKeyAccessObject().GetWrappedKey(), compressedKey)
			if err != nil {
				p.Logger.WarnContext(ctx, "failed to decrypt EC key", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("bad request"), rewrapReasonDEKDecryptFailed, true)
				continue
			}
		case "hybrid-wrapped":
			if !p.Preview.HybridTDFEnabled {
				p.Logger.WarnContext(ctx, "hybrid-wrapped not enabled")
				failedKAORewrap(results, kao, err400("bad request"), rewrapReasonKeyTypeDisabled, false)
				continue
			}

			kid := trust.KeyIdentifier(kao.GetKeyAccessObject().GetKid())
			dek, err = p.KeyDelegator.Decrypt(ctx, kid, kao.GetKeyAccessObject().GetWrappedKey(), nil)
			if err != nil {
				p.Logger.WarnContext(ctx, "failed to decrypt hybrid key", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("bad request"), rewrapReasonDEKDecryptFailed, true)
				continue
			}
		case "mlkem-wrapped":
			if !p.Preview.MLKEMTDFEnabled {
				p.Logger.WarnContext(ctx, "mlkem-wrapped not enabled")
				failedKAORewrap(results, kao, err400("bad request"), rewrapReasonKeyTypeDisabled, false)
				continue
			}

			kid := trust.KeyIdentifier(kao.GetKeyAccessObject().GetKid())
			dek, err = p.KeyDelegator.Decrypt(ctx, kid, kao.GetKeyAccessObject().GetWrappedKey(), nil)
			if err != nil {
				p.Logger.WarnContext(ctx, "failed to decrypt ML-KEM key", slog.Any("error", err))
				failedKAORewrap(results, kao, err400("bad request"), rewrapReasonDEKDecryptFailed, true)
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
					failedKAORewrap(results, kao, err400("no legacy key IDs found"), rewrapReasonDEKDecryptFailed, true)
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
		default:
			// handle unsupported key types
			keyType := kao.GetKeyAccessObject().GetKeyType()
			p.Logger.WarnContext(ctx, "unsupported key type",
				slog.String("key_type", keyType),
				slog.String("kao_id", kao.GetKeyAccessObjectId()))
			failedKAORewrap(results, kao, err400("unsupported key type"), rewrapReasonUnsupportedKeyType, false)
			continue
		}
		if err != nil {
			p.Logger.WarnContext(ctx, "failure to decrypt dek", slog.Any("error", err))
			failedKAORewrap(results, kao, err400("bad request"), rewrapReasonDEKDecryptFailed, true) // Generic: involves secret key material
			continue
		}

		// Check if policy binding is nil
		if kao.GetKeyAccessObject().GetPolicyBinding() == nil {
			p.Logger.WarnContext(ctx, "policy binding is nil", slog.String("kao_id", kao.GetKeyAccessObjectId()))
			failedKAORewrap(results, kao, err400("missing policy binding"), rewrapReasonPolicyBindingMissing, true)
			continue
		}

		// Store policy binding in context for verification
		policyBindingB64Encoded := kao.GetKeyAccessObject().GetPolicyBinding().GetHash()
		policyBinding := make([]byte, base64.StdEncoding.DecodedLen(len(policyBindingB64Encoded)))
		n, err := base64.StdEncoding.Decode(policyBinding, []byte(policyBindingB64Encoded))
		if err != nil {
			p.Logger.WarnContext(ctx, "invalid policy binding encoding", slog.Any("error", err))
			failedKAORewrap(results, kao, err400("bad request"), rewrapReasonPolicyBindingMalformed, true) // Generic: malformed binding may indicate tamper
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
			failedKAORewrap(results, kao, err400("bad request"), rewrapReasonPolicyBindingMismatch, true) // Generic: involves secret key material
			continue
		}

		results[kao.GetKeyAccessObjectId()] = kaoResult{
			ID:  kao.GetKeyAccessObjectId(),
			DEK: dek,
			Audit: rewrapAuditOutcome{
				PolicyVerified: true,
			},
		}

		anyValidKAOs = true
	}

	if policyErr != nil {
		return nil, results, policyErr
	}

	if !anyValidKAOs {
		p.Logger.WarnContext(ctx, "no valid KAOs found")
		return policy, results, errNoValidKeyAccessObjects
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

func (p *Provider) tdf3Rewrap(ctx context.Context, requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, clientPublicKey string, entityInfo *entityInfo, additionalRewrapContext *AdditionalRewrapContext) (string, policyKAOResults, error) {
	if p.Tracer != nil {
		var span trace.Span
		ctx, span = p.Start(ctx, "rewrap-tdf3")
		defer span.End()
	}

	results := make(policyKAOResults)
	requestResults := make(map[*kaspb.UnsignedRewrapRequest_WithPolicyRequest]map[string]kaoResult)
	auditPolicies := make(map[*kaspb.UnsignedRewrapRequest_WithPolicyRequest]*Policy)
	requestOutcomes := make([]requestRewrapAuditOutcome, 0)
	sessionKeyType := ""
	defer func() {
		p.auditRewrapOutcomes(ctx, requests, requestResults, auditPolicies, requestOutcomes, sessionKeyType)
	}()

	var policies []*Policy
	policyReqs := make(map[*Policy]*kaspb.UnsignedRewrapRequest_WithPolicyRequest)
	for _, req := range requests {
		if req == nil || req.GetPolicy() == nil || req.GetPolicy().GetId() == "" {
			p.Logger.WarnContext(ctx, "rewrap: nil request or policy")
			requestOutcomes = append(requestOutcomes, requestRewrapAuditOutcome{
				PolicyID: req.GetPolicy().GetId(),
				Outcome: rewrapAuditOutcome{
					Result:        audit.ActionResultFailure,
					FailureReason: rewrapReasonInvalidRequest,
					Classified:    true,
				},
			})
			continue
		}
		policy, kaoResults, err := p.verifyRewrapRequests(ctx, req)
		policyID := req.GetPolicy().GetId()
		results[policyID] = kaoResults
		requestResults[req] = kaoResults
		auditPolicies[req] = policy
		if err != nil {
			// Store per-KAO results even on error so tamper signals (e.g. corrupted
			// policy body → generic "bad request") reach the SDK rather than being
			// replaced by a top-level "invalid request".
			p.Logger.WarnContext(
				ctx,
				"rewrap: verifyRewrapRequests failed",
				slog.String("policy_id", policyID),
				slog.Any("error", err),
			)
			if len(req.GetKeyAccessObjects()) == 0 {
				reason := rewrapReasonKAOInvalid
				suspectedTamper := false
				if policy == nil {
					reason = rewrapReasonPolicyBodyInvalid
					suspectedTamper = true
				}
				requestOutcomes = append(requestOutcomes, requestRewrapAuditOutcome{
					PolicyID: policyID,
					Outcome: rewrapAuditOutcome{
						Result:          audit.ActionResultFailure,
						FailureReason:   reason,
						SuspectedTamper: suspectedTamper,
						Classified:      true,
					},
				})
			}
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
		category, isInternal := classifyAccessError(ctx, accessErr)
		// Terse, sensitive-payload-free line for the routine-denial flood case.
		// Floods read as floods, not as a forest of stack traces.
		p.Logger.InfoContext(
			ctx,
			"tdf3rewrap: access evaluation failed",
			slog.String("category", category),
			slog.Bool("internal", isInternal),
			slog.Int("policies", len(policies)),
			slog.Int("requests", len(requests)),
		)
		// Verbose / sensitive: only read when investigating one specific request.
		p.Logger.DebugContext(
			ctx,
			"tdf3rewrap: access evaluation failed: details",
			slog.String("category", category),
			slog.Any("error", accessErr),
			slog.Any("policies", policies),
			slog.Any("fulfillable_obligation_fqns", additionalRewrapContext.Obligations.FulfillableFQNs),
		)
		if isInternal {
			reason := rewrapReasonAuthzUnavailable
			if category == AccessErrCategoryContextCancelled {
				reason = rewrapReasonContextCancelled
			}
			failAllKAOsWithAuditOutcome(requests, requestResults, err500("internal: "+category), audit.ActionResultError, reason)
		} else {
			failAllKAOsWithAuditOutcome(requests, requestResults, err403("forbidden: "+category), audit.ActionResultFailure, rewrapReasonAuthzRejected)
		}
		return "", results, nil
	}

	asymEncrypt, err := ocrypto.FromPublicPEMWithSalt(clientPublicKey, security.TDFSalt(), nil)
	if err != nil {
		p.Logger.WarnContext(ctx, "ocrypto.NewAsymEncryption", slog.Any("error", err))
		failAllKAOsWithAuditOutcome(requests, requestResults, err400("invalid request"), audit.ActionResultFailure, rewrapReasonInvalidClientPublicKey)
		return "", results, nil
	}
	sessionKeyType = string(asymEncrypt.KeyType())
	encap := security.OCEncapsulator{PublicKeyEncryptor: asymEncrypt}

	var sessionKey string
	if e, ok := asymEncrypt.(ocrypto.ECEncryptor); ok {
		sessionKey, err = e.PublicKeyInPemFormat()
		if err != nil {
			p.Logger.ErrorContext(ctx, "unable to serialize ephemeral key", slog.Any("error", err))
			failAllKAOsWithAuditOutcome(requests, requestResults, err400("invalid request"), audit.ActionResultError, rewrapReasonSessionKeyError)
			return "", results, nil
		}
		if !p.Preview.ECTDFEnabled {
			p.Logger.ErrorContext(ctx, "ec rewrap not enabled")
			failAllKAOsWithAuditOutcome(requests, requestResults, err400("invalid request"), audit.ActionResultFailure, rewrapReasonECRewrapDisabled)
			return "", results, nil
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

		kaoResults, ok := requestResults[req]
		if !ok { // this should not happen
			//nolint:sloglint // reference to key is intentional
			p.Logger.WarnContext(ctx, "policy not found in policyReq response", "policy.uuid", policy.UUID)
			continue
		}
		access := pdpAccess.Access

		for _, kao := range req.GetKeyAccessObjects() {
			kaoID := kao.GetKeyAccessObjectId()
			kaoRes := kaoResults[kaoID]
			if kaoRes.Error != nil {
				continue
			}

			if !access {
				failedKAORewrapWithObligations(kaoResults, kao, err403("forbidden"), requiredObligationsForPolicy, rewrapReasonPolicyDenied)
				continue
			}

			// Use the Export method with the asymEncrypt encryptor
			encryptedKey, err := encap.Encapsulate(kaoRes.DEK)
			if err != nil {
				//nolint:sloglint // reference to camelcase key is intentional
				p.Logger.WarnContext(ctx, "rewrap: Export with encryptor failed", slog.String("clientPublicKey", clientPublicKey), slog.Any("error", err))
				erroredKAORewrap(kaoResults, kao, err400("bad key for rewrap"), rewrapReasonEncapsulationFailed)
				continue
			}
			kaoResults[kaoID] = kaoResult{
				ID:                  kaoID,
				Encapped:            encryptedKey,
				EphemeralPublicKey:  asymEncrypt.EphemeralKey(),
				RequiredObligations: requiredObligationsForPolicy,
				Audit: rewrapAuditOutcome{
					Result:         audit.ActionResultSuccess,
					PolicyVerified: true,
					Classified:     true,
				},
			}
		}
	}
	return sessionKey, results, nil
}

func failAllKAOsWithAuditOutcome(reqs []*kaspb.UnsignedRewrapRequest_WithPolicyRequest, results map[*kaspb.UnsignedRewrapRequest_WithPolicyRequest]map[string]kaoResult, err error, result audit.ActionResult, reason string) {
	for _, req := range reqs {
		if req == nil || req.GetPolicy() == nil {
			continue
		}
		policyResults := results[req]
		if policyResults == nil {
			continue
		}
		for _, kao := range req.GetKeyAccessObjects() {
			kaoID := kao.GetKeyAccessObjectId()
			current := policyResults[kaoID]
			current.ID = kaoID
			// Keep the legacy response behavior (the stage-wide error applies to
			// every KAO) without erasing a more specific earlier audit outcome.
			current.Error = err
			if !current.Audit.Classified || current.DEK != nil {
				current.Audit.Result = result
				current.Audit.FailureReason = reason
				current.Audit.Classified = true
			}
			policyResults[kaoID] = current
		}
	}
}

// auditRewrapOutcomes is the sole KAO-level emission point. Iterating the
// original requests, rather than the response maps, guarantees one event per
// submitted KAO even when different requests reuse a policy ID.
func (p *Provider) auditRewrapOutcomes(
	ctx context.Context,
	requests []*kaspb.UnsignedRewrapRequest_WithPolicyRequest,
	results map[*kaspb.UnsignedRewrapRequest_WithPolicyRequest]map[string]kaoResult,
	policies map[*kaspb.UnsignedRewrapRequest_WithPolicyRequest]*Policy,
	requestOutcomes []requestRewrapAuditOutcome,
	sessionKeyType string,
) {
	for _, requestOutcome := range requestOutcomes {
		p.recordRewrapAuditEvent(ctx, audit.RewrapAuditEventParams{
			PolicyID:        requestOutcome.PolicyID,
			Result:          requestOutcome.Outcome.Result,
			FailureReason:   requestOutcome.Outcome.FailureReason,
			SuspectedTamper: requestOutcome.Outcome.SuspectedTamper,
			PolicyVerified:  requestOutcome.Outcome.PolicyVerified,
			TDFFormat:       kTDF3Format,
		})
	}

	for _, req := range requests {
		if req == nil || req.GetPolicy() == nil || req.GetPolicy().GetId() == "" {
			continue
		}
		policyID := req.GetPolicy().GetId()
		policyResults := results[req]
		for _, kao := range req.GetKeyAccessObjects() {
			kaoID := kao.GetKeyAccessObjectId()
			kaoRes, ok := policyResults[kaoID]
			if !ok || !kaoRes.Audit.Classified {
				kaoRes.Audit = rewrapAuditOutcome{
					Result:         audit.ActionResultError,
					FailureReason:  rewrapReasonIncomplete,
					PolicyVerified: kaoRes.Audit.PolicyVerified,
					Classified:     true,
				}
			}

			params := audit.RewrapAuditEventParams{
				PolicyID:        policyID,
				Result:          kaoRes.Audit.Result,
				FailureReason:   kaoRes.Audit.FailureReason,
				SuspectedTamper: kaoRes.Audit.SuspectedTamper,
				PolicyVerified:  kaoRes.Audit.PolicyVerified,
				KAOID:           kaoID,
				TDFFormat:       kTDF3Format,
				Algorithm:       req.GetAlgorithm(),
				PolicyBinding:   kao.GetKeyAccessObject().GetPolicyBinding().GetHash(),
				KeyID:           kao.GetKeyAccessObject().GetKid(),
				SessionKeyType:  sessionKeyType,
			}
			if policies[req] != nil {
				params.Policy = ConvertToAuditKasPolicy(*policies[req])
			}
			p.recordRewrapAuditEvent(ctx, params)
		}
	}
}

func (p *Provider) recordRewrapAuditEvent(ctx context.Context, params audit.RewrapAuditEventParams) {
	if auditErr := p.Logger.Audit.Rewrap(ctx, params); auditErr != nil {
		p.Logger.ErrorContext(context.WithoutCancel(ctx), "failed to record rewrap audit event",
			slog.String("kao_id", params.KAOID),
			slog.String("policy_id", params.PolicyID),
			slog.String("rewrap_outcome", params.Result.String()),
			slog.Any("error", auditErr))
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
