package sdk

import (
	"errors"
	"fmt"
	"strings"
)

var (
	errWriteFailed      = errors.New("tdf: io.writer fail to write all bytes")
	errInvalidKasInfo   = errors.New("tdf: kas information is missing")
	errKasPubKeyMissing = errors.New("tdf: kas public key is missing")

	// errInputShorterThanDeclared reports a payload reader that hit EOF before
	// producing the byte count promised by WithInputSize.
	errInputShorterThanDeclared = errors.New("tdf: payload shorter than the declared input size")

	// errTooManySegments rejects a declared input size that would split into more
	// segments than the archive writer can count.
	errTooManySegments = errors.New("tdf: input size needs more segments than the archive can address")

	// ErrAESGCMExhausted is returned by a TDF writer that refuses to encrypt
	// another segment under its data encryption key (DEK). Payload segment IVs
	// are random 96-bit values, so the chance that any two collide grows with
	// the square of the segment count (about k^2 / 2^97 for k segments). NIST SP
	// 800-38D §8 limits that probability to 2^-32 per key, which is reached near
	// 2^32 encryptions; see maxAESGCMSegmentsPerDEK. A collision would expose the
	// XOR of two plaintexts and allow forgery under the DEK, so the writer fails
	// rather than continue. Start a new TDF, which draws a new DEK, or use a
	// larger segment size.
	ErrAESGCMExhausted = errors.New("tdf: AES-GCM IV collision limit reached for this data encryption key")

	// Exposed tamper detection errors, Catch all possible tamper errors with errors.Is(ErrTampered)
	ErrTampered                = errors.New("tamper detected")
	ErrRootSigValidation       = fmt.Errorf("[%w] tdf: failed integrity check on root signature", ErrTampered)
	ErrSegSizeMismatch         = fmt.Errorf("[%w] tdf: mismatch encrypted segment size in manifest", ErrTampered)
	ErrSegSizeUnresolved       = fmt.Errorf("[%w] tdf: segment size invalid or missing from manifest, with no default to fall back on", ErrTampered)
	ErrSegSigValidation        = fmt.Errorf("[%w] tdf: failed integrity check on segment hash", ErrTampered)
	ErrGMACSignatureFailed     = fmt.Errorf("[%w] tdf: ciphertext too short for a gmac signature", ErrTampered)
	ErrTDFPayloadReadFail      = fmt.Errorf("[%w] tdf: fail to read payload from tdf", ErrTampered)
	ErrTDFPayloadInvalidOffset = fmt.Errorf("[%w] sdk.Reader.ReadAt: negative offset", ErrTampered)
	ErrRootSignatureFailure    = fmt.Errorf("[%w] tdf: issue verifying root signature", ErrTampered)
	ErrRewrapBadRequest        = fmt.Errorf("[%w] tdf: rewrap request 400", ErrTampered)

	// ErrUnsupportedRootIntegrityAlgorithm rejects any root signature algorithm
	// other than HS256, on both the write and the read path.
	ErrUnsupportedRootIntegrityAlgorithm = errors.New("tdf: unsupported root integrity algorithm")

	// ErrUnsupportedSegmentIntegrityAlgorithm rejects a segment algorithm that
	// is neither HS256 nor GMAC. SegmentIntegrityAlg is int-backed, so this
	// catches an out-of-range value before it reaches a manifest.
	ErrUnsupportedSegmentIntegrityAlgorithm = errors.New("tdf: unsupported segment integrity algorithm")

	// kasGenericBadRequest is the substring the SDK looks for in serialized
	// KAS 400 errors to identify potential tamper. KAS uses the generic message
	// "bad request" for errors involving secret key material (policy binding,
	// DEK decryption). Per-KAO errors are serialized as plain strings through
	// the proto response (not as gRPC status errors), so substring matching is
	// the only classification mechanism available.
	//
	// The "desc = " prefix anchors the match to the gRPC status description
	// field, avoiding false positives from middleware or error wrapping that
	// might incidentally contain "bad request".
	//
	// Must stay in sync with the "bad request" message in
	// service/kas/access/rewrap.go — and descriptive KAS messages must NOT
	// contain this substring.
	kasGenericBadRequest = "desc = bad request"

	// KAS request errors — client/configuration issues, not integrity failures
	ErrKASRequestError = errors.New("tdf: KAS request error")
	ErrRewrapForbidden = errors.New("tdf: rewrap request 403")
)

// AssertionFailureReason is the stable code that explains why an assertion,
// or the manifest that carries it, was rejected. The values are the reason
// strings of the ZTDF assertions specification, Section 9.
type AssertionFailureReason string

const (
	// AssertionReasonInvalidJSON: the manifest is not JSON, or an assertion
	// object is not I-JSON (lone surrogate, noncharacter, invalid UTF-8, or a
	// number outside the IEEE 754 double range).
	AssertionReasonInvalidJSON AssertionFailureReason = "invalid-json"
	// AssertionReasonDuplicateMember: an object in the manifest repeats a
	// member name, compared after decoding escapes.
	AssertionReasonDuplicateMember AssertionFailureReason = "duplicate-member"
	// AssertionReasonAmbiguousMember: an object at a modelled level holds a
	// case variant of a modelled member name, such as "ID" or "Assertions",
	// or two members whose names differ only in case.
	AssertionReasonAmbiguousMember AssertionFailureReason = "ambiguous-member"
	// AssertionReasonInvalidID: the assertion's "id" is missing, empty, or
	// not a JSON string.
	AssertionReasonInvalidID AssertionFailureReason = "invalid-id"
	// AssertionReasonInvalidStatement is reserved for statement checks that the
	// specification still marks as proposed. Nothing returns it yet.
	AssertionReasonInvalidStatement AssertionFailureReason = "invalid-statement"
	// AssertionReasonInvalidBinding: the binding is missing, is not an object,
	// carries both binding forms or neither, or holds a malformed JWS.
	AssertionReasonInvalidBinding AssertionFailureReason = "invalid-binding"
	// AssertionReasonUnsupportedBinding: the binding names an unknown method,
	// or is a STANAG 4778 binding object, which this SDK does not verify.
	AssertionReasonUnsupportedBinding AssertionFailureReason = "unsupported-binding"
	// AssertionReasonUnsupportedAlgorithm: the JWS alg is missing, "none", or
	// not one this SDK verifies.
	AssertionReasonUnsupportedAlgorithm AssertionFailureReason = "unsupported-algorithm"
	// AssertionReasonAlgorithmMismatch: the JWS alg differs from the algorithm
	// configured for the selected key.
	AssertionReasonAlgorithmMismatch AssertionFailureReason = "algorithm-mismatch"
	// AssertionReasonInvalidEmbeddedKey: an embedded jwk or x5c is symmetric,
	// private, malformed, contradictory, or present when the selected key is
	// an HMAC secret.
	AssertionReasonInvalidEmbeddedKey AssertionFailureReason = "invalid-embedded-key"
	// AssertionReasonSignerNotPermitted: an embedded key is not the selected
	// verification key.
	AssertionReasonSignerNotPermitted AssertionFailureReason = "signer-not-permitted"
	// AssertionReasonSignatureInvalid: the JWS signature does not verify under
	// the selected key.
	AssertionReasonSignatureInvalid AssertionFailureReason = "signature-invalid"
	// AssertionReasonBindingMismatch: the assertionHash or assertionSig claim
	// is missing, not a string, or differs from the recomputed value.
	AssertionReasonBindingMismatch AssertionFailureReason = "binding-mismatch"
	// AssertionReasonConfigurationError: the verification key selected for the
	// assertion is empty, unusable, or of the wrong type for its algorithm.
	AssertionReasonConfigurationError AssertionFailureReason = "configuration-error"
)

// ErrAssertionFailure reports an assertion that failed verification, or a
// manifest rejected while parsing its assertions. It unwraps to ErrTampered.
//
// ID is the assertion's exact "id" when one could be read, and empty
// otherwise. Reason is a single stable code; match on it with errors.As
// rather than on the message text.
type ErrAssertionFailure struct { //nolint:errname // match naming of existing errors
	ID     string
	Reason AssertionFailureReason
}

func (e ErrAssertionFailure) Error() string {
	msg := fmt.Sprintf("[%s] tdf: issue verifying assertions", ErrTampered)
	if e.ID != "" {
		msg += ", id: " + renderAssertionID(e.ID)
	}
	if e.Reason != "" {
		msg += ", reason=" + string(e.Reason)
	}
	return msg
}

func (e ErrAssertionFailure) Unwrap() error {
	return ErrTampered
}

// maxRenderedIDLength caps how many code points of an assertion id an error
// message shows.
const maxRenderedIDLength = 256

// renderAssertionID returns id for an error message. The id comes from the
// TDF, so backslashes and control characters (U+0000 to U+001F and U+007F to
// U+009F) are escaped as in JSON, and a long id is cut at 256 code points and
// marked with an ellipsis. The id can then neither break the message across
// lines nor hide its real end. ErrAssertionFailure.ID keeps the exact id.
func renderAssertionID(id string) string {
	var b strings.Builder
	n := 0
	for _, r := range id {
		if n == maxRenderedIDLength {
			b.WriteString("…")
			break
		}
		n++
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r < 0x20 || (r >= 0x7F && r <= 0x9F):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// assertionFailure returns an ErrAssertionFailure for id and reason, followed
// in the message by detail. The detail never holds key material.
func assertionFailure(id string, reason AssertionFailureReason, detail string) error {
	return fmt.Errorf("%w: %s", ErrAssertionFailure{ID: id, Reason: reason}, detail)
}
