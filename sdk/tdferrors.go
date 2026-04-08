package sdk

import (
	"errors"
	"fmt"
)

var (
	errFileTooLarge     = errors.New("tdf: can't create tdf larger than 64gb")
	errWriteFailed      = errors.New("tdf: io.writer fail to write all bytes")
	errInvalidKasInfo   = errors.New("tdf: kas information is missing")
	errKasPubKeyMissing = errors.New("tdf: kas public key is missing")

	// Exposed tamper detection errors, Catch all possible tamper errors with errors.Is(ErrTampered)
	ErrTampered                = errors.New("tamper detected")
	ErrRootSigValidation       = fmt.Errorf("[%w] tdf: failed integrity check on root signature", ErrTampered)
	ErrSegSizeMismatch         = fmt.Errorf("[%w] tdf: mismatch encrypted segment size in manifest", ErrTampered)
	ErrSegSigValidation        = fmt.Errorf("[%w] tdf: failed integrity check on segment hash", ErrTampered)
	ErrTDFPayloadReadFail      = fmt.Errorf("[%w] tdf: fail to read payload from tdf", ErrTampered)
	ErrTDFPayloadInvalidOffset = fmt.Errorf("[%w] sdk.Reader.ReadAt: negative offset", ErrTampered)
	ErrRootSignatureFailure    = fmt.Errorf("[%w] tdf: issue verifying root signature", ErrTampered)
	ErrRewrapBadRequest        = fmt.Errorf("[%w] tdf: rewrap request 400", ErrTampered)

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

// Custom error struct for Assertion errors
type ErrAssertionFailure struct { //nolint:errname // match naming of existing errors
	ID string
}

func (e ErrAssertionFailure) Error() string {
	return fmt.Errorf("[%w] tdf: issue verifying assertions, id: %s", ErrTampered, e.ID).Error()
}

func (e ErrAssertionFailure) Unwrap() error {
	return ErrTampered
}
