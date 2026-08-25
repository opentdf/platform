package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/otdfctl/pkg/tdf"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
	"github.com/opentdf/platform/sdk"
)

var (
	ErrTDFInspectFailNotValidTDF                = errors.New("file or input is not a valid TDF")
	ErrTDFInspectFailNotInspectable             = errors.New("file or input is not inspectable")
	ErrTDFUnableToReadAttributes                = errors.New("unable to read attributes from TDF")
	ErrTDFUnableToReadUnencryptedMetadata       = errors.New("unable to read unencrypted metadata from TDF")
	ErrTDFUnableToReadAssertions                = errors.New("unable to read assertions")
	ErrTDFUnableToReadAssertionVerificationKeys = errors.New("unable to read assertion verification keys")
)

const (
	MaxAssertionsFileSize = int64(5 * 1024 * 1024) // 5MB
)

type TDFInspect struct {
	ZTDFManifest        *sdk.Manifest
	Attributes          []string
	UnencryptedMetadata []byte
}

// InputSizeUnknown marks a payload whose length cannot be established up front,
// such as one arriving on a pipe. Encrypt passes it through to the SDK, which
// then measures the payload by reading it.
const InputSizeUnknown = int64(-1)

// EncryptOptions carries the non-stream inputs to Encrypt.
type EncryptOptions struct {
	TDFType              string
	Attributes           []string
	MimeType             string
	KASURLPath           string
	Assertions           string
	WrappingKeyAlgorithm ocrypto.KeyType
	TargetMode           string

	// InputSize is the payload length in bytes, or InputSizeUnknown when it
	// cannot be determined without consuming the reader. Supplying a known
	// length lets the SDK size the archive up front rather than defaulting to
	// ZIP64, which keeps output byte-comparable with a seekable reader.
	InputSize int64
}

// Encrypt streams the plaintext from in to a TDF written to out. Memory use is
// bounded by the SDK's segment size rather than by the payload length, so in
// may be a pipe and the payload may be larger than RAM.
func (h Handler) Encrypt(ctx context.Context, out io.Writer, in io.Reader, o EncryptOptions) error {
	switch o.TDFType {
	// Encrypt the data as a ZTDF
	case "", tdf.TypeTDF3, tdf.TypeZTDF:
		opts := []sdk.TDFOption{
			sdk.WithDataAttributes(o.Attributes...),
			sdk.WithKasInformation(sdk.KASInfo{
				URL: h.platformEndpoint + o.KASURLPath,
			}),
			sdk.WithMimeType(o.MimeType),
			sdk.WithWrappingKeyAlg(o.WrappingKeyAlgorithm), //nolint:staticcheck // SDK option is deprecated but no replacement is available in this SDK version.
		}

		if o.InputSize >= 0 {
			opts = append(opts, sdk.WithInputSize(o.InputSize))
		}

		var assertionConfigs []sdk.AssertionConfig
		//nolint:nestif // nested its mainly for error catching and handling case of string vs file
		if o.Assertions != "" {
			err := json.Unmarshal([]byte(o.Assertions), &assertionConfigs)
			if err != nil {
				// if unable to marshal to json, interpret as file string and try to read from file
				assertionBytes, err := utils.ReadBytesFromFile(o.Assertions, MaxAssertionsFileSize)
				if err != nil {
					return fmt.Errorf("unable to read assertions file: %w", err)
				}
				err = json.Unmarshal(assertionBytes, &assertionConfigs)
				if err != nil {
					return fmt.Errorf("unable to unmarshal assertions json: %w", err)
				}
			}
			for i, config := range assertionConfigs {
				if !config.SigningKey.IsEmpty() {
					correctedKey, err := correctKeyType(config.SigningKey, false)
					if err != nil {
						return fmt.Errorf("error with assertion signing key: %w", err)
					}
					assertionConfigs[i].SigningKey.Key = correctedKey
				}
			}
			opts = append(opts, sdk.WithAssertions(assertionConfigs...))
		}

		if o.TargetMode != "" {
			opts = append(opts, sdk.WithTargetMode(o.TargetMode))
		}

		_, err := h.sdk.CreateTDFContext(ctx, out, in, opts...)
		return err
	default:
		return errors.New("unknown TDF type")
	}
}

// DecryptOptions carries the non-stream inputs to Decrypt.
type DecryptOptions struct {
	AssertionVerificationKeysFile string
	DisableAssertionCheck         bool
	SessionKeyAlgorithm           ocrypto.KeyType
	KASAllowList                  []string
	IgnoreAllowlist               bool
	FulfillableObligations        []string
}

// streamingCopy asserts that the SDK reader is copied one segment at a time.
//
// io.Copy prefers WriteTo when the source implements it, and sdk.Reader's
// WriteTo decrypts segment by segment. Without it, io.Copy would fall back to
// Read, which serves bytes from an internal buffer grown by ReadAt — putting
// the whole payload back in memory and silently undoing this change with no
// test failure to show for it.
var _ io.WriterTo = (*sdk.Reader)(nil)

// Decrypt streams the plaintext of the TDF in in to out. Memory use is bounded
// by the SDK's segment size rather than by the payload length.
//
// in must be seekable because the TDF's manifest lives at the end of the
// archive; callers with a pipe need to spool it first.
func (h Handler) Decrypt(ctx context.Context, out io.Writer, in io.ReadSeeker, o DecryptOptions) error {
	switch sdk.GetTdfType(in) {
	case sdk.Standard:
		opts := []sdk.TDFReaderOption{
			sdk.WithDisableAssertionVerification(o.DisableAssertionCheck),
			sdk.WithSessionKeyType(o.SessionKeyAlgorithm),
			sdk.WithIgnoreAllowlist(o.IgnoreAllowlist),
			sdk.WithTDFFulfillableObligationFQNs(o.FulfillableObligations),
		}
		if o.KASAllowList != nil {
			opts = append(opts, sdk.WithKasAllowlist(o.KASAllowList))
		}
		var assertionVerificationKeys sdk.AssertionVerificationKeys
		if o.AssertionVerificationKeysFile != "" {
			// read the file
			assertionVerificationBytes, err := utils.ReadBytesFromFile(o.AssertionVerificationKeysFile, MaxAssertionsFileSize)
			if err != nil {
				return fmt.Errorf("unable to read assertions verification keys file: %w", err)
			}
			err = json.Unmarshal(assertionVerificationBytes, &assertionVerificationKeys)
			if err != nil {
				return fmt.Errorf("unable to unmarshal assertion verification keys json: %w", err)
			}
			for assertionName, key := range assertionVerificationKeys.Keys {
				correctedKey, err := correctKeyType(key, true)
				if err != nil {
					return fmt.Errorf("error with assertion signing key: %w", err)
				}
				assertionVerificationKeys.Keys[assertionName] = sdk.AssertionKey{Alg: key.Alg, Key: correctedKey}
			}
			opts = append(opts, sdk.WithAssertionVerificationKeys(assertionVerificationKeys))
		}
		r, err := h.sdk.LoadTDF(in, opts...)
		if err != nil {
			return err
		}
		//nolint:errorlint // callers intended to test error equality directly
		if _, err = io.Copy(out, r); err != nil && err != io.EOF {
			return formatDecryptError(ctx, r.Obligations, err)
		}
	case sdk.Invalid:
		return errors.New("invalid TDF")
	default:
		return errors.New("unknown TDF type")
	}
	return nil
}

// InspectTDF reads a TDF's manifest without materializing its payload.
func (h Handler) InspectTDF(in io.ReadSeeker) (TDFInspect, []error) {
	switch sdk.GetTdfType(in) {
	case sdk.Standard:
		// grouping errors so we don't impact the piping of the data
		errs := []error{}

		// GetTdfType restores the offset it started from, but LoadTDF expects to
		// begin at the head of the archive regardless of where the caller was.
		if _, err := in.Seek(0, io.SeekStart); err != nil {
			return TDFInspect{}, []error{errors.Join(ErrTDFInspectFailNotInspectable, err)}
		}

		tdfreader, err := h.sdk.LoadTDF(in)
		if err != nil {
			if strings.Contains(err.Error(), "zip: not a valid zip file") {
				return TDFInspect{}, []error{ErrTDFInspectFailNotInspectable}
			}
			return TDFInspect{}, []error{errors.Join(ErrTDFInspectFailNotValidTDF, err)}
		}

		attributes, err := tdfreader.DataAttributes()
		if err != nil {
			errs = append(errs, errors.Join(ErrTDFUnableToReadAttributes, err))
		}

		unencryptedMetadata, err := tdfreader.UnencryptedMetadata()
		if err != nil {
			errs = append(errs, errors.Join(ErrTDFUnableToReadUnencryptedMetadata, err))
		}

		m := tdfreader.Manifest()
		return TDFInspect{
			ZTDFManifest:        &m,
			Attributes:          attributes,
			UnencryptedMetadata: unencryptedMetadata,
		}, errs
	case sdk.Invalid:
		return TDFInspect{}, []error{ErrTDFInspectFailNotValidTDF}
	default:
		return TDFInspect{}, []error{errors.New("tdf format unrecognized")}
	}
}

func correctKeyType(assertionKey sdk.AssertionKey, public bool) (interface{}, error) {
	strKey, ok := assertionKey.Key.(string)
	if !ok {
		return nil, errors.New("unable to convert assertion key to string")
	}

	switch assertionKey.Alg {
	case sdk.AssertionKeyAlgHS256:
		// convert the hs256 key to []byte
		return []byte(strKey), nil
	case sdk.AssertionKeyAlgRS256:
		// Decode the PEM block
		block, _ := pem.Decode([]byte(strKey))
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}

		// Check the block type and parse accordingly
		var privateKey *rsa.PrivateKey
		var publicKey *rsa.PublicKey
		var err error
		switch block.Type {
		case "RSA PRIVATE KEY":
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			publicKey = &privateKey.PublicKey
		case "PRIVATE KEY":
			parsedKey, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", parseErr)
			}
			privateKey, ok = parsedKey.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("parsed key is not an RSA private key")
			}
			publicKey = &privateKey.PublicKey
		case "RSA PUBLIC KEY":
			publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		case "PUBLIC KEY":
			parsedKey, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("failed to parse PKIX public key: %w", parseErr)
			}
			publicKey, ok = parsedKey.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("parsed key is not an RSA public key")
			}
		default:
			return nil, fmt.Errorf("unsupported key type: %s", block.Type)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		if public {
			return publicKey, nil
		}
		return privateKey, nil
	}
	return nil, fmt.Errorf("unsupported signing key alg: %v", assertionKey.Alg)
}

func formatDecryptError(ctx context.Context, getObligations func(ctx context.Context) (sdk.RequiredObligations, error), err error) error {
	// Avoid calling Rewrap again, if the error is a 500 error from KAS
	if errors.Is(err, sdk.ErrRewrapForbidden) {
		obligations, oblErr := getObligations(ctx)
		if oblErr != nil {
			slog.DebugContext(ctx, "failed to get obligations after decrypt, obligations must not be cached",
				slog.Any("error", oblErr),
			)
		}

		if len(obligations.FQNs) > 0 {
			err = errors.Join(err, fmt.Errorf("\nrequired obligations: %v", obligations.FQNs))
		}
	}
	return err
}
