package handlers

import (
	"bytes"
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

// EncryptOptions carries the non-stream inputs to Encrypt.
type EncryptOptions struct {
	TDFType              string
	Attributes           []string
	MimeType             string
	KASURLPath           string
	Assertions           string
	WrappingKeyAlgorithm ocrypto.KeyType
	TargetMode           string
}

// Encrypt streams the plaintext from in to a TDF written to out. Memory use is
// bounded by the SDK's segment size rather than by the payload length, so the
// payload may be larger than RAM.
//
// in must be seekable: the SDK measures the payload by seeking to its end
// before encrypting, and knowing the length up front is what lets it avoid
// defaulting to ZIP64. A caller holding a pipe should spool it first.
func (h Handler) Encrypt(ctx context.Context, out io.Writer, in io.ReadSeeker, o EncryptOptions) error {
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

func (h Handler) DecryptBytes(
	ctx context.Context,
	toDecrypt []byte,
	assertionVerificationKeysFile string,
	disableAssertionCheck bool,
	sessionKeyAlgorithm ocrypto.KeyType,
	kasAllowList []string,
	ignoreAllowlist bool,
	fulfillableObligations []string,
) (*bytes.Buffer, error) {
	out := &bytes.Buffer{}
	pt := io.Writer(out)
	ec := bytes.NewReader(toDecrypt)
	switch sdk.GetTdfType(ec) {
	case sdk.Standard:
		opts := []sdk.TDFReaderOption{
			sdk.WithDisableAssertionVerification(disableAssertionCheck),
			sdk.WithSessionKeyType(sessionKeyAlgorithm),
			sdk.WithIgnoreAllowlist(ignoreAllowlist),
			sdk.WithTDFFulfillableObligationFQNs(fulfillableObligations),
		}
		if kasAllowList != nil {
			opts = append(opts, sdk.WithKasAllowlist(kasAllowList))
		}
		var assertionVerificationKeys sdk.AssertionVerificationKeys
		if assertionVerificationKeysFile != "" {
			// read the file
			assertionVerificationBytes, err := utils.ReadBytesFromFile(assertionVerificationKeysFile, MaxAssertionsFileSize)
			if err != nil {
				return nil, fmt.Errorf("unable to read assertions verification keys file: %w", err)
			}
			err = json.Unmarshal(assertionVerificationBytes, &assertionVerificationKeys)
			if err != nil {
				return nil, fmt.Errorf("unable to unmarshal assertion verification keys json: %w", err)
			}
			for assertionName, key := range assertionVerificationKeys.Keys {
				correctedKey, err := correctKeyType(key, true)
				if err != nil {
					return nil, fmt.Errorf("error with assertion signing key: %w", err)
				}
				assertionVerificationKeys.Keys[assertionName] = sdk.AssertionKey{Alg: key.Alg, Key: correctedKey}
			}
			opts = append(opts, sdk.WithAssertionVerificationKeys(assertionVerificationKeys))
		}
		r, err := h.sdk.LoadTDF(ec, opts...)
		if err != nil {
			return nil, err
		}
		//nolint:errorlint // callers intended to test error equality directly
		if _, err = io.Copy(pt, r); err != nil && err != io.EOF {
			return nil, formatDecryptError(ctx, r.Obligations, err)
		}
	case sdk.Invalid:
		return nil, errors.New("invalid TDF")
	default:
		return nil, errors.New("unknown TDF type")
	}
	return out, nil
}

// InspectTDF reads the manifest and attributes of a TDF.
//
// It takes an io.ReadSeeker rather than a byte slice because only the manifest
// at the end of the archive is needed; buffering the whole payload to reach it
// costs memory proportional to the file. GetTdfType rewinds to the start, so
// the reader is positioned for LoadTDF.
func (h Handler) InspectTDF(toInspect io.ReadSeeker) (TDFInspect, []error) {
	switch sdk.GetTdfType(toInspect) {
	case sdk.Standard:
		// grouping errors so we don't impact the piping of the data
		errs := []error{}

		tdfreader, err := h.sdk.LoadTDF(toInspect)
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
