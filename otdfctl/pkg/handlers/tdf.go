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

	"github.com/opentdf/platform/otdfctl/pkg/tdf"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
	"github.com/opentdf/platform/lib/ocrypto"
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
	NanoHeader          *sdk.NanoTDFHeader
	ZTDFManifest        *sdk.Manifest
	Attributes          []string
	UnencryptedMetadata []byte
}

func (h Handler) EncryptBytes(
	tdfType string,
	unencrypted []byte,
	attrValues []string,
	mimeType string,
	kasURLPath string,
	ecdsaBinding bool,
	assertions string,
	wrappingKeyAlgorithm ocrypto.KeyType,
	policyMode string,
	targetMode string,
) (*bytes.Buffer, error) {
	var encrypted []byte
	enc := bytes.NewBuffer(encrypted)

	switch tdfType {
	// Encrypt the data as a ZTDF
	case "", tdf.TypeTDF3, tdf.TypeZTDF:
		if ecdsaBinding {
			return nil, errors.New("ECDSA policy binding is not supported for ZTDF")
		}
		if policyMode != "" {
			return nil, errors.New("policy mode is not supported for ZTDF")
		}

		opts := []sdk.TDFOption{
			sdk.WithDataAttributes(attrValues...),
			sdk.WithKasInformation(sdk.KASInfo{
				URL: h.platformEndpoint + kasURLPath,
			}),
			sdk.WithMimeType(mimeType),
			sdk.WithWrappingKeyAlg(wrappingKeyAlgorithm),
		}

		var assertionConfigs []sdk.AssertionConfig
		//nolint:nestif // nested its mainly for error catching and handling case of string vs file
		if assertions != "" {
			err := json.Unmarshal([]byte(assertions), &assertionConfigs)
			if err != nil {
				// if unable to marshal to json, interpret as file string and try to read from file
				assertionBytes, err := utils.ReadBytesFromFile(assertions, MaxAssertionsFileSize)
				if err != nil {
					return nil, fmt.Errorf("unable to read assertions file: %w", err)
				}
				err = json.Unmarshal(assertionBytes, &assertionConfigs)
				if err != nil {
					return nil, fmt.Errorf("unable to unmarshal assertions json: %w", err)
				}
			}
			for i, config := range assertionConfigs {
				if !config.SigningKey.IsEmpty() {
					correctedKey, err := correctKeyType(config.SigningKey, false)
					if err != nil {
						return nil, fmt.Errorf("error with assertion signing key: %w", err)
					}
					assertionConfigs[i].SigningKey.Key = correctedKey
				}
			}
			opts = append(opts, sdk.WithAssertions(assertionConfigs...))
		}

		if targetMode != "" {
			opts = append(opts, sdk.WithTargetMode(targetMode))
		}

		_, err := h.sdk.CreateTDF(enc, bytes.NewReader(unencrypted), opts...)
		return enc, err

	// Encrypt the data as a Nano TDF
	case tdf.TypeNanoTDF:
		nanoTDFConfig, err := h.sdk.NewNanoTDFConfig()
		if err != nil {
			return nil, err
		}
		// set the KAS URL
		if err = nanoTDFConfig.SetKasURL(h.platformEndpoint + kasURLPath); err != nil {
			return nil, err
		}
		// set the attributes
		if err = nanoTDFConfig.SetAttributes(attrValues); err != nil {
			return nil, err
		}
		// enable ECDSA policy binding
		if ecdsaBinding {
			nanoTDFConfig.EnableECDSAPolicyBinding()
		}
		switch policyMode {
		case "", "encrypted":
			err = nanoTDFConfig.SetPolicyMode(sdk.NanoTDFPolicyModeEncrypted)
		case "plaintext":
			err = nanoTDFConfig.SetPolicyMode(sdk.NanoTDFPolicyModePlainText)
		default:
			return nil, fmt.Errorf("policy mode unrecognized: [%s]", policyMode)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to set policy mode: [%w]", err)
		}
		// create the nano TDF
		if _, err = h.sdk.CreateNanoTDF(enc, bytes.NewReader(unencrypted), *nanoTDFConfig); err != nil {
			return nil, err
		}
		return enc, nil
	default:
		return nil, errors.New("unknown TDF type")
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
	case sdk.Nano:
		opts := []sdk.NanoTDFReaderOption{
			sdk.WithNanoIgnoreAllowlist(ignoreAllowlist),
			sdk.WithNanoTDFFulfillableObligationFQNs(fulfillableObligations),
		}
		if kasAllowList != nil {
			opts = append(opts, sdk.WithNanoKasAllowlist(kasAllowList))
		}

		n, err := h.sdk.LoadNanoTDF(ctx, ec, opts...)
		if err != nil {
			return nil, err
		}

		if _, err := n.DecryptNanoTDF(ctx, pt); err != nil {
			return nil, formatDecryptError(ctx, n.Obligations, err)
		}
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

// TODO: Rename. Not sure what this value is at present
const inspectTDFEighteen = 18

func (h Handler) InspectTDF(toInspect []byte) (TDFInspect, []error) {
	b := bytes.NewReader(toInspect)
	switch sdk.GetTdfType(b) {
	case sdk.Standard:
		// grouping errors so we don't impact the piping of the data
		errs := []error{}

		tdfreader, err := h.sdk.LoadTDF(bytes.NewReader(toInspect))
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
	case sdk.Nano:
		header, size, err := sdk.NewNanoTDFHeaderFromReader(b)
		if err != nil {
			return TDFInspect{}, []error{errors.Join(ErrTDFInspectFailNotValidTDF, err)}
		}
		r := TDFInspect{
			NanoHeader: &header,
		}
		remainder := len(toInspect) - int(size)
		if remainder < inspectTDFEighteen {
			return r, []error{ErrTDFInspectFailNotValidTDF}
		}
		return r, nil
	case sdk.Invalid:
		return TDFInspect{}, []error{ErrTDFInspectFailNotValidTDF}
	default:
		return TDFInspect{}, []error{fmt.Errorf("tdf format unrecognized")}
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
			slog.DebugContext(ctx, "Failed to get obligations after decrypt, obligations must not be cached", "error", oblErr)
		}

		if len(obligations.FQNs) > 0 {
			err = errors.Join(err, fmt.Errorf("\nrequired obligations: %v", obligations.FQNs))
		}
	}
	return err
}
