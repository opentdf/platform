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
// in need not be seekable, but a seekable one is measurable, and the SDK gives a
// measured payload two things an unmeasurable one cannot have. It gets the
// compact ZIP32 layout below ~2 GiB, where an unmeasurable payload pays a few
// dozen bytes for ZIP64 — a choice fixed before the first segment goes out. And
// it gets a length check, so a reader that runs dry early fails instead of
// yielding a complete-looking TDF holding a truncated payload.
//
// Neither is worth spooling a stream to disk for: needing a writable temp
// directory to encrypt a pipe costs more than it buys. This is what the rest of
// otdfctl means by "keeping the payload measurable"; see streamio.Measurable.
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
//
// Every field is optional; the zero value means "use the SDK default". That
// holds for SessionKeyAlgorithm in particular: the empty string is not a valid
// ocrypto.KeyType, so it is left unset rather than forwarded.
type DecryptOptions struct {
	// URL, when set, loads the TDF over HTTP(S) range requests instead of from in.
	URL                           string
	AssertionVerificationKeysFile string
	DisableAssertionCheck         bool
	SessionKeyAlgorithm           ocrypto.KeyType
	KASAllowList                  []string
	IgnoreAllowlist               bool
	FulfillableObligations        []string
	// RangeOffset and RangeLimit select a plaintext byte range; a negative
	// RangeLimit reads to the end. Only the segments covering the range are read
	// and decrypted.
	RangeOffset int64
	RangeLimit  int64
}

// errRangeComplete stops Reader.WriteTo once the requested range is written.
var errRangeComplete = errors.New("requested range written")

// rangeWriter passes through at most remaining bytes, then returns
// errRangeComplete so the reader stops before fetching another segment.
type rangeWriter struct {
	w         io.Writer
	remaining int64
}

func (rw *rangeWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > rw.remaining {
		p = p[:rw.remaining]
	}
	n, err := rw.w.Write(p)
	rw.remaining -= int64(n)
	if err == nil && rw.remaining == 0 {
		err = errRangeComplete
	}
	return n, err
}

// The assertion below is what keeps Decrypt's io.Copy streaming one segment at
// a time.
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
	if o.RangeOffset < 0 {
		return errors.New("offset must not be negative")
	}

	opts := []sdk.TDFReaderOption{
		sdk.WithDisableAssertionVerification(o.DisableAssertionCheck),
		sdk.WithIgnoreAllowlist(o.IgnoreAllowlist),
		sdk.WithTDFFulfillableObligationFQNs(o.FulfillableObligations),
	}
	// Forwarding an unset algorithm would fail in ocrypto.NewKeyPair before
	// the TDF is read at all. Omitting the option instead lets the SDK apply
	// its own RSA-2048 default, which is the algorithm the CLI asks for.
	if o.SessionKeyAlgorithm != "" {
		opts = append(opts, sdk.WithSessionKeyType(o.SessionKeyAlgorithm))
	}
	if o.KASAllowList != nil {
		opts = append(opts, sdk.WithKasAllowlist(o.KASAllowList))
	}
	if o.AssertionVerificationKeysFile != "" {
		assertionVerificationKeys, err := readAssertionVerificationKeys(o.AssertionVerificationKeysFile)
		if err != nil {
			return err
		}
		opts = append(opts, sdk.WithAssertionVerificationKeys(assertionVerificationKeys))
	}

	var r *sdk.Reader
	var err error
	if o.URL != "" {
		r, err = h.sdk.LoadTDFFromURL(ctx, o.URL, opts...)
	} else {
		switch sdk.GetTdfType(in) {
		case sdk.Standard:
			r, err = h.sdk.LoadTDF(in, opts...)
		case sdk.Invalid:
			return errors.New("invalid TDF")
		default:
			return errors.New("unknown TDF type")
		}
	}
	if err != nil {
		return err
	}

	if _, err := r.Seek(o.RangeOffset, io.SeekStart); err != nil {
		return fmt.Errorf("offset %d is beyond the end of the payload: %w", o.RangeOffset, err)
	}
	if o.RangeLimit == 0 {
		return nil
	}
	if o.RangeLimit > 0 {
		out = &rangeWriter{w: out, remaining: o.RangeLimit}
	}
	//nolint:errorlint // callers intended to test error equality directly
	if _, err := io.Copy(out, r); err != nil && err != io.EOF && !errors.Is(err, errRangeComplete) {
		return formatDecryptError(ctx, r.Obligations, err)
	}
	return nil
}

func readAssertionVerificationKeys(path string) (sdk.AssertionVerificationKeys, error) {
	var keys sdk.AssertionVerificationKeys
	b, err := utils.ReadBytesFromFile(path, MaxAssertionsFileSize)
	if err != nil {
		return keys, fmt.Errorf("unable to read assertions verification keys file: %w", err)
	}
	if err := json.Unmarshal(b, &keys); err != nil {
		return keys, fmt.Errorf("unable to unmarshal assertion verification keys json: %w", err)
	}
	for assertionName, key := range keys.Keys {
		correctedKey, err := correctKeyType(key, true)
		if err != nil {
			return keys, fmt.Errorf("error with assertion signing key: %w", err)
		}
		keys.Keys[assertionName] = sdk.AssertionKey{Alg: key.Alg, Key: correctedKey}
	}
	return keys, nil
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
