package sdk

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
)

const (
	tdf3KeySize            = 2048
	defaultMaxManifestSize = 10 * 1024 * 1024 // 10 MB
	defaultSegmentSize     = 2 * 1024 * 1024  // 2mb
	maxSegmentSize         = defaultSegmentSize * 2
	minSegmentSize         = 16 * 1024
	DefaultRSAKeySize      = 2048
	ECKeySize256           = 256
	ECKeySize384           = 384
	ECKeySize521           = 521
)

type TDFFormat = int

const (
	JSONFormat = iota
	XMLFormat
)

const (
	schemeHTTPS     = "https"
	schemeSeperator = "://"
)

type IntegrityAlgorithm = int

const (
	HS256 = iota
	GMAC
)

// KASInfo contains Key Access Server information.
type KASInfo struct {
	// URL of the KAS server
	URL string
	// Public key can be empty.
	// If it is empty, the public key will be fetched from the KAS server.
	PublicKey string
	// Key identifier associated with the given key, if present.
	KID string
	// The algorithm associated with this key
	Algorithm string
	// If this KAS should be used as the default for 'encrypt' calls
	Default bool
}

type TDFOption func(*TDFConfig) error

// TDFConfig Internal config struct for building TDF options.
type TDFConfig struct {
	autoconfigure              bool
	defaultSegmentSize         int64
	enableEncryption           bool
	tdfFormat                  TDFFormat
	metaData                   string
	mimeType                   string
	integrityAlgorithm         IntegrityAlgorithm
	segmentIntegrityAlgorithm  IntegrityAlgorithm
	assertions                 []AssertionConfig
	attributes                 []AttributeValueFQN
	attributeValues            []*policy.Value
	kasInfoList                []KASInfo
	kaoTemplate                []kaoTpl
	splitPlan                  []keySplitStep
	preferredKeyWrapAlg        ocrypto.KeyType
	useHex                     bool
	excludeVersionFromManifest bool
	addDefaultAssertion        bool
}

func newTDFConfig(opt ...TDFOption) (*TDFConfig, error) {
	c := &TDFConfig{
		autoconfigure:             true,
		defaultSegmentSize:        defaultSegmentSize,
		enableEncryption:          true,
		tdfFormat:                 JSONFormat,
		integrityAlgorithm:        HS256,
		segmentIntegrityAlgorithm: GMAC,
		addDefaultAssertion:       false,
	}

	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

// WithDataAttributes appends the given data attributes to the bound policy
func WithDataAttributes(attributes ...string) TDFOption {
	return func(c *TDFConfig) error {
		c.attributeValues = nil
		for _, a := range attributes {
			v, err := NewAttributeValueFQN(a)
			if err != nil {
				return err
			}
			c.attributes = append(c.attributes, v)
		}
		return nil
	}
}

// WithDataAttributeValues appends the given data attributes to the bound policy.
// Unlike `WithDataAttributes`, this will not trigger an attribute definition lookup
// during autoconfigure. That is, to use autoconfigure in an 'offline' context,
// you must first store the relevant attribute information locally and load
// it to the `CreateTDF` method with this option.
// DEPRECATION: This option is deprecated and will be removed in a future release.
func WithDataAttributeValues(attributes ...*policy.Value) TDFOption {
	return func(c *TDFConfig) error {
		c.attributes = make([]AttributeValueFQN, len(attributes))
		c.attributeValues = make([]*policy.Value, len(attributes))
		for i, a := range attributes {
			c.attributeValues[i] = a
			afqn, err := NewAttributeValueFQN(a.GetFqn())
			if err != nil {
				// TODO: update service to validate and encode FQNs properly
				return err
			}
			c.attributes[i] = afqn
		}
		return nil
	}
}

// WithKasInformation adds all the kas urls and their corresponding public keys
// that is required to create and read the tdf.
// For writing TDFs, this is optional, but adding it can bypass key lookup.
//
// During creation, if the public key is set, the kas will not be contacted for the latest key.
// Please make sure to set the KID if the PublicKey is set to include a KID in any key wrappers.
func WithKasInformation(kasInfoList ...KASInfo) TDFOption {
	return func(c *TDFConfig) error {
		newKasInfos := make([]KASInfo, 0)
		newKasInfos = append(newKasInfos, kasInfoList...)
		c.kasInfoList = newKasInfos

		return nil
	}
}

func withSplitPlan(p ...keySplitStep) TDFOption {
	return func(c *TDFConfig) error {
		c.splitPlan = make([]keySplitStep, len(p))
		copy(c.splitPlan, p)
		c.autoconfigure = false
		return nil
	}
}

// WithMetaData returns an Option that add metadata to TDF.
func WithMetaData(metaData string) TDFOption {
	return func(c *TDFConfig) error {
		c.metaData = metaData
		return nil
	}
}

func WithMimeType(mimeType string) TDFOption {
	return func(c *TDFConfig) error {
		c.mimeType = mimeType
		return nil
	}
}

// WithSegmentSize returns an Option that set the default segment size within the TDF. Any excessively large or small
// values will be replaced with a supported value.
func WithSegmentSize(size int64) TDFOption {
	if size > maxSegmentSize {
		size = maxSegmentSize
	} else if size < minSegmentSize {
		size = minSegmentSize
	}
	return func(c *TDFConfig) error {
		c.defaultSegmentSize = size
		return nil
	}
}

// WithDefaultAssertion returns an Option that adds a default assertion to the TDF.
func WithSystemMetadataAssertion() TDFOption {
	return func(c *TDFConfig) error {
		c.addDefaultAssertion = true
		return nil
	}
}

// WithAssertions returns an Option that add assertions to TDF.
func WithAssertions(assertionList ...AssertionConfig) TDFOption {
	return func(c *TDFConfig) error {
		c.assertions = append(c.assertions, assertionList...)
		return nil
	}
}

// WithAutoconfigure toggles inferring KAS info for encrypt from data attributes.
// This will use the Attributes service to look up key access grants.
// These are KAS URLs associated with attributes.
// Defaults to enabled.
func WithAutoconfigure(enable bool) TDFOption {
	return func(c *TDFConfig) error {
		c.autoconfigure = enable
		c.splitPlan = nil
		return nil
	}
}

// Deprecated: WithWrappingKeyAlg sets the key type for the TDF wrapping key for both storage and transit.
func WithWrappingKeyAlg(keyType ocrypto.KeyType) TDFOption {
	return func(c *TDFConfig) error {
		if keyType == "" {
			return errors.New("key type missing")
		}
		c.preferredKeyWrapAlg = keyType
		return nil
	}
}

// WithTargetMode sets the target schema mode for the TDF
func WithTargetMode(mode string) TDFOption {
	return func(c *TDFConfig) error {
		if mode != "" {
			lessThan, err := isLessThanSemver(mode, hexSemverThreshold)
			if err != nil {
				return fmt.Errorf("isLessThanSemver failed: %w", err)
			}
			c.useHex = lessThan
			c.excludeVersionFromManifest = lessThan
		} else {
			c.useHex = false
			c.excludeVersionFromManifest = false
		}
		return nil
	}
}

// Schema Validation where 0 = none (skip), 1 = lax (allowing novel entries, 'falsy' values for unkowns), 2 = strict (rejecting novel entries, strict match to manifest schema)
type SchemaValidationIntensity int

const (
	Skip SchemaValidationIntensity = iota
	Lax
	Strict
	unreasonable = 100
)

type TDFReaderOption func(*TDFReaderConfig) error

type TDFReaderConfig struct {
	verifiers                    AssertionVerificationKeys
	disableAssertionVerification bool

	schemaValidationIntensity SchemaValidationIntensity
	kasSessionKey             ocrypto.KeyPair
	kasAllowlist              AllowList // KAS URLs that are allowed to be used for reading TDFs
	ignoreAllowList           bool      // If true, the kasAllowlist will be ignored, and all KAS URLs will be allowed
	fulfillableObligationFQNs []string
	maxManifestSize           int64
}

type AllowList map[string]bool

func getKasAddress(kasURL string) (string, error) {
	// default to https if no scheme is provided
	if !strings.Contains(kasURL, schemeSeperator) {
		kasURL = schemeHTTPS + schemeSeperator + kasURL
	}
	parsedURL, err := url.Parse(kasURL)
	if err != nil {
		return "", fmt.Errorf("cannot parse kas url(%s): %w", kasURL, err)
	}
	if parsedURL.Hostname() == "" {
		return "", fmt.Errorf("no host parsed from url: %s", kasURL)
	}

	// Default to port 443 if scheme is https and no port is provided
	if parsedURL.Port() != "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), parsedURL.Port())
	} else if parsedURL.Scheme == schemeHTTPS {
		parsedURL.Host = net.JoinHostPort(parsedURL.Hostname(), "443")
	}

	// Reconstruct the URL with only the scheme, host, and port
	parsedURL.Path = ""
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	return parsedURL.String(), nil
}

func newAllowList(kasList []string) (AllowList, error) {
	allowList := make(AllowList, len(kasList))
	for _, kasURL := range kasList {
		err := allowList.Add(kasURL)
		if err != nil {
			return nil, fmt.Errorf("error adding kas url(%s) to allowlist: %w", kasURL, err)
		}
	}
	return allowList, nil
}

func (a AllowList) IsAllowed(kasURL string) bool {
	if a == nil {
		return false // No allowlist, so no URLs are allowed
	}
	kasAddress, err := getKasAddress(kasURL)
	if err != nil {
		return false // If we can't parse the URL, we can't allow it
	}
	_, ok := a[kasAddress]
	return ok
}

func (a AllowList) Add(kasURL string) error {
	if a == nil {
		a = make(AllowList)
	}
	kasAddress, err := getKasAddress(kasURL)
	if err != nil {
		// If we can't parse the URL, we can't add it to the allowlist
		return fmt.Errorf("error parsing kas url(%s): %w", kasURL, err)
	} else if kasAddress == "" {
		return fmt.Errorf("kas url(%s) not parsed", kasURL)
	}
	a[kasAddress] = true
	return nil
}

func newTDFReaderConfig(opt ...TDFReaderOption) (*TDFReaderConfig, error) {
	c := &TDFReaderConfig{
		disableAssertionVerification: false,
		maxManifestSize:              defaultMaxManifestSize,
	}

	for _, o := range opt {
		err := o(c)
		if err != nil {
			return nil, err
		}
	}

	if c.kasSessionKey == nil {
		// Default to RSA 2048
		err := WithSessionKeyType(ocrypto.RSA2048Key)(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func WithMaxManifestSize(size int64) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.maxManifestSize = size
		return nil
	}
}

func WithAssertionVerificationKeys(keys AssertionVerificationKeys) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.verifiers = keys
		return nil
	}
}

func WithSchemaValidation(intensity SchemaValidationIntensity) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.schemaValidationIntensity = intensity
		return nil
	}
}

func WithDisableAssertionVerification(disable bool) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.disableAssertionVerification = disable
		return nil
	}
}

func WithSessionKeyType(keyType ocrypto.KeyType) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		kasSessionKey, err := ocrypto.NewKeyPair(keyType)
		if err != nil {
			return fmt.Errorf("failed to create RSA key pair: %w", err)
		}
		c.kasSessionKey = kasSessionKey
		return nil
	}
}

func WithKasAllowlist(kasList []string) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		allowlist, err := newAllowList(kasList)
		if err != nil {
			return fmt.Errorf("failed to create kas allowlist: %w", err)
		}
		c.kasAllowlist = allowlist
		return nil
	}
}

func withKasAllowlist(kasList AllowList) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.kasAllowlist = kasList
		return nil
	}
}

func WithIgnoreAllowlist(ignore bool) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.ignoreAllowList = ignore
		return nil
	}
}

func WithTDFFulfillableObligationFQNs(fqns []string) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.fulfillableObligationFQNs = fqns
		return nil
	}
}

func withSessionKey(k ocrypto.KeyPair) TDFReaderOption {
	return func(c *TDFReaderConfig) error {
		c.kasSessionKey = k
		return nil
	}
}
