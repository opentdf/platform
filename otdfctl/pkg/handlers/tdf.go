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

	"connectrpc.com/connect"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/otdfctl/pkg/tdf"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/sdk"
	experimentaltdf "github.com/opentdf/platform/sdk/experimental/tdf"
	"google.golang.org/protobuf/proto"
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
	encryptSegmentSize    = 2 * 1024 * 1024        // 2MB
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

// Encrypt streams plaintext from in into a TDF written to out. Memory use is
// bounded by one plaintext segment and the manifest, rather than payload size.
func (h Handler) Encrypt(ctx context.Context, out io.Writer, in io.Reader, o EncryptOptions) error {
	switch o.TDFType {
	// Encrypt the data as a ZTDF
	case "", tdf.TypeTDF3, tdf.TypeZTDF:
		attributeValues, err := h.resolveTDFAttributeValues(ctx, o.Attributes, o.WrappingKeyAlgorithm)
		if err != nil {
			return err
		}

		var defaultKAS *policy.SimpleKasKey
		if attributesNeedDefaultKAS(attributeValues) {
			defaultKAS, err = h.resolveDefaultKAS(ctx, o.KASURLPath)
			if err != nil {
				return err
			}
			for _, value := range attributeValues {
				if !hasUsableKAS(value) {
					value.KasKeys = append(value.KasKeys, defaultKAS)
				}
			}
		}

		assertionConfigs, err := parseExperimentalAssertions(o.Assertions)
		if err != nil {
			return err
		}

		writer, err := experimentaltdf.NewWriter(ctx,
			experimentaltdf.WithIntegrityAlgorithm(experimentaltdf.HS256),
			experimentaltdf.WithSegmentIntegrityAlgorithm(experimentaltdf.GMAC),
			experimentaltdf.WithTargetMode(o.TargetMode),
		)
		if err != nil {
			return err
		}

		if err := writeTDFSegments(ctx, writer, out, in); err != nil {
			return err
		}

		finalizeOptions := []experimentaltdf.Option[*experimentaltdf.WriterFinalizeConfig]{
			experimentaltdf.WithAttributeValues(attributeValues),
		}
		if o.MimeType != "" {
			finalizeOptions = append(finalizeOptions, experimentaltdf.WithPayloadMimeType(o.MimeType))
		}
		if defaultKAS != nil {
			finalizeOptions = append(finalizeOptions, experimentaltdf.WithDefaultKAS(defaultKAS))
		}
		if len(assertionConfigs) > 0 {
			finalizeOptions = append(finalizeOptions, experimentaltdf.WithAssertions(assertionConfigs...))
		}

		finalized, err := writer.Finalize(ctx, finalizeOptions...)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, bytes.NewReader(finalized.Data)); err != nil {
			return fmt.Errorf("writing finalized TDF: %w", err)
		}
		return nil
	default:
		return errors.New("unknown TDF type")
	}
}

func writeTDFSegments(ctx context.Context, writer *experimentaltdf.Writer, out io.Writer, in io.Reader) error {
	buffer := make([]byte, encryptSegmentSize)
	segmentIndex := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, readErr := io.ReadFull(in, buffer)
		if errors.Is(readErr, io.EOF) && segmentIndex > 0 {
			break
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return fmt.Errorf("reading plaintext segment: %w", readErr)
		}

		segment, err := writer.WriteSegment(ctx, segmentIndex, buffer[:n])
		if err != nil {
			return fmt.Errorf("encrypting segment %d: %w", segmentIndex, err)
		}
		if _, err := io.Copy(out, segment.TDFData); err != nil {
			return fmt.Errorf("writing encrypted segment %d: %w", segmentIndex, err)
		}
		segmentIndex++

		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
	}
	return nil
}

func (h Handler) resolveDefaultKAS(ctx context.Context, kasURLPath string) (*policy.SimpleKasKey, error) {
	kas, err := h.sdk.GetBaseKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolving default KAS: %w", err)
	}
	if kas == nil || kas.GetPublicKey() == nil {
		return nil, errors.New("resolving default KAS: base key is empty")
	}
	if kasURLPath != "" {
		clonedKAS, ok := proto.Clone(kas).(*policy.SimpleKasKey)
		if !ok {
			return nil, errors.New("resolving default KAS: invalid base key type")
		}
		kas = clonedKAS
		kas.KasUri = h.platformEndpoint + kasURLPath
	}
	return kas, nil
}

func (h Handler) resolveTDFAttributeValues(ctx context.Context, fqns []string, wrappingKeyAlgorithm ocrypto.KeyType) ([]*policy.Value, error) {
	if len(fqns) == 0 {
		return nil, nil
	}

	for _, fqn := range fqns {
		if _, err := sdk.NewAttributeValueFQN(fqn); err != nil {
			return nil, err
		}
	}

	resolved := make(map[string]*policy.Value, len(fqns))
	fallback := append([]string(nil), fqns...)
	mappings, err := h.sdk.Attributes.GetKeyMappingsByFqns(ctx, &attributes.GetKeyMappingsByFqnsRequest{Fqns: fqns})
	if err == nil {
		fallback = fallback[:0]
		for _, requestedFQN := range fqns {
			mapping := mappings.GetFqnKeyMappings()[strings.ToLower(requestedFQN)]
			if mapping == nil {
				mapping = mappings.GetFqnKeyMappings()[requestedFQN]
			}
			keys := selectKASKeys(mapping.GetKeys(), wrappingKeyAlgorithm)
			if len(keys) == 0 {
				fallback = append(fallback, requestedFQN)
				continue
			}
			valueFQN, _ := sdk.NewAttributeValueFQN(requestedFQN)
			resolved[strings.ToLower(requestedFQN)] = &policy.Value{
				Fqn:     requestedFQN,
				KasKeys: keys,
				Attribute: &policy.Attribute{
					Fqn:  valueFQN.Prefix().String(),
					Rule: mapping.GetRule(),
				},
			}
		}
	} else if connect.CodeOf(err) != connect.CodeUnimplemented {
		return nil, fmt.Errorf("resolving attribute KAS mappings: %w", err)
	}

	if err := h.resolveFallbackAttributeValues(ctx, fallback, wrappingKeyAlgorithm, resolved); err != nil {
		return nil, err
	}

	values := make([]*policy.Value, 0, len(fqns))
	for _, fqn := range fqns {
		value := resolved[strings.ToLower(fqn)]
		if value == nil {
			return nil, fmt.Errorf("attribute value not found: %s", fqn)
		}
		values = append(values, value)
	}
	return values, nil
}

func (h Handler) resolveFallbackAttributeValues(
	ctx context.Context,
	fqns []string,
	wrappingKeyAlgorithm ocrypto.KeyType,
	resolved map[string]*policy.Value,
) error {
	if len(fqns) == 0 {
		return nil
	}
	response, err := h.sdk.Attributes.GetAttributeValuesByFqns(ctx, &attributes.GetAttributeValuesByFqnsRequest{Fqns: fqns})
	if err != nil {
		return fmt.Errorf("resolving attribute values: %w", err)
	}
	for _, requestedFQN := range fqns {
		pair := response.GetFqnAttributeValues()[requestedFQN]
		if pair == nil {
			pair = response.GetFqnAttributeValues()[strings.ToLower(requestedFQN)]
		}
		if pair == nil || pair.GetAttribute() == nil {
			return fmt.Errorf("attribute value not found: %s", requestedFQN)
		}

		value := &policy.Value{Fqn: requestedFQN}
		if pair.GetValue() != nil {
			clonedValue, ok := proto.Clone(pair.GetValue()).(*policy.Value)
			if !ok {
				return fmt.Errorf("invalid attribute value type: %s", requestedFQN)
			}
			value = clonedValue
		}
		clonedAttribute, ok := proto.Clone(pair.GetAttribute()).(*policy.Attribute)
		if !ok {
			return fmt.Errorf("invalid attribute type: %s", requestedFQN)
		}
		value.Fqn = requestedFQN
		value.Attribute = clonedAttribute
		filterAttributeKASKeys(value, wrappingKeyAlgorithm)
		resolved[strings.ToLower(requestedFQN)] = value
	}
	return nil
}

func selectKASKeys(keys []*policy.SimpleKasKey, algorithm ocrypto.KeyType) []*policy.SimpleKasKey {
	if algorithm == "" {
		return keys
	}
	policyAlgorithm, err := sdk.KeyTypeToPolicyAlgorithm(algorithm)
	if err != nil {
		return nil
	}
	selected := make([]*policy.SimpleKasKey, 0, len(keys))
	for _, key := range keys {
		if key.GetPublicKey().GetAlgorithm() == policyAlgorithm {
			selected = append(selected, key)
		}
	}
	return selected
}

func filterAttributeKASKeys(value *policy.Value, algorithm ocrypto.KeyType) {
	value.KasKeys = selectKASKeys(value.GetKasKeys(), algorithm)
	attribute := value.GetAttribute()
	if attribute == nil {
		return
	}
	attribute.KasKeys = selectKASKeys(attribute.GetKasKeys(), algorithm)
	if namespace := attribute.GetNamespace(); namespace != nil {
		namespace.KasKeys = selectKASKeys(namespace.GetKasKeys(), algorithm)
	}
}

func attributesNeedDefaultKAS(values []*policy.Value) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if !hasUsableKAS(value) {
			return true
		}
	}
	return false
}

func hasUsableKAS(value *policy.Value) bool {
	if value == nil {
		return false
	}
	if hasUsableSimpleKAS(value.GetKasKeys()) || hasUsableGrantKAS(value.GetGrants()) {
		return true
	}
	attribute := value.GetAttribute()
	if attribute == nil {
		return false
	}
	if hasUsableSimpleKAS(attribute.GetKasKeys()) || hasUsableGrantKAS(attribute.GetGrants()) {
		return true
	}
	namespace := attribute.GetNamespace()
	return namespace != nil && (hasUsableSimpleKAS(namespace.GetKasKeys()) || hasUsableGrantKAS(namespace.GetGrants()))
}

func hasUsableSimpleKAS(keys []*policy.SimpleKasKey) bool {
	for _, key := range keys {
		publicKey := key.GetPublicKey()
		if key.GetKasUri() != "" && publicKey.GetKid() != "" && publicKey.GetPem() != "" {
			return true
		}
	}
	return false
}

func hasUsableGrantKAS(grants []*policy.KeyAccessServer) bool {
	for _, grant := range grants {
		if grant.GetUri() == "" {
			continue
		}
		if hasUsableSimpleKAS(grant.GetKasKeys()) {
			return true
		}
		for _, key := range grant.GetPublicKey().GetCached().GetKeys() {
			if key.GetKid() != "" && key.GetPem() != "" {
				return true
			}
		}
	}
	return false
}

func parseExperimentalAssertions(assertionsJSON string) ([]experimentaltdf.AssertionConfig, error) {
	if assertionsJSON == "" {
		return nil, nil
	}

	assertionBytes := []byte(assertionsJSON)
	var assertionConfigs []experimentaltdf.AssertionConfig
	if err := json.Unmarshal(assertionBytes, &assertionConfigs); err != nil {
		var readErr error
		assertionBytes, readErr = utils.ReadBytesFromFile(assertionsJSON, MaxAssertionsFileSize)
		if readErr != nil {
			return nil, fmt.Errorf("unable to read assertions file: %w", readErr)
		}
		if err := json.Unmarshal(assertionBytes, &assertionConfigs); err != nil {
			return nil, fmt.Errorf("unable to unmarshal assertions json: %w", err)
		}
	}

	for i, config := range assertionConfigs {
		if config.SigningKey.IsEmpty() {
			continue
		}
		correctedKey, err := correctKeyType(sdk.AssertionKey{
			Alg: sdk.AssertionKeyAlg(config.SigningKey.Alg),
			Key: config.SigningKey.Key,
		}, false)
		if err != nil {
			return nil, fmt.Errorf("error with assertion signing key: %w", err)
		}
		assertionConfigs[i].SigningKey.Key = correctedKey
	}
	return assertionConfigs, nil
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
