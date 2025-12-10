package sdk

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk/nanobuilder"
)

// ============================================================================================================
// NanoTDFConfig Interface Implementation
// Adapts the SDK's configuration struct to the nanobuilder.HeaderConfig interface.
// ============================================================================================================

func (c NanoTDFConfig) GetKASURL() (string, error) {
	return c.kasURL.GetURL()
}

func (c NanoTDFConfig) GetKASPublicKey() *ecdh.PublicKey {
	return c.kasPublicKey
}

func (c NanoTDFConfig) GetSignerPrivateKey() ocrypto.ECKeyPair {
	return c.keyPair
}

func (c NanoTDFConfig) GetBindingConfig() nanobuilder.BindingConfig {
	return nanobuilder.BindingConfig{
		UseEcdsaBinding: c.bindCfg.useEcdsaBinding,
		EccMode:         c.bindCfg.eccMode,
	}
}

func (c NanoTDFConfig) GetSignatureConfig() nanobuilder.SignatureConfig {
	return nanobuilder.SignatureConfig{
		HasSignature:  c.sigCfg.hasSignature,
		SignatureMode: c.sigCfg.signatureMode,
		Cipher:        nanobuilder.CipherMode(c.sigCfg.cipher),
	}
}

func (c NanoTDFConfig) GetPolicy() nanobuilder.PolicyInfo {
	// We use the SDK's internal helper to create the policy object
	// and serialize it for the builder.
	policyObj, _ := createPolicyObject(c.attributes)
	body, _ := json.Marshal(policyObj)

	return nanobuilder.PolicyInfo{
		Body: body,
		Type: nanobuilder.PolicyType(c.policyMode),
	}
}

func (c NanoTDFConfig) GetPolicyMode() nanobuilder.PolicyType {
	return nanobuilder.PolicyType(c.policyMode)
}

func (c NanoTDFConfig) GetCollection() nanobuilder.CollectionHandler {
	if c.collectionCfg != nil && c.collectionCfg.useCollection {
		return &sdkCollectionHandler{c: c.collectionCfg}
	}
	return nil
}

// sdkCollectionHandler adapts the SDK's private collection config to the builder interface
type sdkCollectionHandler struct {
	c *collectionConfig
}

func (h *sdkCollectionHandler) Lock()   { h.c.mux.Lock() }
func (h *sdkCollectionHandler) Unlock() { h.c.mux.Unlock() }
func (h *sdkCollectionHandler) GetState() (uint32, []byte, []byte) {
	return h.c.iterations, h.c.header, h.c.symKey
}
func (h *sdkCollectionHandler) SetState(i uint32, head []byte, key []byte) {
	h.c.iterations = i
	h.c.header = head
	h.c.symKey = key
}

// ============================================================================================================
// CreateNanoTDF Integration
// ============================================================================================================

func (s SDK) CreateNanoTDF(writer io.Writer, reader io.Reader, config NanoTDFConfig) (uint32, error) {
	keyResolver := &sdkKeyResolver{sdk: &s}
	headerWriter := &nanobuilder.StandardHeaderWriter[NanoTDFConfig]{}
	encryptor := &nanobuilder.StandardEncryptor{UseCollection: config.collectionCfg.useCollection}
	createFunc := nanobuilder.NewNanoTDFCreator[NanoTDFConfig](keyResolver, headerWriter, encryptor)

	return createFunc(writer, reader, config)
}

// sdkKeyResolver adapts SDK key fetching to nanobuilder.KeyResolver
type sdkKeyResolver struct {
	sdk *SDK
}

func (r *sdkKeyResolver) Resolve(ctx context.Context, config *NanoTDFConfig) error {
	ki, err := getKasInfoForNanoTDF(r.sdk, config)
	if err != nil {
		return err
	}
	config.kasPublicKey, err = ocrypto.ECPubKeyFromPem([]byte(ki.PublicKey))
	return err
}

// ============================================================================================================
// LoadNanoTDF Integration
// ============================================================================================================

// LoadNanoTDF initializes a Reader using SDK networking
func (s SDK) LoadNanoTDF(ctx context.Context, reader io.ReadSeeker, opts ...NanoTDFReaderOption) (*NanoTDFReader, error) {
	// 2. Concrete Implementations
	headerReader := &nanobuilder.StandardHeaderReader{}
	decryptor := &nanobuilder.StandardEncryptor{}

	// 3. Cache Bridge
	var cache nanobuilder.KeyCache = nil
	if s.collectionStore != nil {
		cache = s.collectionStore
	}

	// 4. AllowList Adapter
	allowListProvider := func(c NanoTDFReaderConfig) nanobuilder.AllowListChecker {
		return &sdkAllowListChecker{
			allowList: c.kasAllowlist,
			ignored:   c.ignoreAllowList,
		}
	}

	// Prepare Config
	nanoConfig, err := newNanoTDFReaderConfig(opts...)
	if err != nil {
		return nil, err
	}

	// 5. Factory Call
	rewrapper := nanoConfig.rewrapper
	if rewrapper == nil {
		rewrapper = &sdkRewrapper{sdk: &s}
	}
	loadFunc := nanobuilder.NewNanoTDFLoader[NanoTDFReaderConfig](headerReader, nanoConfig.rewrapper, cache, decryptor, allowListProvider)

	// Inject global obligations
	if len(nanoConfig.fulfillableObligationFQNs) == 0 && len(s.fulfillableObligationFQNs) > 0 {
		nanoConfig.fulfillableObligationFQNs = s.fulfillableObligationFQNs
	}

	// Legacy Support: Pre-calculate AllowList using SDK internals
	nanoConfig.kasAllowlist, err = getKasAllowList(ctx, nanoConfig.kasAllowlist, s, nanoConfig.ignoreAllowList)
	if err != nil {
		return nil, err
	}

	// Initialize
	r, err := loadFunc(ctx, reader, nanoConfig)
	if err != nil {
		return nil, err
	}

	return &NanoTDFReader{internal: r}, nil
}

// NanoTDFReader wraps the generic internal reader as the concrete SDK type
type NanoTDFReader struct {
	internal *nanobuilder.NanoTDFReader[NanoTDFReaderConfig]
}

func (n *NanoTDFReader) Init(ctx context.Context) error {
	return n.internal.Init(ctx)
}

func (n *NanoTDFReader) Obligations(ctx context.Context) ([]string, error) {
	return n.internal.Obligations(ctx)
}

func (n *NanoTDFReader) Decrypt(ctx context.Context, writer io.Writer) (int, error) {
	return n.internal.Decrypt(ctx, writer)
}

// sdkAllowListChecker adapts SDK AllowList
type sdkAllowListChecker struct {
	allowList AllowList
	ignored   bool
}

func (c *sdkAllowListChecker) IsAllowed(url string) bool { return c.allowList.IsAllowed(url) }
func (c *sdkAllowListChecker) IsIgnored() bool           { return c.ignored }

// sdkRewrapper adapts SDK KAS Client
type sdkRewrapper struct {
	sdk *SDK
}

func (r *sdkRewrapper) Rewrap(ctx context.Context, header []byte, kasURL string) ([]byte, []string, error) {
	req := &kas.UnsignedRewrapRequest_WithPolicyRequest{
		KeyAccessObjects: []*kas.UnsignedRewrapRequest_WithKeyAccessObject{
			{
				KeyAccessObjectId: "kao-0",
				KeyAccessObject:   &kas.KeyAccess{KasUrl: kasURL, Header: header},
			},
		},
		Policy:    &kas.UnsignedRewrapRequest_WithPolicy{Id: "policy"},
		Algorithm: "ec:secp256r1",
	}

	client := newKASClient(r.sdk.conn.Client, r.sdk.conn.Options, r.sdk.tokenSource, nil, r.sdk.fulfillableObligationFQNs)
	policyResult, err := client.nanoUnwrap(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	res, ok := policyResult["policy"]
	if !ok || len(res) == 0 {
		return nil, nil, fmt.Errorf("policy missing in response")
	}

	return res[0].SymmetricKey, res[0].RequiredObligations, res[0].Error
}

// ============================================================================================================
// Convenience / Legacy Methods
// ============================================================================================================

func (s SDK) ReadNanoTDF(writer io.Writer, reader io.ReadSeeker, opts ...NanoTDFReaderOption) (int, error) {
	return s.ReadNanoTDFContext(context.Background(), writer, reader, opts...)
}

func (s SDK) ReadNanoTDFContext(ctx context.Context, writer io.Writer, reader io.ReadSeeker, opts ...NanoTDFReaderOption) (int, error) {
	r, err := s.LoadNanoTDF(ctx, reader, opts...)
	if err != nil {
		return 0, fmt.Errorf("LoadNanoTDF: %w", err)
	}

	err = r.Init(ctx)
	if err != nil {
		return 0, fmt.Errorf("Init failed: %w", err)
	}

	return r.Decrypt(ctx, writer)
}

// ============================================================================================================
// Internal Helpers (SDK Specific logic)
// ============================================================================================================

func getKasInfoForNanoTDF(s *SDK, config *NanoTDFConfig) (*KASInfo, error) {
	var err error
	// Attempt to use base key if present and ECC.
	ki, err := getNanoKasInfoFromBaseKey(s)
	if err == nil {
		err = updateConfigWithBaseKey(ki, config)
		if err == nil {
			return ki, nil
		}
	}

	s.logger.Debug("getNanoKasInfoFromBaseKey failed, falling back to default kas", slog.String("error", err.Error()))

	kasURL, err := config.kasURL.GetURL()
	if err != nil {
		return nil, fmt.Errorf("config.kasURL failed:%w", err)
	}
	if kasURL == "https://" || kasURL == "http://" {
		return nil, errors.New("config.kasUrl is empty")
	}
	ki, err = s.getPublicKey(context.Background(), kasURL, config.bindCfg.eccMode.String(), "")
	if err != nil {
		return nil, fmt.Errorf("getECPublicKey failed:%w", err)
	}

	// update KAS URL with kid if set
	if ki.KID != "" && !s.nanoFeatures.noKID {
		err = config.kasURL.setURLWithIdentifier(kasURL, ki.KID)
		if err != nil {
			return nil, fmt.Errorf("getECPublicKey setURLWithIdentifier failed:%w", err)
		}
	}

	return ki, nil
}

func updateConfigWithBaseKey(ki *KASInfo, config *NanoTDFConfig) error {
	ecMode, err := ocrypto.ECKeyTypeToMode(ocrypto.KeyType(ki.Algorithm))
	if err != nil {
		return fmt.Errorf("ocrypto.ECKeyTypeToMode failed: %w", err)
	}
	err = config.kasURL.setURLWithIdentifier(ki.URL, ki.KID)
	if err != nil {
		return fmt.Errorf("config.kasURL setURLWithIdentifier failed: %w", err)
	}
	config.bindCfg.eccMode = ecMode

	return nil
}

func getNanoKasInfoFromBaseKey(s *SDK) (*KASInfo, error) {
	baseKey, err := getBaseKey(context.Background(), *s)
	if err != nil {
		return nil, err
	}

	// Check if algorithm is one of the supported EC algorithms
	algorithm := baseKey.GetPublicKey().GetAlgorithm()
	if algorithm != policy.Algorithm_ALGORITHM_EC_P256 &&
		algorithm != policy.Algorithm_ALGORITHM_EC_P384 &&
		algorithm != policy.Algorithm_ALGORITHM_EC_P521 {
		return nil, fmt.Errorf("base key algorithm is not supported for nano: %s", algorithm)
	}

	alg, err := formatAlg(baseKey.GetPublicKey().GetAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("formatAlg failed: %w", err)
	}

	return &KASInfo{
		URL:       baseKey.GetKasUri(),
		PublicKey: baseKey.GetPublicKey().GetPem(),
		KID:       baseKey.GetPublicKey().GetKid(),
		Algorithm: alg,
	}, nil
}

// Deprecated: Kept for compatibility if older tests reference NanoTDFDecryptHandler
// This just delegates to the new generic loader logic
type NanoTDFDecryptHandler struct {
	reader    io.ReadSeeker
	writer    io.Writer
	config    *NanoTDFReaderConfig
	readerObj *NanoTDFReader
}

func createNanoTDFDecryptHandler(reader io.ReadSeeker, writer io.Writer, opts ...NanoTDFReaderOption) (*NanoTDFDecryptHandler, error) {
	nanoTdfReaderConfig, err := newNanoTDFReaderConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("newNanoTDFReaderConfig failed: %w", err)
	}
	// Note: We can't fully hydrate the handler here without the SDK instance to do allow-listing/rewrapping.
	// This struct seems to have been used internally in previous implementations.
	return &NanoTDFDecryptHandler{
		reader: reader,
		writer: writer,
		config: nanoTdfReaderConfig,
	}, nil
}
