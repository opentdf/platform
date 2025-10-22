package sdk

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/Masterminds/semver/v3"
	"github.com/google/uuid"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/kas"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/archive"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"google.golang.org/grpc/codes"
)

const (
	keyAccessSchemaVersion = "1.0"
	maxFileSizeSupported   = 68719476736 // 64gb
	defaultMimeType        = "application/octet-stream"
	tdfAsZip               = "zip"
	gcmIvSize              = 12
	aesBlockSize           = 16
	hmacIntegrityAlgorithm = "HS256"
	gmacIntegrityAlgorithm = "GMAC"
	tdfZipReference        = "reference"
	manifestFileName       = "0.manifest.json"
	kKeySize               = 32
	kWrapped               = "wrapped"
	kECWrapped             = "ec-wrapped"
	kKasProtocol           = "kas"
	kSplitKeyType          = "split"
	kGCMCipherAlgorithm    = "AES-256-GCM"
	kGMACPayloadLength     = 16
	kAssertionSignature    = "assertionSig"
	kAssertionHash         = "assertionHash"
	hexSemverThreshold     = "4.3.0"
	readActionName         = "read"
)

// Loads and reads ZTDF files
type Reader struct {
	tokenSource         auth.AccessTokenSource
	httpClient          *http.Client
	connectOptions      []connect.ClientOption
	manifest            Manifest
	unencryptedMetadata []byte
	tdfReader           archive.TDFReader
	cursor              int64
	aesGcm              ocrypto.AesGcm
	payloadSize         int64
	payloadKey          []byte
	kasSessionKey       ocrypto.KeyPair
	config              TDFReaderConfig
	requiredObligations *RequiredObligations
}

type RequiredObligations struct {
	FQNs []string
}

type TDFObject struct {
	manifest   Manifest
	size       int64
	aesGcm     ocrypto.AesGcm
	payloadKey [kKeySize]byte
}

type tdf3DecryptHandler struct {
	writer io.Writer
	reader *Reader
}

type ecKeyWrappedKeyInfo struct {
	publicKey  string
	wrappedKey string
}

func (r *tdf3DecryptHandler) Decrypt(ctx context.Context, results []kaoResult) (int, error) {
	err := r.reader.buildKey(ctx, results)
	if err != nil {
		return 0, err
	}
	data, err := io.ReadAll(r.reader)
	if err != nil {
		return 0, err
	}

	n, err := r.writer.Write(data)
	return n, err
}

func (r *tdf3DecryptHandler) CreateRewrapRequest(ctx context.Context) (map[string]*kas.UnsignedRewrapRequest_WithPolicyRequest, error) {
	return createRewrapRequest(ctx, r.reader)
}

func (s SDK) createTDF3DecryptHandler(writer io.Writer, reader io.ReadSeeker, opts ...TDFReaderOption) (*tdf3DecryptHandler, error) {
	tdfReader, err := s.LoadTDF(reader, opts...)
	if err != nil {
		return nil, err
	}

	return &tdf3DecryptHandler{
		reader: tdfReader,
		writer: writer,
	}, nil
}

func (t TDFObject) Size() int64 {
	return t.size
}

// AppendAssertion adds a new assertion to the TDF object after creation.
// This method handles the cryptographic binding of the assertion to the TDF's payload.
// The assertion will be signed using the provided signing builder.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - assertionConfig: Configuration for the new assertion to add
//   - signingProvider: Provider to handle the cryptographic signing of the assertion
//
// Returns:
//   - error: Any error that occurred during the append operation
//
// Note: This method modifies the TDF's manifest in place. The assertion will be
// cryptographically bound to the TDF's payload using the aggregate hash.
func (t *TDFObject) AppendAssertion(_ context.Context, assertionConfig AssertionConfig, key AssertionKey) error {
	// Configure the assertion from config
	assertion := Assertion{
		ID:             assertionConfig.ID,
		Type:           assertionConfig.Type,
		Scope:          assertionConfig.Scope,
		AppliesToState: assertionConfig.AppliesToState,
		Statement:      assertionConfig.Statement,
	}

	// Get the hash of the assertion
	assertionHashBytes, err := assertion.GetHash()
	if err != nil {
		return fmt.Errorf("failed to get assertion hash: %w", err)
	}
	assertionHash := string(assertionHashBytes)

	// Cryptographic Binding Strategy:
	// The assertion is bound to the TDF payload using the manifest's root signature.
	// This creates a chain of integrity: payload -> segments -> aggregate hash -> root signature -> assertion
	//
	// The rootSignature is the signed and base64-encoded aggregate hash of all payload segments.
	// By including it in the assertion signature, we cryptographically bind the assertion to the
	// specific payload content. Any modification to the payload will change the root signature,
	// which will cause assertion verification to fail.
	//
	// This approach ensures:
	// 1. Assertions cannot be moved between different TDFs (payload binding)
	// 2. Assertions cannot be added/removed without detection (integrity)
	// 3. The assertion applies to the exact payload state at assertion creation time
	rootSignature := t.manifest.RootSignature.Signature

	// Sign the assertion using the provided signing builder
	if err := assertion.Sign(assertionHash, rootSignature, key); err != nil {
		return fmt.Errorf("failed to sign assertion: %w", err)
	}

	// Add the signed assertion to the manifest
	t.manifest.Assertions = append(t.manifest.Assertions, assertion)

	return nil
}

func (s SDK) CreateTDF(writer io.Writer, reader io.ReadSeeker, opts ...TDFOption) (*TDFObject, error) {
	return s.CreateTDFContext(context.Background(), writer, reader, opts...)
}

func (s SDK) defaultKases(c *TDFConfig) []string {
	allk := make([]string, 0, len(c.kasInfoList))
	defk := make([]string, 0)
	for _, k := range c.kasInfoList {
		if k.Default {
			defk = append(defk, k.URL)
		} else if len(defk) == 0 {
			allk = append(allk, k.URL)
		}
	}
	if len(defk) == 0 {
		return allk
	}
	return defk
}

func uuidSplitIDGenerator() string {
	return uuid.New().String()
}

// CreateTDFContext reads plain text from the given reader and saves it to the writer, subject to the given options
func (s SDK) CreateTDFContext(ctx context.Context, writer io.Writer, reader io.ReadSeeker, opts ...TDFOption) (*TDFObject, error) { //nolint:funlen, gocognit, lll // Better readability keeping it as is
	inputSize, err := reader.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	if inputSize > maxFileSizeSupported {
		return nil, errFileTooLarge
	}

	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	tdfConfig, err := newTDFConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("NewTDFConfig failed: %w", err)
	}

	err = tdfConfig.initKAOTemplate(ctx, s)
	if err != nil {
		return nil, err
	}

	tdfObject := &TDFObject{}
	err = s.prepareManifest(ctx, tdfObject, *tdfConfig)
	if err != nil {
		return nil, fmt.Errorf("fail to create a new split key: %w", err)
	}

	segmentSize := tdfConfig.defaultSegmentSize
	if segmentSize > maxSegmentSize {
		return nil, fmt.Errorf("segment size too large: %d", segmentSize)
	} else if segmentSize < minSegmentSize {
		return nil, fmt.Errorf("segment size too small: %d", segmentSize)
	}
	totalSegments := inputSize / segmentSize
	if inputSize%segmentSize != 0 {
		totalSegments++
	}

	// empty payload we still want to create a payload
	if totalSegments == 0 {
		totalSegments = 1
	}

	encryptedSegmentSize := segmentSize + gcmIvSize + aesBlockSize
	payloadSize := inputSize + (totalSegments * (gcmIvSize + aesBlockSize))
	tdfWriter := archive.NewTDFWriter(writer)

	err = tdfWriter.SetPayloadSize(payloadSize)
	if err != nil {
		return nil, fmt.Errorf("archive.SetPayloadSize failed: %w", err)
	}

	var readPos int64
	var aggregateHash string
	readBuf := bytes.NewBuffer(make([]byte, 0, tdfConfig.defaultSegmentSize))
	for totalSegments != 0 { // adjust read size
		readSize := segmentSize
		if (inputSize - readPos) < segmentSize {
			readSize = inputSize - readPos
		}

		n, err := reader.Read(readBuf.Bytes()[:readSize])
		if err != nil {
			return nil, fmt.Errorf("io.ReadSeeker.Read failed: %w", err)
		}

		if int64(n) != readSize {
			return nil, errors.New("io.ReadSeeker.Read size mismatch")
		}

		cipherData, err := tdfObject.aesGcm.Encrypt(readBuf.Bytes()[:readSize])
		if err != nil {
			return nil, fmt.Errorf("io.ReadSeeker.Read failed: %w", err)
		}

		err = tdfWriter.AppendPayload(cipherData)
		if err != nil {
			return nil, fmt.Errorf("io.writer.Write failed: %w", err)
		}

		segmentSig, err := calculateSignature(cipherData, tdfObject.payloadKey[:],
			tdfConfig.segmentIntegrityAlgorithm, tdfConfig.useHex)
		if err != nil {
			return nil, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
		}

		aggregateHash += segmentSig
		segmentInfo := Segment{
			Hash:          string(ocrypto.Base64Encode([]byte(segmentSig))),
			Size:          readSize,
			EncryptedSize: int64(len(cipherData)),
		}

		tdfObject.manifest.EncryptionInformation.IntegrityInformation.Segments = append(tdfObject.manifest.EncryptionInformation.IntegrityInformation.Segments, segmentInfo)

		totalSegments--
		readPos += readSize
	}

	rootSignature, err := calculateSignature([]byte(aggregateHash), tdfObject.payloadKey[:],
		tdfConfig.integrityAlgorithm, tdfConfig.useHex)
	if err != nil {
		return nil, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
	}

	sig := string(ocrypto.Base64Encode([]byte(rootSignature)))
	tdfObject.manifest.EncryptionInformation.IntegrityInformation.RootSignature.Signature = sig

	integrityAlgStr := gmacIntegrityAlgorithm
	if tdfConfig.integrityAlgorithm == HS256 {
		integrityAlgStr = hmacIntegrityAlgorithm
	}
	tdfObject.manifest.EncryptionInformation.IntegrityInformation.RootSignature.Algorithm = integrityAlgStr

	tdfObject.manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize = segmentSize
	tdfObject.manifest.EncryptionInformation.IntegrityInformation.DefaultEncryptedSegSize = encryptedSegmentSize

	segIntegrityAlgStr := gmacIntegrityAlgorithm
	if tdfConfig.segmentIntegrityAlgorithm == HS256 {
		segIntegrityAlgStr = hmacIntegrityAlgorithm
	}

	tdfObject.manifest.EncryptionInformation.IntegrityInformation.SegmentHashAlgorithm = segIntegrityAlgStr
	tdfObject.manifest.EncryptionInformation.Method.IsStreamable = true

	// add payload info
	mimeType := tdfConfig.mimeType
	if mimeType == "" {
		mimeType = defaultMimeType
	}
	tdfObject.manifest.Payload.MimeType = mimeType
	tdfObject.manifest.Payload.Protocol = tdfAsZip
	tdfObject.manifest.Payload.Type = tdfZipReference
	tdfObject.manifest.Payload.URL = archive.TDFPayloadFileName
	tdfObject.manifest.Payload.IsEncrypted = true

	// if addSystemMetadataAssertion is true, register a system metadata assertion binder
	if tdfConfig.addSystemMetadataAssertion {
		systemMetadataAssertionProvider := NewSystemMetadataAssertionProvider(tdfConfig.useHex, tdfObject.payloadKey[:], aggregateHash)
		tdfConfig.assertionRegistry.RegisterBinder(systemMetadataAssertionProvider)
	}

	var boundAssertions []Assertion
	// Bind Assertions
	for _, registered := range tdfConfig.assertionRegistry.binders {
		boundAssertion, er := registered.Bind(ctx, tdfObject.manifest)
		if er != nil {
			return nil, fmt.Errorf("failed to bind assertion: %w", er)
		}
		boundAssertions = append(boundAssertions, boundAssertion)
	}

	// Sign any unsigned assertions with the DEK (payload key)
	// All assertions MUST have cryptographic bindings for security
	dekKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: tdfObject.payloadKey[:],
	}
	for i := range boundAssertions {
		if boundAssertions[i].Binding.IsEmpty() {
			// Get the hash of the assertion
			assertionHashBytes, err := boundAssertions[i].GetHash()
			if err != nil {
				return nil, fmt.Errorf("failed to get assertion hash: %w", err)
			}
			assertionHash := string(assertionHashBytes)

			// Sign with DEK
			if err := boundAssertions[i].Sign(assertionHash, tdfObject.manifest.RootSignature.Signature, dekKey); err != nil {
				return nil, fmt.Errorf("failed to sign assertion %q with DEK: %w", boundAssertions[i].ID, err)
			}
		}
	}

	tdfObject.manifest.Assertions = boundAssertions

	manifestAsStr, err := json.Marshal(tdfObject.manifest)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed:%w", err)
	}

	err = tdfWriter.AppendManifest(string(manifestAsStr))
	if err != nil {
		return nil, fmt.Errorf("TDFWriter.AppendManifest failed:%w", err)
	}

	tdfObject.size, err = tdfWriter.Finish()
	if err != nil {
		return nil, fmt.Errorf("TDFWriter.Finish failed:%w", err)
	}

	return tdfObject, nil
}

// initKAOTemplate initializes the KAO template, from either the split plan, kaoTemplate, or autoconfigure based on tags.
func (tdfConfig *TDFConfig) initKAOTemplate(ctx context.Context, s SDK) error {
	// At most one of the following should be true:
	// - autoconfigure is true
	// - splitPlan is set
	// - kaoTemplate is set
	if len(tdfConfig.splitPlan) > 0 && len(tdfConfig.kaoTemplate) > 0 {
		return errors.New("cannot set both splitPlan and kaoTemplate")
	}
	if tdfConfig.autoconfigure && (len(tdfConfig.splitPlan) > 0 || len(tdfConfig.kaoTemplate) > 0) {
		return errors.New("cannot set autoconfigure and splitPlan or kaoTemplate")
	}

	// * Get base key before autoconfigure to condition off of.
	if tdfConfig.autoconfigure {
		g, err := s.newGranter(ctx, tdfConfig)
		if err != nil {
			return err
		}

		switch g.typ {
		case mappedFound:
			tdfConfig.kaoTemplate, err = g.resolveTemplate(ctx, string(tdfConfig.preferredKeyWrapAlg), uuidSplitIDGenerator)
		case grantsFound:
			tdfConfig.kaoTemplate = nil
			tdfConfig.splitPlan, err = g.plan(make([]string, 0), uuidSplitIDGenerator)
		case noKeysFound:
			var baseKey *policy.SimpleKasKey
			baseKey, err = getBaseKeyFromWellKnown(ctx, s)
			if err == nil {
				err = populateKasInfoFromBaseKey(baseKey, tdfConfig)
			} else {
				s.Logger().Debug("cannot getting base key, falling back to default kas", slog.Any("error", err))
				dk := s.defaultKases(tdfConfig)
				tdfConfig.kaoTemplate = nil
				tdfConfig.splitPlan, err = g.plan(dk, uuidSplitIDGenerator)
			}
		}
		if err != nil {
			return fmt.Errorf("failed generate plan: %w", err)
		}
	}

	switch {
	case len(tdfConfig.kaoTemplate) > 0:
		// use the kao template to create the key access objects
		// This is the preferred behavior; the following options upgrade deprecated behaviors
	case len(tdfConfig.splitPlan) > 0:
		// Seed anything passed in manually
		latestKASInfo := make(map[string]KASInfo)
		for _, kasInfo := range tdfConfig.kasInfoList {
			if kasInfo.PublicKey != "" {
				latestKASInfo[kasInfo.URL] = kasInfo
			}
		}
		// upgrade split plan to kao template
		tdfConfig.kaoTemplate = make([]kaoTpl, len(tdfConfig.splitPlan))
		for i, splitInfo := range tdfConfig.splitPlan {
			kasInfo, ok := latestKASInfo[splitInfo.KAS]
			if !ok {
				k, err := s.getPublicKey(ctx, splitInfo.KAS, string(tdfConfig.preferredKeyWrapAlg), "")
				if err != nil {
					return fmt.Errorf("unable to retrieve public key from KAS at [%s]: %w", splitInfo.KAS, err)
				}
				kasInfo = *k
			}
			if kasInfo.PublicKey == "" {
				return fmt.Errorf("empty KAS key found for splitID:[%s], kas:[%s]: %w", splitInfo.SplitID, splitInfo.KAS, errKasPubKeyMissing)
			}
			tdfConfig.kaoTemplate[i] = kaoTpl{
				splitInfo.KAS,
				splitInfo.SplitID,
				kasInfo.KID,
				kasInfo.PublicKey,
				ocrypto.KeyType(kasInfo.Algorithm),
			}
		}
		tdfConfig.splitPlan = nil // clear split plan as we are using kaoTemplate now
	case len(tdfConfig.kasInfoList) > 0:
		// Default to split based on kasInfoList
		// To remove. This has been deprecated for some time.
		tdfConfig.kaoTemplate = createKaoTemplateFromKasInfo(tdfConfig.kasInfoList)
	}

	return nil
}

func (s SDK) newGranter(ctx context.Context, tdfConfig *TDFConfig) (granter, error) {
	var g granter
	var err error
	if len(tdfConfig.attributeValues) > 0 {
		g, err = newGranterFromAttributes(s.logger, s.kasKeyCache, tdfConfig.attributeValues...)
	} else if len(tdfConfig.attributes) > 0 {
		g, err = newGranterFromService(ctx, s.logger, s.kasKeyCache, s.Attributes, tdfConfig.attributes...)
	}
	if err != nil {
		return g, err
	}
	g.keyInfoFetcher = s
	return g, nil
}

func (t *TDFObject) Manifest() Manifest {
	return t.manifest
}

func (r *Reader) Manifest() Manifest {
	return r.manifest
}

// prepare the manifest for TDF
func (s SDK) prepareManifest(ctx context.Context, t *TDFObject, tdfConfig TDFConfig) error { //nolint:funlen,gocognit // Better readability keeping it as is
	manifest := Manifest{}

	if !tdfConfig.excludeVersionFromManifest {
		manifest.TDFVersion = TDFSpecVersion
	}

	if len(tdfConfig.kaoTemplate) == 0 {
		return fmt.Errorf("no key access template specified or inferred in initKAOTemplate: %w", errInvalidKasInfo)
	}

	manifest.EncryptionInformation.KeyAccessType = kSplitKeyType

	policyObj, err := createPolicyObject(tdfConfig.attributes)
	if err != nil {
		return fmt.Errorf("fail to create policy object:%w", err)
	}

	policyObjectAsStr, err := json.Marshal(policyObj)
	if err != nil {
		return fmt.Errorf("json.Marshal failed:%w", err)
	}

	base64PolicyObject := ocrypto.Base64Encode(policyObjectAsStr)

	conjunction := make(map[string][]KASInfo)
	var splitIDs []string

	for _, tpl := range tdfConfig.kaoTemplate {
		// Public key was passed in with kasInfoList
		ki := KASInfo{
			URL:       tpl.KAS,
			KID:       tpl.kid,
			PublicKey: tpl.pem,
			Algorithm: string(tpl.algorithm),
		}
		if ki.PublicKey == "" {
			a := ki.Algorithm
			if a == "" {
				a = string(tdfConfig.preferredKeyWrapAlg)
			}
			k, err := s.getPublicKey(ctx, tpl.KAS, a, tpl.kid)
			if err != nil {
				return fmt.Errorf("unable to retrieve public key from KAS at [%s]: %w", tpl.KAS, err)
			}
			ki = *k
		}
		if _, ok := conjunction[tpl.SplitID]; ok {
			conjunction[tpl.SplitID] = append(conjunction[tpl.SplitID], ki)
		} else {
			conjunction[tpl.SplitID] = []KASInfo{ki}
			splitIDs = append(splitIDs, tpl.SplitID)
		}
	}

	symKeys := make([][]byte, 0, len(splitIDs))
	for _, splitID := range splitIDs {
		symKey, err := ocrypto.RandomBytes(kKeySize)
		if err != nil {
			return fmt.Errorf("ocrypto.RandomBytes failed:%w", err)
		}
		symKeys = append(symKeys, symKey)

		// policy binding
		policyBindingHash := hex.EncodeToString(ocrypto.CalculateSHA256Hmac(symKey, base64PolicyObject))
		pbstring := string(ocrypto.Base64Encode([]byte(policyBindingHash)))
		policyBinding := PolicyBinding{
			Alg:  "HS256",
			Hash: pbstring,
		}

		// encrypted metadata
		// add meta data
		var encryptedMetadata string
		if len(tdfConfig.metaData) > 0 {
			encryptedMetadata, err = encryptMetadata(symKey, tdfConfig.metaData)
			if err != nil {
				return err
			}
		}

		for _, kasInfo := range conjunction[splitID] {
			if len(kasInfo.PublicKey) == 0 {
				return fmt.Errorf("splitID:[%s], kas:[%s]: %w", splitID, kasInfo.URL, errKasPubKeyMissing)
			}

			keyAccess, err := createKeyAccess(kasInfo, symKey, policyBinding, encryptedMetadata, splitID)
			if err != nil {
				return err
			}

			manifest.EncryptionInformation.KeyAccessObjs = append(manifest.EncryptionInformation.KeyAccessObjs, keyAccess)
		}
	}

	manifest.EncryptionInformation.Policy = string(base64PolicyObject)
	manifest.EncryptionInformation.Method.Algorithm = kGCMCipherAlgorithm

	// create the payload key by XOR all the keys in key access object.
	for _, symKey := range symKeys {
		for keyByteIndex, keyByte := range symKey {
			t.payloadKey[keyByteIndex] ^= keyByte
		}
	}

	gcm, err := ocrypto.NewAESGcm(t.payloadKey[:])
	if err != nil {
		return fmt.Errorf(" ocrypto.NewAESGcm failed:%w", err)
	}

	t.manifest = manifest
	t.aesGcm = gcm
	return nil
}

func encryptMetadata(symKey []byte, metaData string) (string, error) {
	gcm, err := ocrypto.NewAESGcm(symKey)
	if err != nil {
		return "", fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	emb, err := gcm.Encrypt([]byte(metaData))
	if err != nil {
		return "", fmt.Errorf("ocrypto.AesGcm.encrypt failed:%w", err)
	}

	iv := emb[:ocrypto.GcmStandardNonceSize]
	metadata := EncryptedMetadata{
		Cipher: string(ocrypto.Base64Encode(emb)),
		Iv:     string(ocrypto.Base64Encode(iv)),
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf(" json.Marshal failed:%w", err)
	}
	return string(ocrypto.Base64Encode(metadataJSON)), nil
}

func createKeyAccess(kasInfo KASInfo, symKey []byte, policyBinding PolicyBinding, encryptedMetadata, splitID string) (KeyAccess, error) {
	keyAccess := KeyAccess{
		KeyType:           kWrapped,
		KasURL:            kasInfo.URL,
		KID:               kasInfo.KID,
		Protocol:          kKasProtocol,
		PolicyBinding:     policyBinding,
		EncryptedMetadata: encryptedMetadata,
		SplitID:           splitID,
		SchemaVersion:     keyAccessSchemaVersion,
	}

	ktype := ocrypto.KeyType(kasInfo.Algorithm)
	if ocrypto.IsECKeyType(ktype) {
		mode, err := ocrypto.ECKeyTypeToMode(ktype)
		if err != nil {
			return KeyAccess{}, err
		}
		wrappedKeyInfo, err := generateWrapKeyWithEC(mode, kasInfo.PublicKey, symKey)
		if err != nil {
			return KeyAccess{}, err
		}
		keyAccess.KeyType = kECWrapped
		keyAccess.WrappedKey = wrappedKeyInfo.wrappedKey
		keyAccess.EphemeralPublicKey = wrappedKeyInfo.publicKey
	} else {
		wrappedKey, err := generateWrapKeyWithRSA(kasInfo.PublicKey, symKey)
		if err != nil {
			return KeyAccess{}, err
		}
		keyAccess.WrappedKey = wrappedKey
	}

	return keyAccess, nil
}

func tdfSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)
	return salt
}

func generateWrapKeyWithEC(mode ocrypto.ECCMode, kasPublicKey string, symKey []byte) (ecKeyWrappedKeyInfo, error) {
	ecKeyPair, err := ocrypto.NewECKeyPair(mode)
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("ocrypto.NewECKeyPair failed:%w", err)
	}

	emphermalPublicKey, err := ecKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("generateWrapKeyWithEC: failed to get EC public key: %w", err)
	}

	emphermalPrivateKey, err := ecKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("generateWrapKeyWithEC: failed to get EC private key: %w", err)
	}

	ecdhKey, err := ocrypto.ComputeECDHKey([]byte(emphermalPrivateKey), []byte(kasPublicKey))
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("generateWrapKeyWithEC: ocrypto.ComputeECDHKey failed:%w", err)
	}

	salt := tdfSalt()
	sessionKey, err := ocrypto.CalculateHKDF(salt, ecdhKey)
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("generateWrapKeyWithEC: ocrypto.CalculateHKDF failed:%w", err)
	}

	gcm, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("generateWrapKeyWithEC: ocrypto.NewAESGcm failed:%w", err)
	}

	wrappedKey, err := gcm.Encrypt(symKey)
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("generateWrapKeyWithEC: ocrypto.AESGcm.Encrypt failed:%w", err)
	}

	return ecKeyWrappedKeyInfo{
		publicKey:  emphermalPublicKey,
		wrappedKey: string(ocrypto.Base64Encode(wrappedKey)),
	}, nil
}

func generateWrapKeyWithRSA(publicKey string, symKey []byte) (string, error) {
	asymEncrypt, err := ocrypto.NewAsymEncryption(publicKey)
	if err != nil {
		return "", fmt.Errorf("generateWrapKeyWithRSA: ocrypto.NewAsymEncryption failed:%w", err)
	}

	wrappedKey, err := asymEncrypt.Encrypt(symKey)
	if err != nil {
		return "", fmt.Errorf("generateWrapKeyWithRSA: ocrypto.AsymEncryption.encrypt failed:%w", err)
	}

	return string(ocrypto.Base64Encode(wrappedKey)), nil
}

// create policy object
func createPolicyObject(attributes []AttributeValueFQN) (PolicyObject, error) {
	uuidObj, err := uuid.NewUUID()
	if err != nil {
		return PolicyObject{}, fmt.Errorf("uuid.NewUUID failed: %w", err)
	}

	policyObj := PolicyObject{}
	policyObj.UUID = uuidObj.String()

	for _, attribute := range attributes {
		attributeObj := attributeObject{}
		attributeObj.Attribute = attribute.String()
		policyObj.Body.DataAttributes = append(policyObj.Body.DataAttributes, attributeObj)
		policyObj.Body.Dissem = make([]string, 0)
	}

	return policyObj, nil
}

func allowListFromKASRegistry(ctx context.Context, logger *slog.Logger, kasRegistryClient sdkconnect.KeyAccessServerRegistryServiceClient, platformURL string) (AllowList, error) {
	kases, err := kasRegistryClient.ListKeyAccessServers(ctx, &kasregistry.ListKeyAccessServersRequest{})
	if err != nil {
		return nil, fmt.Errorf("kasregistry.ListKeyAccessServers failed: %w", err)
	}
	kasAllowlist := AllowList{}
	for _, kas := range kases.GetKeyAccessServers() {
		err = kasAllowlist.Add(kas.GetUri())
		if err != nil {
			return nil, fmt.Errorf("kasAllowlist.Add failed: %w", err)
		}
	}
	// grpc target does not have a scheme
	logger.Debug("adding platform URL to KAS allowlist", slog.String("platform_url", platformURL))
	err = kasAllowlist.Add(platformURL)
	if err != nil {
		return nil, fmt.Errorf("kasAllowlist.Add failed: %w", err)
	}
	return kasAllowlist, nil
}

// LoadTDF loads the tdf and prepare for reading the payload from TDF
func (s SDK) LoadTDF(reader io.ReadSeeker, opts ...TDFReaderOption) (*Reader, error) {
	// create tdf reader
	tdfReader, err := archive.NewTDFReader(reader)
	if err != nil {
		return nil, fmt.Errorf("archive.NewTDFReader failed: %w", err)
	}

	if s.kasSessionKey != nil {
		opts = append([]TDFReaderOption{withSessionKey(s.kasSessionKey)}, opts...)
	}

	config, err := newTDFReaderConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("newAssertionConfig failed: %w", err)
	}

	useGlobalFulfillableObligations := len(config.fulfillableObligationFQNs) == 0 && len(s.fulfillableObligationFQNs) > 0
	if useGlobalFulfillableObligations {
		config.fulfillableObligationFQNs = s.fulfillableObligationFQNs
	}

	config.kasAllowlist, err = getKasAllowList(context.Background(), config.kasAllowlist, s, config.ignoreAllowList)
	if err != nil {
		return nil, err
	}

	manifest, err := tdfReader.Manifest()
	if err != nil {
		return nil, fmt.Errorf("tdfReader.Manifest failed: %w", err)
	}

	if config.schemaValidationIntensity == Lax || config.schemaValidationIntensity == Strict {
		valid, err := isValidManifest(manifest, config.schemaValidationIntensity)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, errors.New("manifest schema validation failed")
		}
	}

	manifestObj := &Manifest{}
	err = json.Unmarshal([]byte(manifest), manifestObj)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed:%w", err)
	}

	var payloadSize int64
	for _, seg := range manifestObj.EncryptionInformation.IntegrityInformation.Segments {
		payloadSize += seg.Size
	}

	return &Reader{
		tokenSource:    s.tokenSource,
		httpClient:     s.conn.Client,
		connectOptions: s.conn.Options,
		tdfReader:      tdfReader,
		manifest:       *manifestObj,
		kasSessionKey:  config.kasSessionKey,
		config:         *config,
		payloadSize:    payloadSize,
	}, nil
}

// Do any network based operations required.
// This allows making the requests cancellable
func (r *Reader) Init(ctx context.Context) error {
	if r.payloadKey != nil {
		return nil
	}
	return r.doPayloadKeyUnwrap(ctx)
}

// Read reads up to len(p) bytes into p. It returns the number of bytes
// read (0 <= n <= len(p)) and any error encountered. It returns an
// io.EOF error when the stream ends.
func (r *Reader) Read(p []byte) (int, error) {
	if r.payloadKey == nil {
		err := r.doPayloadKeyUnwrap(context.Background())
		if err != nil {
			return 0, fmt.Errorf("reader.Read failed: %w", err)
		}
	}

	n, err := r.ReadAt(p, r.cursor)
	r.cursor += int64(n)
	return n, err
}

// Seek updates cursor to `Read` or `WriteTo` at an offset.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = 0
	case io.SeekEnd:
		newPos = r.payloadSize
	case io.SeekCurrent:
		newPos = r.cursor
	default:
		return 0, fmt.Errorf("reader.Seek failed: unknown whence: %d", whence)
	}
	newPos += offset
	if newPos < 0 || newPos > r.payloadSize {
		return 0, fmt.Errorf("reader.Seek failed: index if out of range %d", newPos)
	}
	r.cursor = newPos
	return r.cursor, nil
}

// WriteTo writes data to writer until there's no more data to write or
// when an error occurs. This implements the io.WriterTo interface.
func (r *Reader) WriteTo(writer io.Writer) (int64, error) {
	if r.payloadKey == nil {
		err := r.doPayloadKeyUnwrap(context.Background())
		if err != nil {
			return 0, fmt.Errorf("reader.WriteTo failed: %w", err)
		}
	}

	isLegacyTDF := r.manifest.TDFVersion == ""

	var totalBytes int64
	var payloadReadOffset int64
	var decryptedDataOffset int64
	for _, seg := range r.manifest.EncryptionInformation.IntegrityInformation.Segments {
		if decryptedDataOffset+seg.Size < r.cursor {
			decryptedDataOffset += seg.Size
			payloadReadOffset += seg.EncryptedSize
			continue
		}

		readBuf, err := r.tdfReader.ReadPayload(payloadReadOffset, seg.EncryptedSize)
		if err != nil {
			return totalBytes, fmt.Errorf("TDFReader.ReadPayload failed: %w", err)
		}

		if int64(len(readBuf)) != seg.EncryptedSize {
			return totalBytes, ErrSegSizeMismatch
		}

		segHashAlg := r.manifest.EncryptionInformation.IntegrityInformation.SegmentHashAlgorithm
		sigAlg := HS256
		if strings.EqualFold(gmacIntegrityAlgorithm, segHashAlg) {
			sigAlg = GMAC
		}

		payloadSig, err := calculateSignature(readBuf, r.payloadKey, sigAlg, isLegacyTDF)
		if err != nil {
			return totalBytes, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
		}

		if seg.Hash != string(ocrypto.Base64Encode([]byte(payloadSig))) {
			return totalBytes, ErrSegSigValidation
		}

		writeBuf, err := r.aesGcm.Decrypt(readBuf)
		if err != nil {
			return totalBytes, fmt.Errorf("splitKey.decrypt failed: %w", err)
		}

		// special case where segment is in the middle of where cursor is
		if decryptedDataOffset < r.cursor {
			offset := r.cursor - decryptedDataOffset
			writeBuf = writeBuf[offset:]
		}
		n, err := writer.Write(writeBuf)
		totalBytes += int64(n)
		if err != nil {
			return totalBytes, fmt.Errorf("io.writer.write failed: %w", err)
		}

		if n != len(writeBuf) {
			return totalBytes, errWriteFailed
		}

		payloadReadOffset += seg.EncryptedSize
		r.cursor += int64(n)
		decryptedDataOffset += seg.Size
	}

	return totalBytes, nil
}

// ReadAt reads len(p) bytes into p starting at offset off
// in the underlying input source. It returns the number
// of bytes read (0 <= n <= len(p)) and any error encountered. It returns an
// io.EOF error when the stream ends.
// NOTE: For larger tdf sizes use sdk.GetTDFPayload for better performance
func (r *Reader) ReadAt(buf []byte, offset int64) (int, error) { //nolint:funlen, gocognit // Better readability keeping it as is for now
	if r.payloadKey == nil {
		err := r.doPayloadKeyUnwrap(context.Background())
		if err != nil {
			return 0, fmt.Errorf("reader.ReadAt failed: %w", err)
		}
	}

	if offset < 0 {
		return 0, ErrTDFPayloadInvalidOffset
	}

	defaultSegmentSize := r.manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize
	start := offset / defaultSegmentSize
	end := (offset + int64(len(buf)) + defaultSegmentSize - 1) / defaultSegmentSize // rounds up

	firstSegment := start
	lastSegment := end
	if firstSegment > lastSegment {
		return 0, ErrTDFPayloadReadFail
	}

	if offset > r.payloadSize {
		return 0, ErrTDFPayloadReadFail
	}

	isLegacyTDF := r.manifest.TDFVersion == ""
	var decryptedBuf bytes.Buffer
	var payloadReadOffset int64
	for index, seg := range r.manifest.EncryptionInformation.IntegrityInformation.Segments {
		// finish segments to decrypt
		if int64(index) == lastSegment {
			break
		}

		if firstSegment > int64(index) {
			payloadReadOffset += seg.EncryptedSize
			continue
		}

		readBuf, err := r.tdfReader.ReadPayload(payloadReadOffset, seg.EncryptedSize)
		if err != nil {
			return 0, fmt.Errorf("TDFReader.ReadPayload failed: %w", err)
		}

		if int64(len(readBuf)) != seg.EncryptedSize {
			return 0, ErrSegSizeMismatch
		}

		segHashAlg := r.manifest.EncryptionInformation.IntegrityInformation.SegmentHashAlgorithm
		sigAlg := HS256
		if strings.EqualFold(gmacIntegrityAlgorithm, segHashAlg) {
			sigAlg = GMAC
		}

		payloadSig, err := calculateSignature(readBuf, r.payloadKey, sigAlg, isLegacyTDF)
		if err != nil {
			return 0, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
		}

		if seg.Hash != string(ocrypto.Base64Encode([]byte(payloadSig))) {
			return 0, ErrSegSigValidation
		}

		writeBuf, err := r.aesGcm.Decrypt(readBuf)
		if err != nil {
			return 0, fmt.Errorf("splitKey.decrypt failed: %w", err)
		}

		n, err := decryptedBuf.Write(writeBuf)
		if err != nil {
			return 0, fmt.Errorf("bytes.Buffer.writer.write failed: %w", err)
		}

		if n != len(writeBuf) {
			return 0, errWriteFailed
		}

		payloadReadOffset += seg.EncryptedSize
	}

	var err error
	bufLen := int64(len(buf))
	if (offset + int64(len(buf))) > r.payloadSize {
		bufLen = r.payloadSize - offset
		err = io.EOF
	}

	startIndex := offset - (firstSegment * defaultSegmentSize)
	copy(buf[:bufLen], decryptedBuf.Bytes()[startIndex:startIndex+bufLen])
	return int(bufLen), err
}

// UnencryptedMetadata return decrypted metadata in manifest.
func (r *Reader) UnencryptedMetadata() ([]byte, error) {
	if r.payloadKey == nil {
		err := r.doPayloadKeyUnwrap(context.Background())
		if err != nil {
			return nil, fmt.Errorf("reader.UnencryptedMetadata failed: %w", err)
		}
	}

	return r.unencryptedMetadata, nil
}

// Policy returns a copy of the policy object in manifest, if it is valid.
// Otherwise, returns an error.
func (r *Reader) Policy() (PolicyObject, error) {
	policyObj := PolicyObject{}
	policy, err := ocrypto.Base64Decode([]byte(r.manifest.Policy))
	if err != nil {
		return policyObj, fmt.Errorf("ocrypto.Base64Decode failed:%w", err)
	}

	err = json.Unmarshal(policy, &policyObj)
	if err != nil {
		return policyObj, fmt.Errorf("json.Unmarshal failed: %w", err)
	}

	return policyObj, nil
}

// DataAttributes return the data attributes present in tdf.
func (r *Reader) DataAttributes() ([]string, error) {
	policy, err := ocrypto.Base64Decode([]byte(r.manifest.Policy))
	if err != nil {
		return nil, fmt.Errorf("ocrypto.Base64Decode failed:%w", err)
	}

	policyObj := PolicyObject{}
	err = json.Unmarshal(policy, &policyObj)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}

	attributes := make([]string, 0)
	attributeObjs := policyObj.Body.DataAttributes
	for _, attributeObj := range attributeObjs {
		attributes = append(attributes, attributeObj.Attribute)
	}

	return attributes, nil
}

/*
* Returns the obligations required for access to the TDF payload.
*
* If obligations are not populated we call Init() to populate them,
* which will result in a rewrap call.
*
 */
func (r *Reader) Obligations(ctx context.Context) (RequiredObligations, error) {
	if r.requiredObligations != nil {
		return *r.requiredObligations, nil
	}

	err := r.Init(ctx)
	// Do not return error if we required obligations after Init()
	// It's possible that an error was returned do to required obligations
	if r.requiredObligations != nil && len(r.requiredObligations.FQNs) > 0 {
		return *r.requiredObligations, nil
	}

	return RequiredObligations{FQNs: []string{}}, err
}

/*
*WARNING:* Using this function is unsafe since KAS will no longer be able to prevent access to the key.

Retrieve the payload key, either from performing an buildKey or from a previous buildKey,
and write it to a user buffer.

OUTPUTS:
  - []byte - Byte array containing the DEK.
  - error - If an error occurred while processing
*/
func (r *Reader) UnsafePayloadKeyRetrieval() ([]byte, error) {
	if r.payloadKey == nil {
		err := r.doPayloadKeyUnwrap(context.Background())
		if err != nil {
			return nil, fmt.Errorf("reader.PayloadKey failed: %w", err)
		}
	}

	return r.payloadKey, nil
}

// AppendAssertion adds a new assertion to the loaded TDF reader after creation.
// This method handles the cryptographic binding of the assertion to the TDF's payload.
// The assertion will be signed using the provided signing builder.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - assertion: the assertion
//
// Returns:
//   - error: Any error that occurred during the append operation
//
// Note: This method modifies the TDF's manifest in place. The assertion should be
// cryptographically bound to the TDF.
func (r *Reader) AppendAssertion(_ context.Context, assertion Assertion) error {
	// pre-check - can marshal
	manifestBytes, err := json.Marshal(r.manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	// pre-check - can unmarshal
	_ = json.Unmarshal(manifestBytes, &Manifest{})
	// Add the assertion to the manifest
	r.manifest.Assertions = append(r.manifest.Assertions, assertion)
	// post-check - can marshal
	manifestBytes, err = json.Marshal(r.manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}
	// post-check - can unmarshal
	return json.Unmarshal(manifestBytes, &Manifest{})
}

// WriteTDFWithUpdatedManifest writes the TDF to a new file with the updated manifest.
// This is useful for adding assertions to an existing TDF without decrypting/re-encrypting the payload.
//
// The function copies the original TDF ZIP verbatim while replacing only the manifest entry,
// which avoids the expensive operation of re-encrypting the payload and preserves all other
// entries byte-for-byte.
//
// Parameters:
//   - inPath: Path to the input TDF file
//   - outPath: Path to the output TDF file
//
// Returns:
//   - error: Any error that occurred during the write operation
//
// Example:
//
//	reader, _ := sdk.LoadTDF(file)
//	reader.AppendAssertion(ctx, assertion)
//	err := reader.WriteTDFWithUpdatedManifest("input.tdf", "output.tdf")
func (r *Reader) WriteTDFWithUpdatedManifest(inPath, outPath string) error {
	return WriteTDFWithUpdatedManifest(inPath, outPath, r.manifest)
}

// WriteTDFWithUpdatedManifest copies an existing TDF ZIP file while replacing only the manifest entry.
// This avoids re-encrypting the payload by preserving all other entries byte-for-byte.
//
// Parameters:
//   - inPath: Path to the input TDF file
//   - outPath: Path to the output TDF file
//   - manifest: The updated manifest to write
//
// Returns:
//   - error: Any error that occurred during the operation
func WriteTDFWithUpdatedManifest(inPath, outPath string, manifest Manifest) error {
	// Prepare updated manifest JSON without re-encrypting payload
	updatedManifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated manifest: %w", err)
	}

	inF, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("failed to open input TDF: %w", err)
	}
	defer inF.Close()

	stat, err := inF.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat input TDF: %w", err)
	}

	zr, err := zip.NewReader(inF, stat.Size())
	if err != nil {
		return fmt.Errorf("failed to open TDF as zip: %w", err)
	}

	outF, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output TDF: %w", err)
	}
	defer func() {
		// Ensure the file is closed even if zip writer close fails
		_ = outF.Close()
	}()

	zw := zip.NewWriter(outF)

	// Track if we replaced an existing manifest
	replaced := false

	for _, f := range zr.File {
		isManifest := f.Name == manifestFileName || f.Name == "manifest.json"

		// Clone header for faithful copy
		hdr := &zip.FileHeader{
			Name:           f.Name,
			Comment:        f.Comment,
			Method:         f.Method,
			NonUTF8:        f.NonUTF8,
			Modified:       f.Modified,
			ExternalAttrs:  f.ExternalAttrs,
			CreatorVersion: f.CreatorVersion,
			ReaderVersion:  f.ReaderVersion,
			Extra:          append([]byte(nil), f.Extra...),
		}

		if isManifest {
			// Replace the manifest contents
			// Use Deflate for manifest to keep typical compression; preserve Modified timestamp if present
			if hdr.Method == 0 {
				// If the original was stored (rare for manifest), keep it; else deflate by default
				hdr.Method = zip.Store
			}
			ww, err := zw.CreateHeader(hdr)
			if err != nil {
				_ = zw.Close()
				return fmt.Errorf("failed to create manifest entry in output TDF: %w", err)
			}
			// Ensure deterministic-ish timestamp if missing
			if hdr.Modified.IsZero() {
				hdr.SetModTime(time.Now().UTC())
			}
			if _, err := ww.Write(updatedManifestBytes); err != nil {
				_ = zw.Close()
				return fmt.Errorf("failed to write updated manifest: %w", err)
			}
			replaced = true
			continue
		}

		// Copy other entries byte-for-byte
		// Preserve compression method and metadata
		rc, err := f.Open()
		if err != nil {
			_ = zw.Close()
			return fmt.Errorf("failed to open input entry %q: %w", f.Name, err)
		}

		ww, err := zw.CreateHeader(hdr)
		if err != nil {
			rc.Close()
			_ = zw.Close()
			return fmt.Errorf("failed to create output entry %q: %w", f.Name, err)
		}

		//nolint:gosec // G110: Decompression bomb warning expected when unpacking ZIP files
		if _, err := io.Copy(ww, rc); err != nil {
			rc.Close()
			_ = zw.Close()
			return fmt.Errorf("failed to copy entry %q: %w", f.Name, err)
		}
		rc.Close()
	}

	if !replaced {
		// If no manifest was found, add one as 0.manifest.json
		hdr := &zip.FileHeader{
			Name:     manifestFileName,
			Method:   zip.Deflate,
			Modified: time.Now().UTC(),
		}
		ww, err := zw.CreateHeader(hdr)
		if err != nil {
			_ = zw.Close()
			return fmt.Errorf("failed to create new manifest entry: %w", err)
		}
		if _, err := ww.Write(updatedManifestBytes); err != nil {
			_ = zw.Close()
			return fmt.Errorf("failed to write new manifest: %w", err)
		}
	}

	if err := zw.Close(); err != nil {
		return fmt.Errorf("failed to finalize output TDF: %w", err)
	}
	if err := outF.Close(); err != nil {
		return fmt.Errorf("failed to close output TDF: %w", err)
	}

	return nil
}

func createRewrapRequest(_ context.Context, r *Reader) (map[string]*kas.UnsignedRewrapRequest_WithPolicyRequest, error) {
	kasReqs := make(map[string]*kas.UnsignedRewrapRequest_WithPolicyRequest)
	for i, kao := range r.manifest.EncryptionInformation.KeyAccessObjs {
		kaoID := fmt.Sprintf("kao-%d", i)

		key, err := ocrypto.Base64Decode([]byte(kao.WrappedKey))
		if err != nil {
			return nil, fmt.Errorf("could not decode wrapper key: %w", err)
		}
		var alg string
		var hash string
		invalidPolicy := false
		switch policyBinding := kao.PolicyBinding.(type) {
		case string:
			hash = policyBinding
		case map[string]interface{}:
			var ok bool
			hash, ok = policyBinding["hash"].(string)
			invalidPolicy = !ok
			alg, ok = policyBinding["alg"].(string)
			invalidPolicy = invalidPolicy || !ok
		case (PolicyBinding):
			hash = policyBinding.Hash
			alg = policyBinding.Alg
		default:
			invalidPolicy = true
		}
		if invalidPolicy {
			return nil, fmt.Errorf("invalid policy object: %s", kao.PolicyBinding)
		}
		kaoReq := &kas.UnsignedRewrapRequest_WithKeyAccessObject{
			KeyAccessObjectId: kaoID,
			KeyAccessObject: &kas.KeyAccess{
				KeyType:  kao.KeyType,
				KasUrl:   kao.KasURL,
				Kid:      kao.KID,
				Protocol: kao.Protocol,
				PolicyBinding: &kas.PolicyBinding{
					Hash:      hash,
					Algorithm: alg,
				},
				SplitId:            kao.SplitID,
				WrappedKey:         key,
				EphemeralPublicKey: kao.EphemeralPublicKey,
			},
		}
		if req, ok := kasReqs[kao.KasURL]; ok {
			req.KeyAccessObjects = append(req.KeyAccessObjects, kaoReq)
		} else {
			rewrapReq := kas.UnsignedRewrapRequest_WithPolicyRequest{
				Policy: &kas.UnsignedRewrapRequest_WithPolicy{
					Body: r.manifest.EncryptionInformation.Policy,
					Id:   "policy",
				},
				KeyAccessObjects: []*kas.UnsignedRewrapRequest_WithKeyAccessObject{kaoReq},
			}
			kasReqs[kao.KasURL] = &rewrapReq
		}
	}

	return kasReqs, nil
}

func getIdx(kaoID string) int {
	idx, _ := strconv.Atoi(strings.Split(kaoID, "-")[1])
	return idx
}

func (r *Reader) buildKey(ctx context.Context, results []kaoResult) error {
	var unencryptedMetadata []byte
	var payloadKey [kKeySize]byte
	knownSplits := make(map[string]bool)
	foundSplits := make(map[string]bool)
	skippedSplits := make(map[keySplitStep]error)

	for _, kaoRes := range results {
		idx := getIdx(kaoRes.KeyAccessObjectID)
		keyAccessObj := r.manifest.KeyAccessObjs[idx]
		ss := keySplitStep{KAS: keyAccessObj.KasURL, SplitID: keyAccessObj.SplitID}

		wrappedKey := kaoRes.SymmetricKey
		err := kaoRes.Error
		knownSplits[ss.SplitID] = true
		if foundSplits[ss.SplitID] {
			// already found
			continue
		}

		if err != nil {
			errToReturn := fmt.Errorf("kao unwrap failed for split %v: %w", ss, err)
			skippedSplits[ss] = getKasErrorToReturn(err, errToReturn)
			continue
		}

		for keyByteIndex, keyByte := range wrappedKey {
			payloadKey[keyByteIndex] ^= keyByte
		}
		foundSplits[ss.SplitID] = true

		if len(keyAccessObj.EncryptedMetadata) != 0 {
			gcm, err := ocrypto.NewAESGcm(wrappedKey)
			if err != nil {
				return fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
			}

			decodedMetaData, err := ocrypto.Base64Decode([]byte(keyAccessObj.EncryptedMetadata))
			if err != nil {
				return fmt.Errorf("ocrypto.Base64Decode failed:%w", err)
			}

			metadata := EncryptedMetadata{}
			err = json.Unmarshal(decodedMetaData, &metadata)
			if err != nil {
				return fmt.Errorf("json.Unmarshal failed:%w", err)
			}

			encodedCipherText := metadata.Cipher
			cipherText, _ := ocrypto.Base64Decode([]byte(encodedCipherText))
			metaData, err := gcm.Decrypt(cipherText)
			if err != nil {
				return fmt.Errorf("ocrypto.AesGcm.encrypt failed:%w", err)
			}

			unencryptedMetadata = metaData
		}
	}

	if len(knownSplits) > len(foundSplits) {
		v := make([]error, 1, len(skippedSplits))
		v[0] = fmt.Errorf("splitKey.unable to reconstruct split key: %v", skippedSplits)
		for _, e := range skippedSplits {
			v = append(v, e)
		}
		return errors.Join(v...)
	}

	aggregateHashBytes, err := ComputeAggregateHash(r.manifest.EncryptionInformation.IntegrityInformation.Segments)
	if err != nil {
		return fmt.Errorf("ComputeAggregateHash failed:%w", err)
	}

	res, err := validateRootSignature(r.manifest, aggregateHashBytes, payloadKey[:])
	if err != nil {
		return fmt.Errorf("%w: splitKey.validateRootSignature failed: %w", ErrRootSignatureFailure, err)
	}

	if !res {
		return fmt.Errorf("%w: %w", ErrRootSignatureFailure, ErrRootSigValidation)
	}

	segSize := r.manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize
	encryptedSegSize := r.manifest.EncryptionInformation.IntegrityInformation.DefaultEncryptedSegSize

	if segSize != encryptedSegSize-(gcmIvSize+aesBlockSize) {
		return ErrSegSizeMismatch
	}

	// Register DEK default system metadata assertion validator
	if r.config.disableAssertionVerification {
		// Skip all assertion verification setup
		gcm, err := ocrypto.NewAESGcm(payloadKey[:])
		if err != nil {
			return fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
		}

		r.unencryptedMetadata = unencryptedMetadata
		r.payloadKey = payloadKey[:]
		r.aesGcm = gcm

		return nil
	}

	// Propagate verification mode to all registered validators
	// This ensures validators respect the configured verification mode
	for _, validator := range r.config.assertionRegistry.validators {
		if setter, ok := validator.(interface {
			SetVerificationMode(AssertionVerificationMode)
		}); ok {
			setter.SetVerificationMode(r.config.assertionVerificationMode)
		}
	}

	// useHex is used for legacy TDF compatibility (versions < 4.3.0)
	// When reading legacy TDFs, signatures are hex-encoded instead of raw bytes
	// Legacy TDFs have no TDFVersion field in the manifest
	useHex := r.manifest.TDFVersion == ""
	systemMetadataAssertionProvider := NewSystemMetadataAssertionProvider(useHex, payloadKey[:], string(aggregateHashBytes))
	systemMetadataAssertionProvider.SetVerificationMode(r.config.assertionVerificationMode)
	// if already registered, ignore
	_ = r.config.assertionRegistry.RegisterValidator(systemMetadataAssertionProvider)

	// Create DEK-based validator for fallback verification (not registered with wildcard)
	// This will be used as a last resort for unknown assertions that might be DEK-signed
	dekKey := AssertionKey{
		Alg: AssertionKeyAlgHS256,
		Key: payloadKey[:],
	}
	dekAssertionValidator := NewDEKAssertionValidator(dekKey, string(aggregateHashBytes), useHex)
	dekAssertionValidator.SetVerificationMode(r.config.assertionVerificationMode)

	// Validate assertions based on configured verification mode
	for _, assertion := range r.manifest.Assertions {
		// SECURITY: Assertions without cryptographic bindings cannot be verified and must fail
		// This prevents unsigned assertions from being tampered with
		// Unsigned assertions represent a security risk and should not be accepted
		if assertion.Binding.Signature == "" {
			return fmt.Errorf("%w: assertion has no cryptographic binding - unsigned assertions are not allowed",
				ErrAssertionFailure{ID: assertion.ID})
		}

		validator, err := r.config.assertionRegistry.GetValidationProvider(assertion.Statement.Schema)
		if err != nil && r.config.verifiers.IsEmpty() {
			// No schema-specific validator found, and no explicit verification keys provided
			// Try DEK-based verification as a fallback (for assertions signed with DEK during encryption)
			dekVerifyErr := dekAssertionValidator.Verify(ctx, assertion, *r)
			switch {
			case dekVerifyErr == nil:
				// DEK verification succeeded - assertion was signed with DEK
				// Continue to validation phase
				validator = dekAssertionValidator
			case errors.Is(dekVerifyErr, errAssertionVerifyKeyFailure):
				// JWT signature verification failed with DEK - assertion not signed with DEK
				// Treat as unknown assertion (forward compatibility)
				validator = nil
			default:
				// DEK verification failed for other reason (hash mismatch, binding mismatch, etc.)
				// This indicates tampering of a DEK-signed assertion - FAIL immediately
				return r.handleAssertionVerificationError(assertion.ID, dekVerifyErr)
			}
		}

		// If we still don't have a validator, handle as unknown assertion
		if err != nil && validator == nil {
			// Unknown assertion handling depends on verification mode
			switch r.config.assertionVerificationMode {
			case PermissiveMode, FailFast:
				// Skip unknown assertions with warning (forward compatibility)
				continue
			case StrictMode:
				// Fail on unknown assertions
				return fmt.Errorf("%w: unknown assertion type in strict mode", ErrAssertionFailure{ID: assertion.ID})
			}
		}

		// Verify integrity and binding
		slog.DebugContext(ctx, "verifying assertion integrity and binding",
			slog.String("assertion_id", assertion.ID))
		err = validator.Verify(ctx, assertion, *r)
		if err != nil {
			// Verification errors are always treated as potential tampering
			slog.ErrorContext(ctx, "assertion verification failed",
				slog.String("assertion_id", assertion.ID),
				slog.String("assertion_schema", assertion.Statement.Schema),
				slog.Any("error", err))
			return r.handleAssertionVerificationError(assertion.ID, err)
		}
		slog.DebugContext(ctx, "assertion verification succeeded",
			slog.String("assertion_id", assertion.ID))

		// Validate trust
		err = validator.Validate(ctx, assertion, *r)
		if err != nil {
			// Trust validation errors may be handled based on mode
			switch r.config.assertionVerificationMode {
			case PermissiveMode:
				// Log validation errors but continue
				slog.ErrorContext(ctx, "assertion validation failed, continuing in permissive mode",
					slog.String("assertion_id", assertion.ID),
					slog.Any("error", err))
				// This could be reported as a tamper event in the future
				continue
			case StrictMode, FailFast:
				// StrictMode and FailFast both fail on validation errors
				return r.handleAssertionVerificationError(assertion.ID, err)
			}
		}
		slog.DebugContext(ctx, "assertion validation complete",
			slog.String("assertion_id", assertion.ID))
	}

	gcm, err := ocrypto.NewAESGcm(payloadKey[:])
	if err != nil {
		return fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	r.unencryptedMetadata = unencryptedMetadata
	r.payloadKey = payloadKey[:]
	r.aesGcm = gcm

	return nil
}

// handleAssertionVerificationError handles errors from assertion verification
func (r *Reader) handleAssertionVerificationError(assertionID string, err error) error {
	if errors.Is(err, errAssertionVerifyKeyFailure) {
		return fmt.Errorf("assertion verification failed: %w", err)
	}
	return fmt.Errorf("%w: assertion verification failed: %w", ErrAssertionFailure{ID: assertionID}, err)
}

// Unwraps the payload key, if possible, using the access service
func (r *Reader) doPayloadKeyUnwrap(ctx context.Context) error { //nolint:gocognit // Better readability keeping it as is
	kasClient := newKASClient(r.httpClient, r.connectOptions, r.tokenSource, r.kasSessionKey, r.config.fulfillableObligationFQNs)

	var kaoResults []kaoResult
	reqFail := func(err error, req *kas.UnsignedRewrapRequest_WithPolicyRequest) {
		for _, kao := range req.GetKeyAccessObjects() {
			kaoResults = append(kaoResults, kaoResult{
				KeyAccessObjectID: kao.GetKeyAccessObjectId(),
				Error:             err,
			})
		}
	}

	reqs, err := createRewrapRequest(ctx, r)
	if err != nil {
		return err
	}
	for kasurl, req := range reqs {
		// if ignoreing allowlist then warn
		// if kas url is not allowed then return error
		if r.config.ignoreAllowList {
			getLogger().WarnContext(ctx, "kasAllowlist is ignored, kas url is allowed", slog.String("kas_url", kasurl))
		} else if !r.config.kasAllowlist.IsAllowed(kasurl) {
			reqFail(fmt.Errorf("KasAllowlist: kas url %s is not allowed", kasurl), req)
			continue
		}

		// if allowed then unwrap
		policyRes, err := kasClient.unwrap(ctx, req)
		if err != nil {
			reqFail(err, req)
		} else {
			result, ok := policyRes["policy"]
			if !ok {
				err = errors.New("could not find policy in rewrap response")
				reqFail(err, req)
			}
			kaoResults = append(kaoResults, result...)
		}
	}
	// Deduplicate obligations for all kao results
	r.requiredObligations = &RequiredObligations{FQNs: dedupRequiredObligations(kaoResults)}

	return r.buildKey(ctx, kaoResults)
}

// calculateSignature calculate signature of data of the given algorithm.
func calculateSignature(data []byte, secret []byte, alg IntegrityAlgorithm, isLegacyTDF bool) (string, error) {
	if alg == HS256 {
		hmac := ocrypto.CalculateSHA256Hmac(secret, data)
		if isLegacyTDF {
			return hex.EncodeToString(hmac), nil
		}
		return string(hmac), nil
	}
	if kGMACPayloadLength > len(data) {
		return "", errors.New("fail to create gmac signature")
	}

	if isLegacyTDF {
		return hex.EncodeToString(data[len(data)-kGMACPayloadLength:]), nil
	}
	return string(data[len(data)-kGMACPayloadLength:]), nil
}

// validate the root signature
func validateRootSignature(manifest Manifest, aggregateHash, secret []byte) (bool, error) {
	rootSigAlg := manifest.EncryptionInformation.IntegrityInformation.RootSignature.Algorithm
	rootSigValue := manifest.EncryptionInformation.IntegrityInformation.RootSignature.Signature
	isLegacyTDF := manifest.TDFVersion == ""

	sigAlg := HS256
	if strings.EqualFold(gmacIntegrityAlgorithm, rootSigAlg) {
		sigAlg = GMAC
	}

	sig, err := calculateSignature(aggregateHash, secret, sigAlg, isLegacyTDF)
	if err != nil {
		return false, fmt.Errorf("splitkey.getSignature failed:%w", err)
	}

	if rootSigValue == string(ocrypto.Base64Encode([]byte(sig))) {
		return true, nil
	}

	return false, nil
}

// check if the provided semver is less than the target
func isLessThanSemver(version, target string) (bool, error) {
	v1, err := semver.NewVersion(version)
	if err != nil {
		return false, fmt.Errorf("semver.NewVersion failed for version %s: %w", version, err)
	}
	v2, err := semver.NewVersion(target)
	if err != nil {
		return false, fmt.Errorf("semver.NewVersion failed for version %s: %w", target, err)
	}
	// Check if the provided version is less than the target version based on semantic versioning rules.
	return v1.LessThan(v2), nil
}

func getBaseKeyFromWellKnown(ctx context.Context, s SDK) (*policy.SimpleKasKey, error) {
	key, err := getBaseKey(ctx, s)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func populateKasInfoFromBaseKey(key *policy.SimpleKasKey, tdfConfig *TDFConfig) error {
	if key == nil {
		return errors.New("populateKasInfoFromBaseKey failed: key is nil")
	}

	algoString, err := formatAlg(key.GetPublicKey().GetAlgorithm())
	if err != nil {
		return fmt.Errorf("formatAlg failed: %w", err)
	}

	// ? Maybe we shouldn't overwrite the key type
	if tdfConfig.preferredKeyWrapAlg != ocrypto.KeyType(algoString) {
		getLogger().Warn("base key is enabled, setting key type", slog.String("key_type", algoString))
	}
	tdfConfig.preferredKeyWrapAlg = ocrypto.KeyType(algoString)
	tdfConfig.splitPlan = nil
	if len(tdfConfig.kasInfoList) > 0 {
		getLogger().Warn("base key is enabled, overwriting kasInfoList with base key info")
	}
	tdfConfig.kasInfoList = []KASInfo{
		{
			URL:       key.GetKasUri(),
			PublicKey: key.GetPublicKey().GetPem(),
			KID:       key.GetPublicKey().GetKid(),
			Algorithm: algoString,
		},
	}
	return nil
}

func createKaoTemplateFromKasInfo(kasInfoArr []KASInfo) []kaoTpl {
	kaoTemplate := make([]kaoTpl, len(kasInfoArr))
	for i, kasInfo := range kasInfoArr {
		splitID := ""
		if len(kasInfoArr) > 1 {
			splitID = fmt.Sprintf("s-%d", i)
		}
		kaoTemplate[i] = kaoTpl{
			KAS:       kasInfo.URL,
			SplitID:   splitID,
			kid:       kasInfo.KID,
			pem:       kasInfo.PublicKey,
			algorithm: ocrypto.KeyType(kasInfo.Algorithm),
		}
	}

	return kaoTemplate
}

func getKasErrorToReturn(err error, defaultError error) error {
	errToReturn := defaultError
	if strings.Contains(err.Error(), codes.InvalidArgument.String()) {
		errToReturn = errors.Join(ErrRewrapBadRequest, errToReturn)
	} else if strings.Contains(err.Error(), codes.PermissionDenied.String()) {
		errToReturn = errors.Join(ErrRewrapForbidden, errToReturn)
	}

	return errToReturn
}

func getKasAllowList(ctx context.Context, kasAllowList AllowList, s SDK, ignoreAllowList bool) (AllowList, error) {
	allowList := kasAllowList
	if len(allowList) == 0 && !ignoreAllowList {
		if s.KeyAccessServerRegistry == nil {
			slog.Error("no KAS allowlist provided and no KeyAccessServerRegistry available")
			return nil, errors.New("no KAS allowlist provided and no KeyAccessServerRegistry available")
		}

		// retrieve the registered kases if not provided
		platformEndpoint, err := s.PlatformConfiguration.platformEndpoint()
		if err != nil {
			return nil, fmt.Errorf("retrieving platformEndpoint failed: %w", err)
		}
		allowList, err = allowListFromKASRegistry(ctx, s.logger, s.KeyAccessServerRegistry, platformEndpoint)
		if err != nil {
			return nil, fmt.Errorf("allowListFromKASRegistry failed: %w", err)
		}
	}

	return allowList, nil
}

func dedupRequiredObligations(kaoResults []kaoResult) []string {
	seen := make(map[string]struct{})
	dedupedOblgs := make([]string, 0)
	for _, kao := range kaoResults {
		for _, oblg := range kao.RequiredObligations {
			normalizedOblg := strings.TrimSpace(strings.ToLower(oblg))
			if len(normalizedOblg) == 0 {
				continue
			}
			if _, ok := seen[normalizedOblg]; !ok {
				seen[normalizedOblg] = struct{}{}
				dedupedOblgs = append(dedupedOblgs, normalizedOblg)
			}
		}
	}

	return dedupedOblgs
}
