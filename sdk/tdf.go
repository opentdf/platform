package sdk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/opentdf/platform/protocol/go/kas"

	"github.com/google/uuid"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/archive"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	keyAccessSchemaVersion  = "1.0"
	maxFileSizeSupported    = 68719476736 // 64gb
	defaultMimeType         = "application/octet-stream"
	tdfAsZip                = "zip"
	gcmIvSize               = 12
	aesBlockSize            = 16
	hmacIntegrityAlgorithm  = "HS256"
	gmacIntegrityAlgorithm  = "GMAC"
	tdfZipReference         = "reference"
	kKeySize                = 32
	kWrapped                = "wrapped"
	kECWrapped              = "ec-wrapped"
	kKasProtocol            = "kas"
	kSplitKeyType           = "split"
	kGCMCipherAlgorithm     = "AES-256-GCM"
	kGMACPayloadLength      = 16
	kAssertionSignature     = "assertionSig"
	kAssertionHash          = "assertionHash"
	kClientPublicKey        = "clientPublicKey"
	kSignedRequestToken     = "signedRequestToken"
	kKasURL                 = "url"
	kRewrapV2               = "/v2/rewrap"
	kAuthorizationKey       = "Authorization"
	kContentTypeKey         = "Content-Type"
	kAcceptKey              = "Accept"
	kContentTypeJSONValue   = "application/json"
	kEntityWrappedKey       = "entityWrappedKey"
	kPolicy                 = "policy"
	kHmacIntegrityAlgorithm = "HS256"
	kGmacIntegrityAlgorithm = "GMAC"
)

// Loads and reads ZTDF files
type Reader struct {
	tokenSource         auth.AccessTokenSource
	dialOptions         []grpc.DialOption
	manifest            Manifest
	unencryptedMetadata []byte
	tdfReader           archive.TDFReader
	cursor              int64
	aesGcm              ocrypto.AesGcm
	payloadSize         int64
	payloadKey          []byte
	kasSessionKey       ocrypto.KeyPair
	config              TDFReaderConfig
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

func (s SDK) createTDF3DecryptHandler(writer io.Writer, reader io.ReadSeeker) (*tdf3DecryptHandler, error) {
	tdfReader, err := s.LoadTDF(reader)
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

	if tdfConfig.autoconfigure {
		var g granter
		if len(tdfConfig.attributeValues) > 0 {
			g, err = newGranterFromAttributes(s.kasKeyCache, tdfConfig.attributeValues...)
		} else if len(tdfConfig.attributes) > 0 {
			g, err = newGranterFromService(ctx, s.kasKeyCache, s.Attributes, tdfConfig.attributes...)
		}
		if err != nil {
			return nil, err
		}

		dk := s.defaultKases(tdfConfig)
		tdfConfig.splitPlan, err = g.plan(dk, func() string {
			return uuid.New().String()
		})
		if err != nil {
			return nil, err
		}
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
			return nil, fmt.Errorf("io.ReadSeeker.Read size mismatch")
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
			tdfConfig.segmentIntegrityAlgorithm, false)
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
		tdfConfig.integrityAlgorithm, false)
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

	var signedAssertion []Assertion
	for _, assertion := range tdfConfig.assertions {
		// Store a temporary assertion
		tmpAssertion := Assertion{}

		tmpAssertion.ID = assertion.ID
		tmpAssertion.Type = assertion.Type
		tmpAssertion.Scope = assertion.Scope
		tmpAssertion.Statement = assertion.Statement
		tmpAssertion.AppliesToState = assertion.AppliesToState

		hashOfAssertionAsHex, err := tmpAssertion.GetHash()
		if err != nil {
			return nil, err
		}

		hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
		_, err = hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
		if err != nil {
			return nil, fmt.Errorf("error decoding hex string: %w", err)
		}

		var completeHashBuilder strings.Builder
		completeHashBuilder.WriteString(aggregateHash)
		completeHashBuilder.Write(hashOfAssertion)

		encoded := ocrypto.Base64Encode([]byte(completeHashBuilder.String()))

		assertionSigningKey := AssertionKey{}

		// Set default to HS256 and payload key
		assertionSigningKey.Alg = AssertionKeyAlgHS256
		assertionSigningKey.Key = tdfObject.payloadKey[:]

		if !assertion.SigningKey.IsEmpty() {
			assertionSigningKey = assertion.SigningKey
		}

		if err := tmpAssertion.Sign(string(hashOfAssertionAsHex), string(encoded), assertionSigningKey); err != nil {
			return nil, fmt.Errorf("failed to sign assertion: %w", err)
		}

		signedAssertion = append(signedAssertion, tmpAssertion)
	}

	tdfObject.manifest.Assertions = signedAssertion

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

func (t *TDFObject) Manifest() Manifest {
	return t.manifest
}

func (r *Reader) Manifest() Manifest {
	return r.manifest
}

// prepare the manifest for TDF
func (s SDK) prepareManifest(ctx context.Context, t *TDFObject, tdfConfig TDFConfig) error { //nolint:funlen,gocognit // Better readability keeping it as is
	manifest := Manifest{}

	manifest.TDFVersion = TDFSpecVersion
	if len(tdfConfig.splitPlan) == 0 && len(tdfConfig.kasInfoList) == 0 {
		return fmt.Errorf("%w: no key access template specified or inferred", errInvalidKasInfo)
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
	symKeys := make([][]byte, 0)
	latestKASInfo := make(map[string]KASInfo)
	if len(tdfConfig.splitPlan) == 0 {
		// Default split plan: Split keys across all kases
		tdfConfig.splitPlan = make([]keySplitStep, len(tdfConfig.kasInfoList))
		for i, kasInfo := range tdfConfig.kasInfoList {
			tdfConfig.splitPlan[i].KAS = kasInfo.URL
			if len(tdfConfig.kasInfoList) > 1 {
				tdfConfig.splitPlan[i].SplitID = fmt.Sprintf("s-%d", i)
			}
			if kasInfo.PublicKey != "" {
				latestKASInfo[kasInfo.URL] = kasInfo
			}
		}
	}
	// Seed anything passed in manually
	for _, kasInfo := range tdfConfig.kasInfoList {
		if kasInfo.PublicKey != "" {
			latestKASInfo[kasInfo.URL] = kasInfo
		}
	}

	// split plan: restructure by conjunctions
	conjunction := make(map[string][]KASInfo)
	var splitIDs []string

	keyAlgorithm := string(tdfConfig.keyType)

	for _, splitInfo := range tdfConfig.splitPlan {
		// Public key was passed in with kasInfoList
		// TODO first look up in attribute information / add to split plan?
		ki, ok := latestKASInfo[splitInfo.KAS]
		if !ok || ki.PublicKey == "" {
			k, err := s.getPublicKey(ctx, splitInfo.KAS, keyAlgorithm)
			if err != nil {
				return fmt.Errorf("unable to retrieve public key from KAS at [%s]: %w", splitInfo.KAS, err)
			}
			latestKASInfo[splitInfo.KAS] = *k
			ki = *k
		}
		if _, ok = conjunction[splitInfo.SplitID]; ok {
			conjunction[splitInfo.SplitID] = append(conjunction[splitInfo.SplitID], ki)
		} else {
			conjunction[splitInfo.SplitID] = []KASInfo{ki}
			splitIDs = append(splitIDs, splitInfo.SplitID)
		}
	}

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

			keyAccess, err := createKeyAccess(tdfConfig, kasInfo, symKey, policyBinding, encryptedMetadata, splitID)
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

func createKeyAccess(tdfConfig TDFConfig, kasInfo KASInfo, symKey []byte, policyBinding PolicyBinding, encryptedMetadata, splitID string) (KeyAccess, error) {
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

	if ocrypto.IsECKeyType(tdfConfig.keyType) {
		mode, err := ocrypto.ECKeyTypeToMode(tdfConfig.keyType)
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

func generateWrapKeyWithEC(mode ocrypto.ECCMode, kasPublicKey string, symKey []byte) (ecKeyWrappedKeyInfo, error) {
	ecKeyPair, err := ocrypto.NewECKeyPair(mode)
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("ocrypto.NewECKeyPair failed:%w", err)
	}

	emphermalPublicKey, err := ecKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("failed to get EC public key: %w", err)
	}

	emphermalPrivateKey, err := ecKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("failed to get EC private key: %w", err)
	}

	ecdhKey, err := ocrypto.ComputeECDHKey([]byte(emphermalPrivateKey), []byte(kasPublicKey))
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("ocrypto.ComputeECDHKey failed:%w", err)
	}

	digest := sha256.New()
	digest.Write([]byte("TDF"))
	salt := digest.Sum(nil)
	sessionKey, err := ocrypto.CalculateHKDF([]byte(salt), ecdhKey)
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
	}

	gcm, err := ocrypto.NewAESGcm(sessionKey)
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	wrappedKey, err := gcm.Encrypt(symKey)
	if err != nil {
		return ecKeyWrappedKeyInfo{}, fmt.Errorf("ocrypto.AESGcm.Encrypt failed:%w", err)
	}

	return ecKeyWrappedKeyInfo{
		publicKey:  emphermalPublicKey,
		wrappedKey: string(ocrypto.Base64Encode(wrappedKey)),
	}, nil
}

func generateWrapKeyWithRSA(publicKey string, symKey []byte) (string, error) {
	asymEncrypt, err := ocrypto.NewAsymEncryption(publicKey)
	if err != nil {
		return "", fmt.Errorf("ocrypto.NewAsymEncryption failed:%w", err)
	}

	wrappedKey, err := asymEncrypt.Encrypt(symKey)
	if err != nil {
		return "", fmt.Errorf("ocrypto.AsymEncryption.encrypt failed:%w", err)
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

// LoadTDF loads the tdf and prepare for reading the payload from TDF
func (s SDK) LoadTDF(reader io.ReadSeeker, opts ...TDFReaderOption) (*Reader, error) {
	// create tdf reader
	tdfReader, err := archive.NewTDFReader(reader)
	if err != nil {
		return nil, fmt.Errorf("archive.NewTDFReader failed: %w", err)
	}

	config, err := newTDFReaderConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("newAssertionConfig failed: %w", err)
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
			return nil, fmt.Errorf("manifest schema validation failed")
		}
	}

	manifestObj := &Manifest{}
	err = json.Unmarshal([]byte(manifest), manifestObj)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed:%w", err)
	}

	return &Reader{
		tokenSource:   s.tokenSource,
		dialOptions:   s.dialOptions,
		tdfReader:     tdfReader,
		manifest:      *manifestObj,
		kasSessionKey: config.kasSessionKey,
		config:        *config,
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
	for _, seg := range r.manifest.EncryptionInformation.IntegrityInformation.Segments {
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

		n, err := writer.Write(writeBuf)
		if err != nil {
			return totalBytes, fmt.Errorf("io.writer.write failed: %w", err)
		}

		if n != len(writeBuf) {
			return totalBytes, errWriteFailed
		}

		payloadReadOffset += seg.EncryptedSize
		totalBytes += int64(n)
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
	start := math.Floor(float64(offset) / float64(defaultSegmentSize))
	end := math.Ceil(float64(offset+int64(len(buf))) / float64(defaultSegmentSize))

	firstSegment := int64(start)
	lastSegment := int64(end)
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

		// finish segments to decrypt
		if int64(index) == lastSegment {
			break
		}
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

func (r *Reader) buildKey(_ context.Context, results []kaoResult) error {
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
			if strings.Contains(err.Error(), codes.InvalidArgument.String()) {
				errToReturn = fmt.Errorf("%w: %w", ErrRewrapBadRequest, errToReturn)
			}
			if strings.Contains(err.Error(), codes.PermissionDenied.String()) {
				errToReturn = fmt.Errorf("%w: %w", errRewrapForbidden, errToReturn)
			}
			skippedSplits[ss] = errToReturn
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

	aggregateHash := &bytes.Buffer{}
	for _, segment := range r.manifest.EncryptionInformation.IntegrityInformation.Segments {
		decodedHash, err := ocrypto.Base64Decode([]byte(segment.Hash))
		if err != nil {
			return fmt.Errorf("ocrypto.Base64Decode failed:%w", err)
		}

		aggregateHash.Write(decodedHash)
	}

	res, err := validateRootSignature(r.manifest, aggregateHash.Bytes(), payloadKey[:])
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

	// Validate assertions
	for _, assertion := range r.manifest.Assertions {
		// Skip assertion verification if disabled
		if r.config.disableAssertionVerification {
			continue
		}

		assertionKey := AssertionKey{}
		// Set default to HS256
		assertionKey.Alg = AssertionKeyAlgHS256
		assertionKey.Key = payloadKey[:]

		if !r.config.verifiers.IsEmpty() {
			// Look up the key for the assertion
			foundKey, err := r.config.verifiers.Get(assertion.ID)

			if err != nil {
				return fmt.Errorf("%w: %w", ErrAssertionFailure{ID: assertion.ID}, err)
			} else if !foundKey.IsEmpty() {
				assertionKey.Alg = foundKey.Alg
				assertionKey.Key = foundKey.Key
			}
		}

		assertionHash, assertionSig, err := assertion.Verify(assertionKey)
		if err != nil {
			if errors.Is(err, errAssertionVerifyKeyFailure) {
				return fmt.Errorf("assertion verification failed: %w", err)
			}
			return fmt.Errorf("%w: assertion verification failed: %w", ErrAssertionFailure{ID: assertion.ID}, err)
		}

		// Get the hash of the assertion
		hashOfAssertionAsHex, err := assertion.GetHash()
		if err != nil {
			return fmt.Errorf("%w: failed to get hash of assertion: %w", ErrAssertionFailure{ID: assertion.ID}, err)
		}

		hashOfAssertion := make([]byte, hex.DecodedLen(len(hashOfAssertionAsHex)))
		_, err = hex.Decode(hashOfAssertion, hashOfAssertionAsHex)
		if err != nil {
			return fmt.Errorf("error decoding hex string: %w", err)
		}

		isLegacyTDF := r.manifest.TDFVersion == ""
		if isLegacyTDF {
			hashOfAssertion = hashOfAssertionAsHex
		}

		var completeHashBuilder bytes.Buffer
		completeHashBuilder.Write(aggregateHash.Bytes())
		completeHashBuilder.Write(hashOfAssertion)

		base64Hash := ocrypto.Base64Encode(completeHashBuilder.Bytes())

		if string(hashOfAssertionAsHex) != assertionHash {
			return fmt.Errorf("%w: assertion hash missmatch", ErrAssertionFailure{ID: assertion.ID})
		}

		if assertionSig != string(base64Hash) {
			return fmt.Errorf("%w: failed integrity check on assertion signature", ErrAssertionFailure{ID: assertion.ID})
		}
	}

	var payloadSize int64
	for _, seg := range r.manifest.EncryptionInformation.IntegrityInformation.Segments {
		payloadSize += seg.Size
	}

	gcm, err := ocrypto.NewAESGcm(payloadKey[:])
	if err != nil {
		return fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
	}

	r.payloadSize = payloadSize
	r.unencryptedMetadata = unencryptedMetadata
	r.payloadKey = payloadKey[:]
	r.aesGcm = gcm

	return nil
}

// Unwraps the payload key, if possible, using the access service
func (r *Reader) doPayloadKeyUnwrap(ctx context.Context) error { //nolint:gocognit // Better readability keeping it as is
	kasClient := newKASClient(r.dialOptions, r.tokenSource, r.kasSessionKey)

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
	for _, req := range reqs {
		policyRes, err := kasClient.unwrap(ctx, req)
		if err != nil {
			reqFail(err, req)
		}
		result, ok := policyRes["policy"]
		if !ok {
			err = fmt.Errorf("could not find policy in rewrap response")
			reqFail(err, req)
		}
		kaoResults = append(kaoResults, result...)
	}

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
		return "", fmt.Errorf("fail to create gmac signature")
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
