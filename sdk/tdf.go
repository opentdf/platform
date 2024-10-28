package sdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/google/uuid"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/sdk/auth"
	"github.com/opentdf/platform/sdk/internal/archive"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
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
	kasSessionKey       ocrypto.RsaKeyPair
	config              TDFReaderConfig
}

type TDFObject struct {
	manifest   Manifest
	size       int64
	aesGcm     ocrypto.AesGcm
	payloadKey [kKeySize]byte
}

func (t TDFObject) Size() int64 {
	return t.size
}

// CreateTDF reads plain text from the given reader and saves it to the writer, subject to the given options
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

		segmentSig, err := calculateSignature(cipherData, tdfObject.payloadKey[:], tdfConfig.segmentIntegrityAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
		}

		aggregateHash += segmentSig
		segmentInfo := Segment{
			Hash:          string(ocrypto.Base64Encode([]byte(segmentSig))),
			Size:          readSize,
			EncryptedSize: int64(len(cipherData)),
		}

		tdfObject.manifest.EncryptionInformation.IntegrityInformation.Segments =
			append(tdfObject.manifest.EncryptionInformation.IntegrityInformation.Segments, segmentInfo)

		totalSegments--
		readPos += readSize
	}

	rootSignature, err := calculateSignature([]byte(aggregateHash), tdfObject.payloadKey[:], tdfConfig.integrityAlgorithm)
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

		hashOfAssertion, err := tmpAssertion.GetHash()
		if err != nil {
			return nil, err
		}

		var completeHashBuilder strings.Builder
		completeHashBuilder.WriteString(aggregateHash)
		completeHashBuilder.Write(hashOfAssertion)

		encoded := ocrypto.Base64Encode([]byte(completeHashBuilder.String()))

		var assertionSigningKey = AssertionKey{}

		// Set default to HS256 and payload key
		assertionSigningKey.Alg = AssertionKeyAlgHS256
		assertionSigningKey.Key = tdfObject.payloadKey[:]

		if !assertion.SigningKey.IsEmpty() {
			assertionSigningKey = assertion.SigningKey
		}

		if err := tmpAssertion.Sign(string(hashOfAssertion), string(encoded), assertionSigningKey); err != nil {
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

	for _, splitInfo := range tdfConfig.splitPlan {
		// Public key was passed in with kasInfoList
		// TODO first look up in attribute information / add to split plan?
		ki, ok := latestKASInfo[splitInfo.KAS]
		if !ok || ki.PublicKey == "" {
			k, err := s.getPublicKey(ctx, splitInfo.KAS, "rsa:2048")
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
			gcm, err := ocrypto.NewAESGcm(symKey)
			if err != nil {
				return fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
			}

			emb, err := gcm.Encrypt([]byte(tdfConfig.metaData))
			if err != nil {
				return fmt.Errorf("ocrypto.AesGcm.encrypt failed:%w", err)
			}

			iv := emb[:ocrypto.GcmStandardNonceSize]
			metadata := EncryptedMetadata{
				Cipher: string(ocrypto.Base64Encode(emb)),
				Iv:     string(ocrypto.Base64Encode(iv)),
			}

			metadataJSON, err := json.Marshal(metadata)
			if err != nil {
				return fmt.Errorf(" json.Marshal failed:%w", err)
			}
			encryptedMetadata = string(ocrypto.Base64Encode(metadataJSON))
		}

		for _, kasInfo := range conjunction[splitID] {
			if len(kasInfo.PublicKey) == 0 {
				return fmt.Errorf("splitID:[%s], kas:[%s]: %w", splitID, kasInfo.URL, errKasPubKeyMissing)
			}

			// wrap the key with kas public key
			asymEncrypt, err := ocrypto.NewAsymEncryption(kasInfo.PublicKey)
			if err != nil {
				return fmt.Errorf("ocrypto.NewAsymEncryption failed:%w", err)
			}

			wrappedKey, err := asymEncrypt.Encrypt(symKey)
			if err != nil {
				return fmt.Errorf("ocrypto.AsymEncryption.encrypt failed:%w", err)
			}

			keyAccess := KeyAccess{
				KeyType:           kWrapped,
				KasURL:            kasInfo.URL,
				KID:               kasInfo.KID,
				Protocol:          kKasProtocol,
				PolicyBinding:     policyBinding,
				EncryptedMetadata: encryptedMetadata,
				SplitID:           splitID,
				WrappedKey:        string(ocrypto.Base64Encode(wrappedKey)),
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
		kasSessionKey: *s.config.kasSessionKey,
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

		payloadSig, err := calculateSignature(readBuf, r.payloadKey, sigAlg)
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
	var start = math.Floor(float64(offset) / float64(defaultSegmentSize))
	var end = math.Ceil(float64(offset+int64(len(buf))) / float64(defaultSegmentSize))

	firstSegment := int64(start)
	lastSegment := int64(end)
	if firstSegment > lastSegment {
		return 0, ErrTDFPayloadReadFail
	}

	if offset > r.payloadSize {
		return 0, ErrTDFPayloadReadFail
	}

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

		payloadSig, err := calculateSignature(readBuf, r.payloadKey, sigAlg)
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

Retrieve the payload key, either from performing an unwrap or from a previous unwrap,
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

// Unwraps the payload key, if possible, using the access service
func (r *Reader) doPayloadKeyUnwrap(ctx context.Context) error { //nolint:gocognit // Better readability keeping it as is
	var unencryptedMetadata []byte
	var payloadKey [kKeySize]byte
	knownSplits := make(map[string]bool)
	foundSplits := make(map[string]bool)
	skippedSplits := make(map[keySplitStep]error)
	mixedSplits := len(r.manifest.KeyAccessObjs) > 1 && r.manifest.KeyAccessObjs[0].SplitID != ""

	for _, keyAccessObj := range r.manifest.EncryptionInformation.KeyAccessObjs {
		client, err := newKASClient(r.dialOptions, r.tokenSource, r.kasSessionKey)
		if err != nil {
			return fmt.Errorf("newKASClient failed:%w", err)
		}

		ss := keySplitStep{KAS: keyAccessObj.KasURL, SplitID: keyAccessObj.SplitID}

		var wrappedKey []byte
		if !mixedSplits { //nolint:nestif // todo: subfunction
			wrappedKey, err = client.unwrap(ctx, keyAccessObj, r.manifest.EncryptionInformation.Policy)
			if err != nil {
				errToReturn := fmt.Errorf("doPayloadKeyUnwrap splitKey.rewrap failed: %w", err)
				if !strings.Contains(err.Error(), codes.InvalidArgument.String()) {
					return fmt.Errorf("%w: %w", ErrRewrapBadRequest, errToReturn)
				}
				if !strings.Contains(err.Error(), codes.PermissionDenied.String()) {
					return fmt.Errorf("%w: %w", errRewrapForbidden, errToReturn)
				}
				return errToReturn
			}
		} else {
			knownSplits[ss.SplitID] = true
			if foundSplits[ss.SplitID] {
				// already found
				continue
			}
			wrappedKey, err = client.unwrap(ctx, keyAccessObj, r.manifest.EncryptionInformation.Policy)
			if err != nil {
				errToReturn := fmt.Errorf("kao unwrap failed for split %v: %w", ss, err)
				if !strings.Contains(err.Error(), codes.InvalidArgument.String()) {
					skippedSplits[ss] = fmt.Errorf("%w: %w", ErrRewrapBadRequest, errToReturn)
				}
				if !strings.Contains(err.Error(), codes.PermissionDenied.String()) {
					skippedSplits[ss] = fmt.Errorf("%w: %w", errRewrapForbidden, errToReturn)
				}
				skippedSplits[ss] = errToReturn
				continue
			}
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

	if mixedSplits && len(knownSplits) > len(foundSplits) {
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

		if !r.config.AssertionVerificationKeys.IsEmpty() {
			// Look up the key for the assertion
			foundKey, err := r.config.AssertionVerificationKeys.Get(assertion.ID)

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
		hashOfAssertion, err := assertion.GetHash()
		if err != nil {
			return fmt.Errorf("%w: failed to get hash of assertion: %w", ErrAssertionFailure{ID: assertion.ID}, err)
		}

		var completeHashBuilder bytes.Buffer
		completeHashBuilder.Write(aggregateHash.Bytes())
		completeHashBuilder.Write(hashOfAssertion)

		base64Hash := ocrypto.Base64Encode(completeHashBuilder.Bytes())

		if string(hashOfAssertion) != assertionHash {
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

// calculateSignature calculate signature of data of the given algorithm.
func calculateSignature(data []byte, secret []byte, alg IntegrityAlgorithm) (string, error) {
	if alg == HS256 {
		hmac := ocrypto.CalculateSHA256Hmac(secret, data)
		return hex.EncodeToString(hmac), nil
	}
	if kGMACPayloadLength > len(data) {
		return "", fmt.Errorf("fail to create gmac signature")
	}

	return hex.EncodeToString(data[len(data)-kGMACPayloadLength:]), nil
}

// validate the root signature
func validateRootSignature(manifest Manifest, aggregateHash, secret []byte) (bool, error) {
	rootSigAlg := manifest.EncryptionInformation.IntegrityInformation.RootSignature.Algorithm
	rootSigValue := manifest.EncryptionInformation.IntegrityInformation.RootSignature.Signature

	sigAlg := HS256
	if strings.EqualFold(gmacIntegrityAlgorithm, rootSigAlg) {
		sigAlg = GMAC
	}

	sig, err := calculateSignature(aggregateHash, secret, sigAlg)
	if err != nil {
		return false, fmt.Errorf("splitkey.getSignature failed:%w", err)
	}

	if rootSigValue == string(ocrypto.Base64Encode([]byte(sig))) {
		return true, nil
	}

	return false, nil
}
