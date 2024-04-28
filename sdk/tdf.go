package sdk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/arkavo-org/opentdf-platform/lib/ocrypto"
	"github.com/arkavo-org/opentdf-platform/sdk/internal/archive"
	"github.com/google/uuid"
)

var (
	errFileTooLarge            = errors.New("tdf: can't create tdf larger than 64gb")
	errRootSigValidation       = errors.New("tdf: failed integrity check on root signature")
	errSegSizeMismatch         = errors.New("tdf: mismatch encrypted segment size in manifest")
	errTDFReaderFailed         = errors.New("tdf: fail to read bytes from TDFReader")
	errWriteFailed             = errors.New("tdf: io.writer fail to write all bytes")
	errSegSigValidation        = errors.New("tdf: failed integrity check on segment hash")
	errTDFPayloadReadFail      = errors.New("tdf: fail to read payload from tdf")
	errInvalidKasInfo          = errors.New("tdf: kas information is missing")
	errKasPubKeyMissing        = errors.New("tdf: kas public key is missing")
	errTDFPayloadInvalidOffset = errors.New("sdk.Reader.ReadAt: negative offset")
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
	kClientPublicKey        = "clientPublicKey"
	kSignedRequestToken     = "signedRequestToken"
	kKasURL                 = "url"
	kRewrapV2               = "kas/v2/rewrap"
	kAuthorizationKey       = "Authorization"
	kContentTypeKey         = "Content-Type"
	kAcceptKey              = "Accept"
	kContentTypeJSONValue   = "application/json"
	kEntityWrappedKey       = "entityWrappedKey"
	kPolicy                 = "policy"
	kHmacIntegrityAlgorithm = "HS256"
	kGmacIntegrityAlgorithm = "GMAC"
)

type Reader struct {
	manifest            Manifest
	unencryptedMetadata []byte
	tdfReader           archive.TDFReader
	unwrapper           Unwrapper
	cursor              int64
	aesGcm              ocrypto.AesGcm
	payloadSize         int64
	payloadKey          []byte
}

type TDFObject struct {
	manifest   Manifest
	size       int64
	aesGcm     ocrypto.AesGcm
	payloadKey [kKeySize]byte
}

type Unwrapper interface {
	unwrap(keyAccess KeyAccess, policy string) ([]byte, error)
	getPublicKey(kas KASInfo) (string, error)
}

// CreateTDF reads plain text from the given reader and saves it to the writer, subject to the given options
func (s SDK) CreateTDF(writer io.Writer, reader io.ReadSeeker, opts ...TDFOption) (*TDFObject, error) { //nolint:funlen, gocognit, lll // Better readability keeping it as is
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

	tdfConfig, err := NewTDFConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("NewTDFConfig failed: %w", err)
	}

	err = fillInPublicKeys(s.unwrapper, tdfConfig.kasInfoList)
	if err != nil {
		return nil, err
	}

	tdfObject := &TDFObject{}
	err = tdfObject.prepareManifest(*tdfConfig)
	if err != nil {
		return nil, fmt.Errorf("fail to create a new split key: %w", err)
	}

	segmentSize := tdfConfig.defaultSegmentSize
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
			return nil, fmt.Errorf("io.ReadSeeker.Read size missmatch")
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
	tdfObject.manifest.Payload.MimeType = defaultMimeType
	tdfObject.manifest.Payload.Protocol = tdfAsZip
	tdfObject.manifest.Payload.Type = tdfZipReference
	tdfObject.manifest.Payload.URL = archive.TDFPayloadFileName
	tdfObject.manifest.Payload.IsEncrypted = true

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
func (t *TDFObject) prepareManifest(tdfConfig TDFConfig) error { //nolint:funlen,gocognit // Better readability keeping it as is
	manifest := Manifest{}
	if len(tdfConfig.kasInfoList) == 0 {
		return errInvalidKasInfo
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
	symKeys := make([][]byte, 0, len(tdfConfig.kasInfoList))
	for _, kasInfo := range tdfConfig.kasInfoList {
		if len(kasInfo.PublicKey) == 0 {
			return errKasPubKeyMissing
		}

		symKey, err := ocrypto.RandomBytes(kKeySize)
		if err != nil {
			return fmt.Errorf("ocrypto.RandomBytes failed:%w", err)
		}

		keyAccess := KeyAccess{}
		keyAccess.KeyType = kWrapped
		keyAccess.KasURL = kasInfo.URL
		keyAccess.Protocol = kKasProtocol

		// add policyBinding
		policyBinding := hex.EncodeToString(ocrypto.CalculateSHA256Hmac(symKey, base64PolicyObject))
		keyAccess.PolicyBinding = string(ocrypto.Base64Encode([]byte(policyBinding)))

		// wrap the key with kas public key
		asymEncrypt, err := ocrypto.NewAsymEncryption(kasInfo.PublicKey)
		if err != nil {
			return fmt.Errorf("ocrypto.NewAsymEncryption failed:%w", err)
		}

		wrappedKey, err := asymEncrypt.Encrypt(symKey)
		if err != nil {
			return fmt.Errorf("ocrypto.AsymEncryption.encrypt failed:%w", err)
		}
		keyAccess.WrappedKey = string(ocrypto.Base64Encode(wrappedKey))

		// add meta data
		if len(tdfConfig.metaData) > 0 {
			gcm, err := ocrypto.NewAESGcm(symKey)
			if err != nil {
				return fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
			}

			encryptedMetaData, err := gcm.Encrypt([]byte(tdfConfig.metaData))
			if err != nil {
				return fmt.Errorf("ocrypto.AesGcm.encrypt failed:%w", err)
			}

			iv := encryptedMetaData[:ocrypto.GcmStandardNonceSize]
			metadata := EncryptedMetadata{
				Cipher: string(ocrypto.Base64Encode(encryptedMetaData)),
				Iv:     string(ocrypto.Base64Encode(iv)),
			}

			metadataJSON, err := json.Marshal(metadata)
			if err != nil {
				return fmt.Errorf(" json.Marshal failed:%w", err)
			}

			keyAccess.EncryptedMetadata = string(ocrypto.Base64Encode(metadataJSON))
		}

		symKeys = append(symKeys, symKey)
		manifest.EncryptionInformation.KeyAccessObjs = append(manifest.EncryptionInformation.KeyAccessObjs, keyAccess)
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
func createPolicyObject(attributes []string) (PolicyObject, error) {
	uuidObj, err := uuid.NewUUID()
	if err != nil {
		return PolicyObject{}, fmt.Errorf("uuid.NewUUID failed: %w", err)
	}

	policyObj := PolicyObject{}
	policyObj.UUID = uuidObj.String()

	for _, attribute := range attributes {
		attributeObj := attributeObject{}
		attributeObj.Attribute = attribute
		policyObj.Body.DataAttributes = append(policyObj.Body.DataAttributes, attributeObj)
		policyObj.Body.Dissem = make([]string, 0)
	}

	return policyObj, nil
}

// LoadTDF loads the tdf and prepare for reading the payload from TDF
func (s SDK) LoadTDF(reader io.ReadSeeker) (*Reader, error) {
	// create tdf reader
	tdfReader, err := archive.NewTDFReader(reader)
	if err != nil {
		return nil, fmt.Errorf("archive.NewTDFReader failed: %w", err)
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
		tdfReader: tdfReader,
		manifest:  *manifestObj,
		unwrapper: s.unwrapper,
	}, nil
}

// Read reads up to len(p) bytes into p. It returns the number of bytes
// read (0 <= n <= len(p)) and any error encountered. It returns an
// io.EOF error when the stream ends.
func (r *Reader) Read(p []byte) (int, error) {
	if r.payloadKey == nil {
		err := r.doPayloadKeyUnwrap()
		if err != nil {
			return 0, fmt.Errorf("reader.doPayloadKeyUnwrap failed: %w", err)
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
		err := r.doPayloadKeyUnwrap()
		if err != nil {
			return 0, fmt.Errorf("reader.doPayloadKeyUnwrap failed: %w", err)
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
			return totalBytes, errTDFReaderFailed
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
			return totalBytes, errSegSigValidation
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
		err := r.doPayloadKeyUnwrap()
		if err != nil {
			return 0, fmt.Errorf("reader.doPayloadKeyUnwrap failed: %w", err)
		}
	}

	if offset < 0 {
		return 0, errTDFPayloadInvalidOffset
	}

	defaultSegmentSize := r.manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize
	var start = math.Floor(float64(offset) / float64(defaultSegmentSize))
	var end = math.Ceil(float64(offset+int64(len(buf))) / float64(defaultSegmentSize))

	// slog.Debug("Invoked ReadAt", slog.Int("bufsize", len(buf)), slog.Int("offset", int(offset)))

	firstSegment := int64(start)
	lastSegment := int64(end)
	if firstSegment > lastSegment {
		return 0, errTDFPayloadReadFail
	}

	if offset > r.payloadSize {
		return 0, errTDFPayloadReadFail
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
			return 0, errTDFReaderFailed
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
			return 0, errSegSigValidation
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
		err := r.doPayloadKeyUnwrap()
		if err != nil {
			return nil, fmt.Errorf("reader.doPayloadKeyUnwrap failed: %w", err)
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

// Unwraps the payload key, if possible, using the access service
func (r *Reader) doPayloadKeyUnwrap() error { //nolint:gocognit // Better readability keeping it as is
	var unencryptedMetadata []byte
	var payloadKey [kKeySize]byte
	for _, keyAccessObj := range r.manifest.EncryptionInformation.KeyAccessObjs {
		wrappedKey, err := r.unwrapper.unwrap(keyAccessObj, r.manifest.EncryptionInformation.Policy)
		if err != nil {
			return fmt.Errorf(" splitKey.rewrap failed:%w", err)
		}

		for keyByteIndex, keyByte := range wrappedKey {
			payloadKey[keyByteIndex] ^= keyByte
		}

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

	res, err := validateRootSignature(r.manifest, payloadKey[:])
	if err != nil {
		return fmt.Errorf("splitKey.validateRootSignature failed: %w", err)
	}

	if !res {
		return errRootSigValidation
	}

	segSize := r.manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize
	encryptedSegSize := r.manifest.EncryptionInformation.IntegrityInformation.DefaultEncryptedSegSize

	if segSize != encryptedSegSize-(gcmIvSize+aesBlockSize) {
		return errSegSizeMismatch
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
func validateRootSignature(manifest Manifest, secret []byte) (bool, error) {
	rootSigAlg := manifest.EncryptionInformation.IntegrityInformation.RootSignature.Algorithm
	rootSigValue := manifest.EncryptionInformation.IntegrityInformation.RootSignature.Signature

	aggregateHash := &bytes.Buffer{}
	for _, segment := range manifest.EncryptionInformation.IntegrityInformation.Segments {
		decodedHash, err := ocrypto.Base64Decode([]byte(segment.Hash))
		if err != nil {
			return false, fmt.Errorf("ocrypto.Base64Decode failed:%w", err)
		}

		aggregateHash.Write(decodedHash)
	}

	sigAlg := HS256
	if strings.EqualFold(gmacIntegrityAlgorithm, rootSigAlg) {
		sigAlg = GMAC
	}

	sig, err := calculateSignature(aggregateHash.Bytes(), secret, sigAlg)
	if err != nil {
		return false, fmt.Errorf("splitkey.getSignature failed:%w", err)
	}

	if rootSigValue == string(ocrypto.Base64Encode([]byte(sig))) {
		return true, nil
	}

	return false, nil
}

func fillInPublicKeys(unwrapper Unwrapper, kasInfos []KASInfo) error {
	for idx, kasInfo := range kasInfos {
		if kasInfo.PublicKey != "" {
			continue
		}

		publicKey, err := unwrapper.getPublicKey(kasInfo)
		if err != nil {
			return fmt.Errorf("unable to retrieve public key from KAS at [%s]: %w", kasInfo.URL, err)
		}

		kasInfos[idx].PublicKey = publicKey
	}
	return nil
}
