package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/opentdf/opentdf-v2-poc/sdk/internal/archive"
	"github.com/opentdf/opentdf-v2-poc/sdk/internal/crypto"
)

var (
	errFileTooLarge            = errors.New("tdf: can't create tdf larger than 64gb")
	errRootSigValidation       = errors.New("tdf: failed integrity check on root signature")
	errSegSizeMismatch         = errors.New("tdf: mismatch encrypted segment size in manifest")
	errTDFReaderFailed         = errors.New("tdf: fail to read bytes from TDFReader")
	errWriteFailed             = errors.New("tdf: io.writer fail to write all bytes")
	errSegSigValidation        = errors.New("tdf: failed integrity check on segment hash")
	errTDFPayloadReadFail      = errors.New("tdf: fail to read payload from tdf")
	errTDFPayloadInvalidOffset = errors.New("sdk.Reader.ReadAt: negative offset")
)

const (
	maxFileSizeSupported   = 68719476736 // 64gb
	defaultMimeType        = "application/octet-stream"
	tdfAsZip               = "zip"
	gcmIvSize              = 12
	aesBlockSize           = 16
	hmacIntegrityAlgorithm = "HS256"
	gmacIntegrityAlgorithm = "GMAC"
	tdfZipReference        = "reference"
)

type Reader struct {
	tdfReader   archive.TDFReader
	sKey        splitKey
	cursor      int64
	payloadSize int64
	manifest    Manifest
}

// CreateTDF tdf
func CreateTDF(tdfConfig TDFConfig, reader io.ReadSeeker, writer io.Writer) (int64, error) {

	inputSize, err := reader.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	if inputSize > maxFileSizeSupported {
		return 0, errFileTooLarge
	}

	// create a split key
	splitKey, err := newSplitKeyFromKasInfo(tdfConfig.kasInfoList, tdfConfig.attributes, tdfConfig.metaData)
	if err != nil {
		return 0, fmt.Errorf("fail to create a new split key: %w", err)
	}

	manifest, err := splitKey.getManifest()
	if err != nil {
		return 0, fmt.Errorf("fail to create manifest: %w", err)
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
		return 0, fmt.Errorf("archive.SetPayloadSize failed: %w", err)
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
			return 0, fmt.Errorf("io.ReadSeeker.Read failed: %w", err)
		}

		if int64(n) != readSize {
			return 0, fmt.Errorf("io.ReadSeeker.Read size missmatch")
		}

		cipherData, err := splitKey.encrypt(readBuf.Bytes()[:readSize])
		if err != nil {
			return 0, fmt.Errorf("io.ReadSeeker.Read failed: %w", err)
		}

		err = tdfWriter.AppendPayload(cipherData)
		if err != nil {
			return 0, fmt.Errorf("io.writer.Write failed: %w", err)
		}

		payloadSig, err := splitKey.getSignature(cipherData, tdfConfig.segmentIntegrityAlgorithm)
		if err != nil {
			return 0, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
		}

		aggregateHash += payloadSig

		segmentInfo := Segment{}
		segmentInfo.Hash = string(crypto.Base64Encode([]byte(payloadSig)))
		segmentInfo.Size = readSize
		segmentInfo.EncryptedSize = int64(len(cipherData))
		manifest.EncryptionInformation.IntegrityInformation.Segments =
			append(manifest.EncryptionInformation.IntegrityInformation.Segments, segmentInfo)

		totalSegments--
		readPos += readSize
	}

	aggregateHashSig, err := splitKey.getSignature([]byte(aggregateHash), tdfConfig.integrityAlgorithm)
	if err != nil {
		return 0, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
	}

	sig := string(crypto.Base64Encode([]byte(aggregateHashSig)))
	manifest.EncryptionInformation.IntegrityInformation.RootSignature.Signature = sig

	integrityAlgStr := gmacIntegrityAlgorithm
	if tdfConfig.integrityAlgorithm == HS256 {
		integrityAlgStr = hmacIntegrityAlgorithm
	}
	manifest.EncryptionInformation.IntegrityInformation.RootSignature.Algorithm = integrityAlgStr

	manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize = segmentSize
	manifest.EncryptionInformation.IntegrityInformation.DefaultEncryptedSegSize = encryptedSegmentSize

	segIntegrityAlgStr := gmacIntegrityAlgorithm
	if tdfConfig.segmentIntegrityAlgorithm == HS256 {
		segIntegrityAlgStr = hmacIntegrityAlgorithm
	}

	manifest.EncryptionInformation.IntegrityInformation.SegmentHashAlgorithm = segIntegrityAlgStr
	manifest.EncryptionInformation.Method.IsStreamable = true

	// add payload info
	manifest.Payload.MimeType = defaultMimeType
	manifest.Payload.Protocol = tdfAsZip
	manifest.Payload.Type = tdfZipReference
	manifest.Payload.URL = archive.TDFPayloadFileName
	manifest.Payload.IsEncrypted = true

	manifestAsStr, err := json.Marshal(manifest)
	if err != nil {
		return 0, fmt.Errorf("json.Marshal failed:%w", err)
	}

	err = tdfWriter.AppendManifest(string(manifestAsStr))
	if err != nil {
		return 0, fmt.Errorf("TDFWriter.AppendManifest failed:%w", err)
	}

	totalBytes, err := tdfWriter.Finish()
	if err != nil {
		return 0, fmt.Errorf("TDFWriter.Finish failed:%w", err)
	}

	return totalBytes, nil
}

func NewReader(authConfig AuthConfig, reader io.ReadSeeker) (*Reader, error) {
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

	// create a split key
	sKey, err := newSplitKeyFromManifest(authConfig, *manifestObj)
	if err != nil {
		return nil, fmt.Errorf("fail to create a new split key: %w", err)
	}

	res, err := sKey.validateRootSignature(manifestObj)
	if err != nil {
		return nil, fmt.Errorf("splitKey.validateRootSignature failed: %w", err)
	}

	if !res {
		return nil, errRootSigValidation
	}

	segSize := manifestObj.EncryptionInformation.IntegrityInformation.DefaultSegmentSize
	encryptedSegSize := manifestObj.EncryptionInformation.IntegrityInformation.DefaultEncryptedSegSize

	if segSize != encryptedSegSize-(gcmIvSize+aesBlockSize) {
		return nil, errSegSizeMismatch
	}

	var payloadSize int64
	for _, seg := range manifestObj.EncryptionInformation.IntegrityInformation.Segments {
		payloadSize += seg.Size
	}

	return &Reader{
		tdfReader:   tdfReader,
		manifest:    *manifestObj,
		payloadSize: payloadSize,
		sKey:        sKey,
	}, nil
}

// Read reads up to len(p) bytes into p. It returns the number of bytes
// read (0 <= n <= len(p)) and any error encountered. It returns an
// io.EOF error when the stream ends.
func (reader *Reader) Read(p []byte) (int, error) {
	n, err := reader.ReadAt(p, reader.cursor)
	reader.cursor += int64(n)
	return n, err
}

// WriteTo writes data to writer until there's no more data to write or
// when an error occurs.
func (reader *Reader) WriteTo(writer io.Writer) (n int64, err error) {
	var totalBytes int64
	var payloadReadOffset int64
	for _, seg := range reader.manifest.EncryptionInformation.IntegrityInformation.Segments {
		readBuf, err := reader.tdfReader.ReadPayload(payloadReadOffset, seg.EncryptedSize)
		if err != nil {
			return totalBytes, fmt.Errorf("TDFReader.ReadPayload failed: %w", err)
		}

		if int64(len(readBuf)) != seg.EncryptedSize {
			return totalBytes, errTDFReaderFailed
		}

		segHashAlg := reader.manifest.EncryptionInformation.IntegrityInformation.SegmentHashAlgorithm
		sigAlg := HS256
		if strings.EqualFold(gmacIntegrityAlgorithm, segHashAlg) {
			sigAlg = GMAC
		}

		payloadSig, err := reader.sKey.getSignature(readBuf, sigAlg)
		if err != nil {
			return totalBytes, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
		}

		if seg.Hash != string(crypto.Base64Encode([]byte(payloadSig))) {
			return totalBytes, errSegSigValidation
		}

		writeBuf, err := reader.sKey.decrypt(readBuf)
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
func (reader *Reader) ReadAt(buf []byte, offset int64) (int, error) {

	if offset < 0 {
		return 0, errTDFPayloadInvalidOffset
	}

	defaultSegmentSize := reader.manifest.EncryptionInformation.IntegrityInformation.DefaultSegmentSize
	var start = math.Floor(float64(offset) / float64(defaultSegmentSize))
	var end = math.Ceil(float64(offset+int64(len(buf))) / float64(defaultSegmentSize))

	// slog.Debug("Invoked ReadAt", slog.Int("bufsize", len(buf)), slog.Int("offset", int(offset)))

	firstSegment := int64(start)
	lastSegment := int64(end)
	if firstSegment > lastSegment {
		return 0, errTDFPayloadReadFail
	}

	if offset > reader.payloadSize {
		return 0, errTDFPayloadReadFail
	}

	var decryptedBuf bytes.Buffer
	var payloadReadOffset int64
	for index, seg := range reader.manifest.EncryptionInformation.IntegrityInformation.Segments {
		if firstSegment > int64(index) {
			payloadReadOffset += seg.EncryptedSize
			continue
		}

		readBuf, err := reader.tdfReader.ReadPayload(payloadReadOffset, seg.EncryptedSize)
		if err != nil {
			return 0, fmt.Errorf("TDFReader.ReadPayload failed: %w", err)
		}

		if int64(len(readBuf)) != seg.EncryptedSize {
			return 0, errTDFReaderFailed
		}

		segHashAlg := reader.manifest.EncryptionInformation.IntegrityInformation.SegmentHashAlgorithm
		sigAlg := HS256
		if strings.EqualFold(gmacIntegrityAlgorithm, segHashAlg) {
			sigAlg = GMAC
		}

		payloadSig, err := reader.sKey.getSignature(readBuf, sigAlg)
		if err != nil {
			return 0, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
		}

		if seg.Hash != string(crypto.Base64Encode([]byte(payloadSig))) {
			return 0, errSegSigValidation
		}

		writeBuf, err := reader.sKey.decrypt(readBuf)
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

	var err error = nil
	bufLen := int64(len(buf))
	if (offset + int64(len(buf))) > reader.payloadSize {
		bufLen = reader.payloadSize - offset
		err = io.EOF
	}

	startIndex := offset - (firstSegment * defaultSegmentSize)
	copy(buf[:bufLen], decryptedBuf.Bytes()[startIndex:startIndex+bufLen])
	return int(bufLen), err
}

// Manifest return the manifest as json string.
func (reader *Reader) Manifest() (string, error) {
	manifestAsStr, err := json.Marshal(reader.manifest)
	if err != nil {
		return "", fmt.Errorf("json.Marshal failed:%w", err)
	}

	return string(manifestAsStr), nil
}

// UnencryptedMetadata return the meta present in tdf.
func (reader *Reader) UnencryptedMetadata() string {
	// There will be at least one key access in tdf
	return reader.sKey.tdfKeyAccessObjects[0].metaData
}

// DataAttributes return the data attributes present in tdf.
func (reader *Reader) DataAttributes() ([]string, error) {
	policy, err := crypto.Base64Decode([]byte(reader.manifest.Policy))
	if err != nil {
		return nil, fmt.Errorf("crypto.Base64Decode failed:%w", err)
	}

	policyObj := policyObject{}
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
