package sdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/opentdf/opentdf-v2-poc/internal/archive"
	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
	"io"
	"strings"
)

var (
	errFileTooLarge      = errors.New("tdf: can't create tdf larger than 64gb")
	errRootSigValidation = errors.New("tdf: failed integrity check on root signature")
	errSegSizeMismatch   = errors.New("tdf: mismatch encrypted segment size in manifest")
	errTDFReaderFailed   = errors.New("tdf: fail to read bytes from TDFReader")
	errWriteFailed       = errors.New("tdf: io.writer fail to write all bytes")
	errSegSigValidation  = errors.New("tdf: Failed integrity check on segment hash")
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

// Create tdf
func Create(tdfConfig TDFConfig, reader io.ReadSeeker, writer io.Writer) (int64, error) {
	toalBytes := int64(0)
	inputSize, err := reader.Seek(0, io.SeekEnd)
	if err != nil {
		return toalBytes, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	_, err = reader.Seek(0, io.SeekStart)
	if err != nil {
		return toalBytes, fmt.Errorf("readSeeker.Seek failed: %w", err)
	}

	if inputSize > maxFileSizeSupported {
		return toalBytes, errFileTooLarge
	}

	// create a split key
	splitKey, err := newSplitKeyFromKasInfo(tdfConfig.kasInfoList, tdfConfig.attributes, tdfConfig.metaData)
	if err != nil {
		return toalBytes, fmt.Errorf("fail to create a new split key: %w", err)
	}

	manifest, err := splitKey.getManifest()
	if err != nil {
		return toalBytes, fmt.Errorf("fail to create manifest: %w", err)
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
		return toalBytes, fmt.Errorf("archive.SetPayloadSize failed: %w", err)
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
			return toalBytes, fmt.Errorf("io.ReadSeeker.Read failed: %w", err)
		}

		if int64(n) != readSize {
			return toalBytes, fmt.Errorf("io.ReadSeeker.Read size missmatch")
		}

		cipherData, err := splitKey.encrypt(readBuf.Bytes()[:readSize])
		if err != nil {
			return toalBytes, fmt.Errorf("io.ReadSeeker.Read failed: %w", err)
		}

		err = tdfWriter.AppendPayload(cipherData)
		if err != nil {
			return toalBytes, fmt.Errorf("io.writer.Write failed: %w", err)
		}

		payloadSig, err := splitKey.getSignature(cipherData, tdfConfig.segmentIntegrityAlgorithm)
		if err != nil {
			return toalBytes, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
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
		return toalBytes, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
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
		return toalBytes, fmt.Errorf("json.Marshal failed:%w", err)
	}

	err = tdfWriter.AppendManifest(string(manifestAsStr))
	if err != nil {
		return toalBytes, fmt.Errorf("TDFWriter.AppendManifest failed:%w", err)
	}

	totalBytes, err := tdfWriter.Finish()
	if err != nil {
		return toalBytes, fmt.Errorf("TDFWriter.Finish failed:%w", err)
	}

	return totalBytes, nil
}

// GetPayload decrypt the tdf and write the data to writer.
func GetPayload(authConfig AuthConfig, reader io.ReadSeeker, writer io.Writer) (int64, error) {

	totalBytes := int64(0)

	// create tdf reader
	tdfReader, err := archive.NewTDFReader(reader)
	if err != nil {
		return totalBytes, fmt.Errorf("archive.NewTDFReader failed: %w", err)
	}

	manifest, err := tdfReader.Manifest()
	if err != nil {
		return totalBytes, fmt.Errorf("tdfReader.Manifest failed: %w", err)
	}

	manifestObj := &Manifest{}
	err = json.Unmarshal([]byte(manifest), manifestObj)
	if err != nil {
		return totalBytes, fmt.Errorf("json.Unmarshal failed:%w", err)
	}

	// create a split key
	sKey, err := newSplitKeyFromManifest(authConfig, *manifestObj)
	if err != nil {
		return totalBytes, fmt.Errorf("fail to create a new split key: %w", err)
	}

	res, err := sKey.validateRootSignature(manifestObj)
	if err != nil {
		return totalBytes, fmt.Errorf("splitKey.validateRootSignature failed: %w", err)
	}

	if !res {
		return totalBytes, errRootSigValidation
	}

	segSize := manifestObj.EncryptionInformation.IntegrityInformation.DefaultSegmentSize
	encryptedSegSize := manifestObj.EncryptionInformation.IntegrityInformation.DefaultEncryptedSegSize

	if segSize != encryptedSegSize-(gcmIvSize+aesBlockSize) {
		return totalBytes, errSegSizeMismatch
	}

	var payloadReadOffset int64
	for _, seg := range manifestObj.EncryptionInformation.IntegrityInformation.Segments {
		readBuf, err := tdfReader.ReadPayload(payloadReadOffset, seg.EncryptedSize)
		if err != nil {
			return totalBytes, fmt.Errorf("TDFReader.ReadPayload failed: %w", err)
		}

		if int64(len(readBuf)) != seg.EncryptedSize {
			return totalBytes, errTDFReaderFailed
		}

		segHashAlg := manifestObj.EncryptionInformation.IntegrityInformation.SegmentHashAlgorithm
		sigAlg := HS256
		if strings.EqualFold(gmacIntegrityAlgorithm, segHashAlg) {
			sigAlg = GMAC
		}

		payloadSig, err := sKey.getSignature(readBuf, sigAlg)
		if err != nil {
			return totalBytes, fmt.Errorf("splitKey.GetSignaturefailed: %w", err)
		}

		if seg.Hash != string(crypto.Base64Encode([]byte(payloadSig))) {
			return totalBytes, errSegSigValidation
		}

		writeBuf, err := sKey.decrypt(readBuf)
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

// GetMetadata return the meta present in tdf.
func GetMetadata(authConfig AuthConfig, reader io.ReadSeeker) (string, error) {
	// create tdf reader
	tdfReader, err := archive.NewTDFReader(reader)
	if err != nil {
		return "", fmt.Errorf("archive.NewTDFReader failed: %w", err)
	}

	manifest, err := tdfReader.Manifest()
	if err != nil {
		return "", fmt.Errorf("tdfReader.Manifest failed: %w", err)
	}

	manifestObj := &Manifest{}
	err = json.Unmarshal([]byte(manifest), manifestObj)
	if err != nil {
		return "", fmt.Errorf("json.Unmarshal failed:%w", err)
	}

	// create a split key
	sKey, err := newSplitKeyFromManifest(authConfig, *manifestObj)
	if err != nil {
		return "", fmt.Errorf("fail to create a new split key: %w", err)
	}

	// There will be at least one key access in tdf
	return sKey.tdfKeyAccessObjects[0].metaData, nil
}

// GetAttributes return the attributes present in tdf.
func GetAttributes(reader io.ReadSeeker) ([]string, error) {
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

	policy, err := crypto.Base64Decode([]byte(manifestObj.Policy))
	if err != nil {
		return nil, fmt.Errorf("crypto.Base64Decode failed:%w", err)
	}

	return attributesFromPolicy(policy)
}

func attributesFromPolicy(policy []byte) ([]string, error) {
	policyObj := policyObject{}
	err := json.Unmarshal(policy, &policyObj)
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
