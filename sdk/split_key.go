package sdk

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
)

const (
	kKeySize                = 32
	kWrapped                = "wrapped"
	kKasProtocol            = "kas"
	kSplitKeyType           = "split"
	kGCMCipherAlgorithm     = "AES-256-GCM"
	kGMACPayloadLength      = 16
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

type rewrapJWTClaims struct {
	jwt.RegisteredClaims
	Body string `json:"requestBody"`
}

type splitKey struct {
	attributes          []string
	tdfKeyAccessObjects []tdfKeyAccess
	kasInfoList         []KASInfo
	key                 [kKeySize]byte
	aesGcm              crypto.AesGcm
}

type tdfKeyAccess struct {
	kasPublicKey string
	kasURL       string
	wrappedKey   [kKeySize]byte
	metaData     string
}

var (
	errInvalidKasInfo   = errors.New("split-key: kas information is missing")
	errKasPubKeyMissing = errors.New("split-key: kas public key is missing")
)

// newSplitKeyFromKasInfo create a instance of split key object.
func newSplitKeyFromKasInfo(kasInfoList []KASInfo, attributes []string, metaData string) (splitKey, error) {
	if len(kasInfoList) == 0 {
		return splitKey{}, errInvalidKasInfo
	}

	tdfKeyAccessObjs := make([]tdfKeyAccess, 0)
	for _, kasInfo := range kasInfoList {
		if len(kasInfo.publicKey) == 0 {
			return splitKey{}, errKasPubKeyMissing
		}

		keyAccess := tdfKeyAccess{}
		keyAccess.kasPublicKey = kasInfo.publicKey
		keyAccess.kasURL = kasInfo.url
		keyAccess.metaData = metaData

		key, err := crypto.RandomBytes(kKeySize)
		if err != nil {
			return splitKey{}, fmt.Errorf("crypto.RandomBytes failed:%w", err)
		}

		keyAccess.wrappedKey = [kKeySize]byte(key)
		tdfKeyAccessObjs = append(tdfKeyAccessObjs, keyAccess)
	}

	sKey := splitKey{}

	// create the split key by XOR all the keys in key access object.
	for _, keyAccessObj := range tdfKeyAccessObjs {
		for keyByteIndex, keyByte := range keyAccessObj.wrappedKey {
			sKey.key[keyByteIndex] ^= keyByte
		}
	}

	gcm, err := crypto.NewAESGcm(sKey.key[:])
	if err != nil {
		return splitKey{}, fmt.Errorf(" crypto.NewAESGcm failed:%w", err)
	}

	sKey.attributes = attributes
	sKey.tdfKeyAccessObjects = tdfKeyAccessObjs
	sKey.kasInfoList = kasInfoList
	sKey.aesGcm = gcm

	return sKey, nil
}

// newSplitKeyFromManifest create a instance of split key from(parsing) the manifest.
func newSplitKeyFromManifest(unwrapper Unwrapper, manifest Manifest) (splitKey, error) {
	sKey := splitKey{}

	for _, keyAccessObj := range manifest.EncryptionInformation.KeyAccessObjs {
		key, err := unwrapper.Unwrap(keyAccessObj, manifest.EncryptionInformation.Policy)
		if err != nil {
			return splitKey{}, fmt.Errorf(" splitKey.rewrap failed:%w", err)
		}

		for keyByteIndex, keyByte := range key {
			sKey.key[keyByteIndex] ^= keyByte
		}

		keyAccess := tdfKeyAccess{}
		keyAccess.kasURL = keyAccessObj.KasURL
		keyAccess.wrappedKey = [32]byte(key)

		if len(keyAccessObj.EncryptedMetadata) != 0 {
			gcm, err := crypto.NewAESGcm(key)
			if err != nil {
				return splitKey{}, fmt.Errorf("crypto.NewAESGcm failed:%w", err)
			}

			decodedMetaData, err := crypto.Base64Decode([]byte(keyAccessObj.EncryptedMetadata))
			if err != nil {
				return splitKey{}, fmt.Errorf("crypto.Base64Decode failed:%w", err)
			}

			metaData, err := gcm.Decrypt(decodedMetaData)
			if err != nil {
				return splitKey{}, fmt.Errorf("crypto.AesGcm.encrypt failed:%w", err)
			}

			keyAccess.metaData = string(metaData)
		}

		sKey.tdfKeyAccessObjects = append(sKey.tdfKeyAccessObjects, keyAccess)
	}

	gcm, err := crypto.NewAESGcm(sKey.key[:])
	if err != nil {
		return splitKey{}, fmt.Errorf(" crypto.NewAESGcm failed:%w", err)
	}
	sKey.aesGcm = gcm

	return sKey, nil
}

// getManifest Return the manifest.
func (splitKey splitKey) getManifest() (*Manifest, error) {
	manifest := Manifest{}
	manifest.EncryptionInformation.KeyAccessType = kSplitKeyType

	policyObj, err := splitKey.createPolicyObject()
	if err != nil {
		return nil, fmt.Errorf("fail to create policy object:%w", err)
	}

	policyObjectAsStr, err := json.Marshal(policyObj)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed:%w", err)
	}

	base64PolicyObject := crypto.Base64Encode(policyObjectAsStr)

	for _, keyAccessObj := range splitKey.tdfKeyAccessObjects {
		keyAccess := KeyAccess{}
		keyAccess.KeyType = kWrapped
		keyAccess.KasURL = keyAccessObj.kasURL
		keyAccess.Protocol = kKasProtocol

		// wrap the key with kas public key
		asymEncrypt, err := crypto.NewAsymEncryption(keyAccessObj.kasPublicKey)
		if err != nil {
			return nil, fmt.Errorf("crypto.NewAsymEncryption failed:%w", err)
		}

		encryptData, err := asymEncrypt.Encrypt(keyAccessObj.wrappedKey[:])
		if err != nil {
			return nil, fmt.Errorf("crypto.AsymEncryption.encrypt failed:%w", err)
		}
		keyAccess.WrappedKey = string(crypto.Base64Encode(encryptData))

		// add policyBinding
		policyBinding := hex.EncodeToString(crypto.CalculateSHA256Hmac(keyAccessObj.wrappedKey[:], base64PolicyObject))
		keyAccess.PolicyBinding = string(crypto.Base64Encode([]byte(policyBinding)))

		// add meta data
		if len(keyAccessObj.metaData) > 0 {
			gcm, err := crypto.NewAESGcm(keyAccessObj.wrappedKey[:])
			if err != nil {
				return nil, fmt.Errorf("crypto.NewAESGcm failed:%w", err)
			}

			encryptedMetaData, err := gcm.Encrypt([]byte(keyAccessObj.metaData))
			if err != nil {
				return nil, fmt.Errorf("crypto.AesGcm.encrypt failed:%w", err)
			}

			keyAccess.EncryptedMetadata = string(crypto.Base64Encode(encryptedMetaData))
		}

		manifest.EncryptionInformation.KeyAccessObjs = append(manifest.EncryptionInformation.KeyAccessObjs, keyAccess)
	}

	manifest.EncryptionInformation.Policy = string(base64PolicyObject)
	manifest.EncryptionInformation.Method.Algorithm = kGCMCipherAlgorithm

	return &manifest, nil
}

// encrypt the data using the split key.
func (splitKey splitKey) encrypt(data []byte) ([]byte, error) {
	buf, err := splitKey.aesGcm.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("AesGcm.encrypt failed:%w", err)
	}

	return buf, nil
}

// decrypt the data using the split key.
func (splitKey splitKey) decrypt(data []byte) ([]byte, error) {
	buf, err := splitKey.aesGcm.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("AesGcm.Decrypt failed:%w", err)
	}

	return buf, nil
}

func (splitKey splitKey) validateRootSignature(manifest *Manifest) (bool, error) {
	rootSigAlg := manifest.EncryptionInformation.IntegrityInformation.RootSignature.Algorithm
	rootSigValue := manifest.EncryptionInformation.IntegrityInformation.RootSignature.Signature

	aggregateHash := &bytes.Buffer{}
	for _, segment := range manifest.EncryptionInformation.IntegrityInformation.Segments {
		decodedHash, err := crypto.Base64Decode([]byte(segment.Hash))
		if err != nil {
			return false, fmt.Errorf("crypto.Base64Decode failed:%w", err)
		}

		aggregateHash.Write(decodedHash)
	}

	sigAlg := HS256
	if strings.EqualFold(gmacIntegrityAlgorithm, rootSigAlg) {
		sigAlg = GMAC
	}

	sig, err := splitKey.getSignature(aggregateHash.Bytes(), sigAlg)
	if err != nil {
		return false, fmt.Errorf("splitkey.getSignature failed:%w", err)
	}

	if rootSigValue == string(crypto.Base64Encode([]byte(sig))) {
		return true, nil
	}

	return false, nil
}

// getSignature calculate signature of data of the given algorithm.
func (splitKey splitKey) getSignature(data []byte, alg IntegrityAlgorithm) (string, error) {
	if alg == HS256 {
		hmac := crypto.CalculateSHA256Hmac(splitKey.key[:], data)
		return hex.EncodeToString(hmac), nil
	}
	if kGMACPayloadLength > len(data) {
		return "", fmt.Errorf("fail to create gmac signature")
	}

	return hex.EncodeToString(data[len(data)-kGMACPayloadLength:]), nil
}

func (splitKey splitKey) createPolicyObject() (policyObject, error) {
	uuidObj, err := uuid.NewUUID()
	if err != nil {
		return policyObject{}, fmt.Errorf("uuid.NewUUID failed: %w", err)
	}

	policyObj := policyObject{}
	policyObj.UUID = uuidObj.String()

	for _, attribute := range splitKey.attributes {
		attributeObj := attributeObject{}
		attributeObj.Attribute = attribute
		policyObj.Body.DataAttributes = append(policyObj.Body.DataAttributes, attributeObj)
	}

	return policyObj, nil
}
