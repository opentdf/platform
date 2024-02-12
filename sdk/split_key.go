package sdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/opentdf/opentdf-v2-poc/sdk/internal/crypto"
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

type RequestBody struct {
	KeyAccess       `json:"keyAccess"`
	ClientPublicKey string `json:"clientPublicKey"`
	Policy          string `json:"policy"`
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
func newSplitKeyFromManifest(authConfig AuthConfig, manifest Manifest) (splitKey, error) {
	sKey := splitKey{}

	for _, keyAccessObj := range manifest.EncryptionInformation.KeyAccessObjs {
		requestBody := RequestBody{keyAccessObj, "", manifest.EncryptionInformation.Policy}
		key, err := sKey.rewrap(authConfig, &requestBody)
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
			metadata := EncryptedMetadata{}
			err = json.Unmarshal(decodedMetaData, &metadata)
			if err != nil {
				return splitKey{}, fmt.Errorf("json.Unmarshal failed:%w", err)

			}
			encodedCipherText := metadata.Cipher
			cipherText, _ := crypto.Base64Decode([]byte(encodedCipherText))
			metaData, err := gcm.Decrypt(cipherText)
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

			iv := encryptedMetaData[:crypto.GcmStandardNonceSize]
			metadata := EncryptedMetadata{Cipher: string(crypto.Base64Encode(encryptedMetaData)), Iv: string(crypto.Base64Encode(iv))}

			metadataJson, err := json.Marshal(metadata)
			if err != nil {
				return nil, fmt.Errorf(" json.Marshal failed:%w", err)

			}

			keyAccess.EncryptedMetadata = string(crypto.Base64Encode(metadataJson))
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
		policyObj.Body.Dissem = make([]string, 0)
	}

	return policyObj, nil
}

func (splitKey splitKey) handleKasRequest(kasPath string, body *RequestBody, authConfig AuthConfig) (*http.Response, error) {
	kasURL := body.KasURL

	requestBodyData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	claims := rewrapJWTClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(60 * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		string(requestBodyData),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signingRSAPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(authConfig.signingPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("jwt.ParseRSAPrivateKeyFromPEM failed: %w", err)
	}

	signedToken, err := token.SignedString(signingRSAPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("jwt.SignedString failed: %w", err)
	}

	signedTokenRequestBody, err := json.Marshal(map[string]string{
		kSignedRequestToken: signedToken,
	})
	if err != nil {
		return nil, fmt.Errorf("json.Marshal failed: %w", err)
	}

	kasRequestURL, err := url.JoinPath(fmt.Sprintf("%v", kasURL), kasPath)
	if err != nil {
		return nil, fmt.Errorf("url.JoinPath failed: %w", err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, kasRequestURL,
		bytes.NewBuffer(signedTokenRequestBody))
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext failed: %w", err)
	}

	// add required headers
	request.Header = http.Header{
		kContentTypeKey:   {kContentTypeJSONValue},
		kAuthorizationKey: {authConfig.authToken},
		kAcceptKey:        {kContentTypeJSONValue},
	}

	client := &http.Client{}

	response, err := client.Do(request)
	if err != nil {
		slog.Error("failed http request")
		return nil, err
	}

	return response, nil
}
func (splitKey splitKey) rewrap(authConfig AuthConfig, requestBody *RequestBody) ([]byte, error) {

	clientKeyPair, err := crypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewRSAKeyPair failed: %w", err)
	}

	clientPubKey, err := clientKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyInPemFormat failed: %w", err)
	}
	requestBody.ClientPublicKey = clientPubKey

	clientPrivateKey, err := clientKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, fmt.Errorf("crypto.PublicKeyInPemFormat failed: %w", err)
	}

	response, err := splitKey.handleKasRequest(kRewrapV2, requestBody, authConfig)
	if err != nil {
		slog.Error("failed http request")
		return nil, err
	}
	if response.StatusCode != kHTTPOk {
		return nil, fmt.Errorf("http request failed status code:%d", response.StatusCode)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error("Fail to close HTTP response")
		}
	}(response.Body)

	rewrapResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll failed: %w", err)
	}

	key, err := getWrappedKey(rewrapResponseBody, clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap the wrapped key:%w", err)
	}

	return key, nil
}

func getWrappedKey(rewrapResponseBody []byte, clientPrivateKey string) ([]byte, error) {
	var data map[string]interface{}
	err := json.Unmarshal(rewrapResponseBody, &data)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed: %w", err)
	}

	entityWrappedKey, ok := data[kEntityWrappedKey]
	if !ok {
		return nil, fmt.Errorf("entityWrappedKey is missing in key access object")
	}

	asymDecrypt, err := crypto.NewAsymDecryption(clientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("crypto.NewAsymDecryption failed: %w", err)
	}

	entityWrappedKeyDecoded, err := crypto.Base64Decode([]byte(fmt.Sprintf("%v", entityWrappedKey)))
	if err != nil {
		return nil, fmt.Errorf("crypto.Base64Decode failed: %w", err)
	}

	key, err := asymDecrypt.Decrypt(entityWrappedKeyDecoded)
	if err != nil {
		return nil, fmt.Errorf("crypto.Decrypt failed: %w", err)
	}

	return key, nil
}
