package sdk

import "errors"

var (
	// TDF errors
	ErrTDFArchiveReaderUnexpected  = errors.New("archive.NewTDFReader failed")
	ErrTDFReaderManifestUnexpected = errors.New("tdfReader.Manifest failed")

	// TDF Manifest errors
	ErrTDFManifestValidationFailed = errors.New("could not validate manifest.json")
	ErrTDFManifestInvalid          = errors.New("manifest was not valid")

	// NanoTDF errors
	ErrNanoTDFMagicNumber                   = errors.New("not a valid nano tdf")
	ErrNanoTDFHeaderRead                    = errors.New("nanoTDF read error")
	ErrNanoTDFSeekFailed                    = errors.New("readSeeker.Seek failed")
	ErrNanoTDFNewKASClientFailed            = errors.New("newKASClient failed")
	ErrNanoTDFUnwrapNanoTDFFailed           = errors.New("unwrapNanoTDF failed")
	ErrNanoTDFSizeOfAuthTagForCipher        = errors.New("SizeOfAuthTagForCipher failed")
	ErrNanoTDFReadFailed                    = errors.New("io.Reader.Read failed")
	ErrNanoTDFInvalidNanoTDF                = errors.New("not a valid nano tdf")
	ErrNanoTDFCurveUnsupported              = errors.New("curve is not supported")
	ErrNanoTDFOnlySecp256r1Supported        = errors.New("current implementation of nano tdf only support secp256r1 curve")
	ErrNanoTDFOnlyEmbeddedPolicyType        = errors.New("current implementation only support embedded policy type")
	ErrNanoTDFWriteNanoTDFHeaderFailed      = errors.New("writeNanoTDFHeader failed")
	ErrNanoTDFExceedsMaxSizeForNanoTDF      = errors.New("exceeds max size for nano tdf")
	ErrNanoTDFConfigKASURLFailed            = errors.New("config.kasURL failed")
	ErrNanoTDFConfigKASURLEmpty             = errors.New("config.kasUrl is empty")
	ErrNanoTDFGetECPublicKeyFailed          = errors.New("getECPublicKey failed")
	ErrNanoTDFSetURLWithIdentifierFailed    = errors.New("getECPublicKey setURLWithIdentifier failed")
	ErrNanoTDFEncryptWithIVAndTagSize       = errors.New("AesGcm.EncryptWithIVAndTagSize failed")
	ErrNanoTDFDecryptWithIVAndTagSize       = errors.New("DecryptWithIVAndTagSize failed")
	ErrNanoTDFPolicyCreate                  = errors.New("fail to create policy object")
	ErrNanoTDFPolicyMarshal                 = errors.New("json.Marshal failed")
	ErrNanoTDFAESGCMEncryptWithIVAndTagSize = errors.New("AesGcm.EncryptWithIVAndTagSize failed")
	ErrNanoTDFWriteEmbeddedPolicy           = errors.New("writeEmbeddedPolicy failed")
	ErrNanoTDFNewResourceLocatorFromReader  = errors.New("call to NewResourceLocatorFromReader failed")
	ErrNanoTDFGetECCKeyLength               = errors.New("getECCKeyLength failed")
	ErrNanoTDFExceedsMaxSize                = errors.New("exceeds max size for nano tdf")
	ErrNanoTDFConfigKASUrl                  = errors.New("config.kasUrl failed")

	// OCrypto errors
	ErrOcryptoConvertECDHPrivateKey      = errors.New("ocrypto.ConvertToECDHPrivateKey failed")
	ErrOcryptoComputeECDHKeyFromECDHKeys = errors.New("ocrypto.ComputeECDHKeyFromEC failed")
	ErrOcryptoCalculateHKDF              = errors.New("ocrypto.CalculateHKDF failed")
	ErrOcryptoNewAESGCM                  = errors.New("ocrypto.NewAESGcm failed")
	ErrOcryptoComputeECDSASig            = errors.New("ocrypto.ComputeECDSASig failed")
	ErrOcryptoRandomBytesFailed          = errors.New("ocrypto.RandomBytes failed")
	ErrOcryptoECPubKeyFromPemFailed      = errors.New("ocrypto.ECPubKeyFromPem failed")
	ErrOcryptoNewRSAKeyPairFailed        = errors.New("ocrypto.NewRSAKeyPair failed")

	// ResourceLocator errors
	ErrResourceLocatorURLLength                     = errors.New("URL too long")
	ErrResourceLocatorReadProtocol                  = errors.New("Error reading ResourceLocator protocol value")
	ErrResourceLocatorUnsupportedProtocol           = errors.New("unsupported protocol")
	ErrResourceLocatorReadBodyLength                = errors.New("Error reading ResourceLocator body length value")
	ErrResourceLocatorReadBodyValue                 = errors.New("Error reading ResourceLocator body value")
	ErrResourceLocatorReadIdentifier                = errors.New("Error reading ResourceLocator identifier value")
	ErrResourceLocatorReadIdentifierEmpty           = errors.New("identifier is empty")
	ErrResourceLocatorUnsupportedIdentifierLength   = errors.New("unsupported identifier length")
	ErrResourceLocatorUnsupportedIdentifierProtocol = errors.New("unsupported identifier protocol")

	// Platform errors
	ErrPlatformEndpointMalformed            = errors.New("platform endpoint is malformed")
	ErrPlatformEndpointParseFailed          = errors.New("cannot parse platform endpoint")
	ErrPlatformConfigRetrieval              = errors.New("unable to retrieve config information, and none was provided")
	ErrPlatformConfigFailed                 = errors.New("failed to retrieve platform configuration")
	ErrPlatformConfigIssuerNotFound         = errors.New("issuer not found in platform well-known idp configuration")
	ErrPlatformConfigAuthzEndpointNotFound  = errors.New("authorization_endpoint not found in well-known idp configuration")
	ErrPlatformConfigPublicClientIDNotFound = errors.New("public_client_id not found in well-known idp configuration")
	ErrPlatformConfigTokenEndpointNotFound  = errors.New("token_endpoint not found in well-known idp configuration")
	ErrPlatformConfigAccessTokenInvalid     = errors.New("access token is invalid")

	// OIDC errors
	ErrOIDCTokenEndpointMissing = errors.New("token_endpoint not found in well-known configuration")

	// Auth errors
	ErrAuthTokenExchangeOrCertExchange = errors.New("cannot do both token exchange and certificate exchange")

	// Generic SDK errors
	ErrSDKNilValue                  = errors.New("nil value")
	ErrSDKShutdownFailed            = errors.New("failed to shutdown sdk")
	ErrSDKRSAKeyGenerationFailed    = errors.New("could not generate RSA Key")
	ErrSDKIPCCoreConnectionRequired = errors.New("core connection is required for IPC mode")

	// gRPC errors
	ErrGrpcDialFailed = errors.New("failed to dial grpc endpoint")

	// Deprecated errors
	// deprecated
	ErrAccessTokenInvalid = ErrPlatformConfigAccessTokenInvalid
	// deprecated
	ErrPlatformIssuerNotFound = ErrPlatformConfigIssuerNotFound
	// deprecated
	ErrPlatformAuthzEndpointNotFound = ErrPlatformConfigAuthzEndpointNotFound
	// deprecated
	ErrPlatformTokenEndpointNotFound = ErrPlatformConfigTokenEndpointNotFound
	// deprecated
	ErrPlatformPublicClientIDNotFound = ErrPlatformConfigPublicClientIDNotFound
)
