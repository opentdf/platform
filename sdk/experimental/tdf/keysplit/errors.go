// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package keysplit

import "errors"

var (
	// Base input validation errors
	ErrNoAttributes = errors.New("no attributes provided")
	ErrInvalidDEK   = errors.New("invalid DEK: must be 32 bytes")
	ErrEmptyDEK     = errors.New("DEK cannot be empty")

	// Attribute resolution errors
	ErrInvalidAttributeFQN = errors.New("invalid attribute FQN")
	ErrMissingDefinition   = errors.New("attribute missing definition")
	ErrNoKASFound          = errors.New("no KAS found for attribute")
	ErrMissingGrants       = errors.New("attribute missing grants")
	ErrInvalidRule         = errors.New("invalid attribute rule type")

	// KAS and key errors
	ErrInvalidPublicKey = errors.New("invalid KAS public key")
	ErrMissingKID       = errors.New("KAS key missing key identifier")
	ErrMissingPEM       = errors.New("KAS key missing PEM data")
	ErrUnsupportedAlg   = errors.New("unsupported key algorithm")
	ErrInvalidKASURL    = errors.New("invalid KAS URL")

	// Split generation errors
	ErrSplitGeneration    = errors.New("failed to generate key split")
	ErrInvalidSplitID     = errors.New("invalid split ID")
	ErrNoSplitsGenerated  = errors.New("no splits generated")
	ErrSplitCountMismatch = errors.New("split count mismatch")

	// KAO building errors
	ErrKAOBuild         = errors.New("failed to build key access object")
	ErrEncryptionFailed = errors.New("failed to encrypt key")
	ErrPolicyBinding    = errors.New("failed to create policy binding")
	ErrMetadataEncrypt  = errors.New("failed to encrypt metadata")

	// Configuration errors
	ErrNoDefaultKAS  = errors.New("no default KAS configured")
	ErrInvalidConfig = errors.New("invalid configuration")
)
