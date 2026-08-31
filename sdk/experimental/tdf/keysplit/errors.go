// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package keysplit

import "errors"

// Only ErrEmptyDEK, ErrInvalidDEK, ErrNoDefaultKAS and
// ErrNoSplitsGenerated are still returned; the rest are retained so
// dependent code keeps compiling. Splitting now happens in package sdk,
// which reports its own errors -- match on those, or just on err != nil.
var (
	// Base input validation errors

	// Deprecated: never returned.
	ErrNoAttributes = errors.New("no attributes provided")
	ErrInvalidDEK   = errors.New("invalid DEK: must be 32 bytes")
	ErrEmptyDEK     = errors.New("DEK cannot be empty")

	// Attribute resolution errors

	// Deprecated: never returned.
	ErrInvalidAttributeFQN = errors.New("invalid attribute FQN")
	// Deprecated: never returned.
	ErrMissingDefinition = errors.New("attribute missing definition")
	// Deprecated: never returned.
	ErrNoKASFound = errors.New("no KAS found for attribute")
	// Deprecated: never returned.
	ErrMissingGrants = errors.New("attribute missing grants")
	// Deprecated: never returned.
	ErrInvalidRule = errors.New("invalid attribute rule type")

	// KAS and key errors

	// Deprecated: never returned.
	ErrInvalidPublicKey = errors.New("invalid KAS public key")
	// Deprecated: never returned.
	ErrMissingKID = errors.New("KAS key missing key identifier")
	// Deprecated: never returned.
	ErrMissingPEM = errors.New("KAS key missing PEM data")
	// Deprecated: never returned.
	ErrUnsupportedAlg = errors.New("unsupported key algorithm")
	// Deprecated: never returned.
	ErrInvalidKASURL = errors.New("invalid KAS URL")

	// Split generation errors

	// Deprecated: never returned.
	ErrSplitGeneration = errors.New("failed to generate key split")
	// Deprecated: never returned.
	ErrInvalidSplitID    = errors.New("invalid split ID")
	ErrNoSplitsGenerated = errors.New("no splits generated")
	// Deprecated: never returned.
	ErrSplitCountMismatch = errors.New("split count mismatch")

	// KAO building errors

	// Deprecated: never returned.
	ErrKAOBuild = errors.New("failed to build key access object")
	// Deprecated: never returned.
	ErrEncryptionFailed = errors.New("failed to encrypt key")
	// Deprecated: never returned.
	ErrPolicyBinding = errors.New("failed to create policy binding")
	// Deprecated: never returned.
	ErrMetadataEncrypt = errors.New("failed to encrypt metadata")

	// Configuration errors
	ErrNoDefaultKAS = errors.New("no default KAS configured")
	// Deprecated: never returned.
	ErrInvalidConfig = errors.New("invalid configuration")
)
