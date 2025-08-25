package sdk

import (
	"errors"

	"github.com/opentdf/platform/sdk/tdf"
)

type (
	Segment               = tdf.Segment
	RootSignature         = tdf.RootSignature
	IntegrityInformation  = tdf.IntegrityInformation
	KeyAccess             = tdf.KeyAccess
	PolicyBinding         = tdf.PolicyBinding
	Method                = tdf.Method
	Payload               = tdf.Payload
	EncryptionInformation = tdf.EncryptionInformation
	Manifest              = tdf.Manifest
	attributeObject       = tdf.PolicyAttribute
	PolicyObject          = tdf.Policy
	EncryptedMetadata     = tdf.EncryptedMetadata

	// Statement includes information applying to the scope of the assertion.
	// It could contain rights, handling instructions, or general metadata.
	Statement = tdf.Statement

	// Binding enforces cryptographic integrity of the assertion.
	// So the can't be modified or copied to another tdf.
	Binding = tdf.Binding

	// AssertionType represents the type of the assertion.
	AssertionType = tdf.AssertionType

	// Scope represents the object which the assertion applies to.
	Scope = tdf.Scope

	// AppliesToState indicates whether the assertion applies to encrypted or unencrypted data.
	AppliesToState = tdf.AppliesToState

	// BindingMethod represents the method used to bind the assertion.
	BindingMethod = tdf.BindingMethod

	// AssertionKeyAlg represents the algorithm of an assertion key.
	AssertionKeyAlg = tdf.AssertionKeyAlg

	// AssertionKey represents a key for assertions.
	AssertionKey = tdf.AssertionKey

	// AssertionVerificationKeys represents the verification keys for assertions.
	AssertionVerificationKeys = tdf.AssertionVerificationKeys

	// AssertionConfig is a shadow of Assertion with the addition of the signing key.
	// It is used on creation
	AssertionConfig tdf.AssertionConfig

	Assertion = tdf.Assertion
)

const (
	// The latest version of TDF Spec currently targeted by the SDK.
	// By default, new files will conform to this version of the spec
	// and, where possible, older versions will still be readable.
	TDFSpecVersion = tdf.TDFSpecVersion
)

const (
	SystemMetadataAssertionID = tdf.SystemMetadataAssertionID
	SystemMetadataSchemaV1    = tdf.SystemMetadataSchemaV1
)

var errAssertionVerifyKeyFailure = errors.New("assertion: failed to verify with provided key")
