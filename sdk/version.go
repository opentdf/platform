package sdk

const (
	// The latest version of TDF Spec currently targeted by the SDK.
	// By default, new files will conform to this version of the spec
	// and, where possible, older versions will still be readable.
	TDFSpecVersion = "4.3.0"

	// The three-part semantic version number of this SDK
	Version = "0.27.0" // x-release-please-version
)

// SupportedFeatures returns a list of optional features supported by this SDK build.
// Used by xtest integration harness for feature detection.
//
// These strings are part of the stable API surface. The xtest harness silently
// SKIPs (rather than fails) tests gated on an unknown feature string, so removing
// or renaming a feature here must be coordinated with opentdf/tests before merging
// to avoid quietly disabling coverage.
func SupportedFeatures() []string {
	return []string{
		"dpop",                 // RFC 9449 DPoP (Demonstrating Proof-of-Possession)
		"dpop_nonce_challenge", // RFC 9449 §8 server-issued DPoP-Nonce challenge/retry
		"connectrpc",           // Connect RPC protocol support
	}
}
