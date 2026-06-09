package sdk

const (
	// The latest version of TDF Spec currently targeted by the SDK.
	// By default, new files will conform to this version of the spec
	// and, where possible, older versions will still be readable.
	TDFSpecVersion = "4.3.0"

	// The three-part semantic version number of this SDK
	Version = "0.24.0" // x-release-please-version
)

// SupportedFeatures returns a list of optional features supported by this SDK build.
// Used by xtest integration harness for feature detection.
func SupportedFeatures() []string {
	return []string{
		"dpop",       // RFC 9449 DPoP (Demonstrating Proof-of-Possession)
		"connectrpc", // Connect RPC protocol support
	}
}
