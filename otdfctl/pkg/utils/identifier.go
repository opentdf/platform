// pkg/utils/identifier.go
package utils

import (
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// IdentifierStringType defines the type of string identified.
type IdentifierStringType int

const (
	// StringTypeUnknown indicates the string type could not be determined or is empty.
	StringTypeUnknown IdentifierStringType = iota
	// StringTypeUUID indicates the string is a valid UUID.
	StringTypeUUID
	// StringTypeURI indicates the string is a valid absolute URI.
	StringTypeURI
	// StringTypeGeneric indicates the string is not a UUID or URI, and can be treated as a generic identifier (e.g., a name).
	StringTypeGeneric
)

// String returns a string representation of the IdentifierStringType.
func (it IdentifierStringType) String() string {
	switch it {
	case StringTypeUUID:
		return "UUID"
	case StringTypeURI:
		return "URI"
	case StringTypeGeneric:
		return "Generic"
	case StringTypeUnknown:
		fallthrough
	default:
		return "Unknown"
	}
}

// ClassifyString attempts to determine if the input string is a UUID, an absolute URI, or a generic string.
// It prioritizes UUID, then URI, then defaults to Generic.
func ClassifyString(input string) IdentifierStringType {
	trimmedInput := strings.TrimSpace(input)
	if trimmedInput == "" {
		return StringTypeUnknown // Or StringTypeGeneric if empty strings should be treated as such
	}

	// Check for UUID
	// uuid.Parse is strict and will return an error if the string is not a valid UUID.
	if _, err := uuid.Parse(trimmedInput); err == nil {
		return StringTypeUUID
	}

	// Check for an absolute URI
	// url.ParseRequestURI requires the URL to be absolute.
	// We also check for a scheme and host to ensure it's a usable network URI.
	if parsedURL, err := url.ParseRequestURI(trimmedInput); err == nil {
		if parsedURL.Scheme != "" && parsedURL.Host != "" {
			return StringTypeURI
		}
	}
	// A slightly more lenient check that also catches schemeless URLs if needed,
	// but for KAS identifiers, absolute URIs are usually expected.
	// if parsedURL, err := url.Parse(trimmedInput); err == nil {
	// 	if parsedURL.Scheme != "" && parsedURL.Host != "" {
	// 		return StringTypeURI
	// 	}
	// }

	// If not a UUID and not a well-formed absolute URI, treat as generic
	return StringTypeGeneric
}
