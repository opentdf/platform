package auth

import (
	"fmt"
	"net/url"
	"strings"
)

// normalizeDPoPURI applies the syntax- and scheme-based normalization that
// RFC 9449 recommends before comparing htu values.
func normalizeDPoPURI(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != httpScheme && scheme != httpsScheme {
		return "", fmt.Errorf("unsupported DPoP URI scheme %q", u.Scheme)
	}
	return originFromHost(u.Host, scheme == httpsScheme) + normalizeEscapedPath(u.EscapedPath()), nil
}

func normalizeEscapedPath(escapedPath string) string {
	if escapedPath == "" {
		escapedPath = "/"
	}
	return removeDotSegments(normalizePercentEncoding(escapedPath))
}

func normalizePercentEncoding(s string) string {
	const (
		upperHex     = "0123456789ABCDEF"
		hexDigitBits = 4
		hexDigitMask = 1<<hexDigitBits - 1
	)
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+2 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		hi, hiOK := hexValue(s[i+1])
		lo, loOK := hexValue(s[i+2])
		if !hiOK || !loOK {
			b.WriteByte(s[i])
			continue
		}
		decoded := hi<<hexDigitBits | lo
		if isUnreserved(decoded) {
			b.WriteByte(decoded)
		} else {
			b.WriteByte('%')
			b.WriteByte(upperHex[decoded>>hexDigitBits])
			b.WriteByte(upperHex[decoded&hexDigitMask])
		}
		i += 2
	}
	return b.String()
}

func hexValue(c byte) (byte, bool) {
	const hexAlphaOffset = 10
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + hexAlphaOffset, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + hexAlphaOffset, true
	default:
		return 0, false
	}
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// removeDotSegments implements RFC 3986 section 5.2.4 without collapsing
// repeated slashes, which are significant path data.
func removeDotSegments(input string) string {
	var output string
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = input[2:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = input[3:]
			output = trimLastPathSegment(output)
		case input == "/..":
			input = "/"
			output = trimLastPathSegment(output)
		case input == "." || input == "..":
			input = ""
		default:
			n := strings.IndexByte(input[1:], '/')
			if n < 0 {
				output += input
				input = ""
			} else {
				n++
				output += input[:n]
				input = input[n:]
			}
		}
	}
	return output
}

func trimLastPathSegment(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	return ""
}
