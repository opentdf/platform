package sdk

import (
	"bytes"
	"testing"
)

const (
	resourceLocatorTestURLHTTPS = "https://test.virtru.com/kas/endpoint"
	resourceLocatorTestURLHTTP  = "http://test.virtru.com/kas/endpoint"
	resourceLocatorTestURLBad   = "this is a bad url"
)

func TestResourceLocatorHttps(t *testing.T) {
	rl, err := NewResourceLocator(resourceLocatorTestURLHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	if rl.protocol != urlProtocolHTTPS {
		t.Fatalf("expecting protocol %d, got %d", urlProtocolHTTPS, rl.protocol)
	}
	if len(rl.body) != len(resourceLocatorTestURLHTTPS)-len(kPrefixHTTPS) {
		t.Fatalf("expecting length %d, got %d", len(resourceLocatorTestURLHTTPS), len(rl.body))
	}
}

func TestResourceLocatorHttp(t *testing.T) {
	rl, err := NewResourceLocator(resourceLocatorTestURLHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if rl.protocol != urlProtocolHTTP {
		t.Fatalf("expecting protocol %d, got %d", urlProtocolHTTP, rl.protocol)
	}
	if len(rl.body) != len(resourceLocatorTestURLHTTP)-len(kPrefixHTTP) {
		t.Fatalf("expecting length %d, got %d", len(resourceLocatorTestURLHTTP), len(rl.body))
	}
}

func TestResourceLocatorBad(t *testing.T) {
	_, err := NewResourceLocator(resourceLocatorTestURLBad)
	if err == nil {
		t.Fatal("expecting error")
	}
}

func TestReadResourceLocator(t *testing.T) {
	tests := []struct {
		n           string
		protocol    protocolHeader
		body        string
		identifier  string
		expectError bool
	}{
		{"http plain", urlProtocolHTTP, "test.com", "", false},
		{"https plain", urlProtocolHTTPS, "test.com", "", false},
		{"https id2", urlProtocolHTTPS, "test.com", "id", false},
		{"https id32", urlProtocolHTTPS, "test.com", "id1234567890123456789012345678901", false},
		{"invalid protocol", 123, "test.com", "X", true},
		{"unknown protocol id2", identifierNone, "test.com", "i0", false},
		{"unknown protocol id2", identifier2Byte, "test.com", "X", true},
		{"unknown protocol id8", identifier8Byte, "test.com", "X", true},
		{"unknown protocol id32", identifier32Byte, "test.com", "X", true},
	}

	for _, test := range tests {
		t.Run(test.n, func(t *testing.T) {
			rl := &ResourceLocator{
				protocol:   test.protocol,
				body:       test.body,
				identifier: test.identifier,
			}
			buff := bytes.Buffer{}
			if err := rl.writeResourceLocator(&buff); err != nil {
				t.Fatal(err)
			}
			err := rl.readResourceLocator(&buff)
			if (err != nil) != test.expectError {
				t.Fatalf("expected error: %v, got %v, error: %v", test.expectError, err != nil, err)
			}
			if err == nil && rl.body != test.body {
				t.Fatalf("expected body: %s, got %s", test.body, rl.body)
			}
			if err == nil && rl.identifier != test.identifier {
				t.Fatalf("expected identifier: %s, got %s", test.identifier, rl.identifier)
			}
		})
	}
}

func TestURLWithIdentifier(t *testing.T) {
	tests := []struct {
		name               string
		url                string
		identifier         string
		expectedErr        bool
		expectedProtocol   protocolHeader
		expectedBody       string
		expectedIdentifier string
	}{
		{
			name:               "HTTPS URL with 18-byte identifier",
			url:                "https://example.com",
			identifier:         "aws-kms-asymmetric",
			expectedErr:        false,
			expectedProtocol:   urlProtocolHTTPS | identifier32Byte,
			expectedBody:       "example.com",
			expectedIdentifier: "aws-kms-asymmetric\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		},
		{
			name:               "HTTP URL with 8-byte identifier",
			url:                "http://example.com",
			identifier:         "id123456",
			expectedErr:        false,
			expectedProtocol:   urlProtocolHTTP | identifier8Byte,
			expectedBody:       "example.com",
			expectedIdentifier: "id123456",
		},
		{
			name:               "HTTPS URL with 2-byte identifier",
			url:                "https://example.com",
			identifier:         "i1",
			expectedErr:        false,
			expectedProtocol:   urlProtocolHTTPS | identifier2Byte,
			expectedBody:       "example.com",
			expectedIdentifier: "i1",
		},
		{
			name:               "HTTP URL with 6-byte identifier",
			url:                "http://example.com",
			identifier:         "id1234",
			expectedErr:        false,
			expectedProtocol:   urlProtocolHTTP | identifier8Byte,
			expectedBody:       "example.com",
			expectedIdentifier: "id1234\x00\x00",
		},
		{
			name:               "HTTPS URL with 32-byte identifier",
			url:                "https://long.url.for.testing.com/path",
			identifier:         "12345678901234567890123456789012",
			expectedErr:        false,
			expectedProtocol:   urlProtocolHTTPS | identifier32Byte,
			expectedBody:       "long.url.for.testing.com/path",
			expectedIdentifier: "12345678901234567890123456789012",
		},
		{
			name:               "Unsupported protocol should error",
			url:                "ftp://example.com",
			identifier:         "id1",
			expectedErr:        true,
			expectedProtocol:   0,
			expectedBody:       "",
			expectedIdentifier: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rl := &ResourceLocator{}
			err := rl.setURLWithIdentifier(tt.url, tt.identifier)

			if tt.expectedErr {
				if err == nil {
					t.Fatal("expected an error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("setURLWithIdentifier() unexpected error: %v", err)
			}

			var buf bytes.Buffer
			err = rl.writeResourceLocator(&buf)
			if err != nil {
				t.Fatalf("writeResourceLocator() unexpected error: %v", err)
			}

			parsedRl, err := NewResourceLocatorFromReader(&buf)
			if err != nil {
				t.Fatalf("NewResourceLocatorFromReader() unexpected error: %v", err)
			}

			if tt.expectedProtocol != parsedRl.protocol {
				t.Fatalf("expected protocol %v, got %v", tt.expectedProtocol, parsedRl.protocol)
			}
			if tt.expectedBody != parsedRl.body {
				t.Fatalf("expected body %q, got %q", tt.expectedBody, parsedRl.body)
			}
			if tt.expectedIdentifier != parsedRl.identifier {
				t.Fatalf("expected identifier %q, got %q", tt.expectedIdentifier, parsedRl.identifier)
			}
		})
	}
}

func TestGetIdentifier(t *testing.T) {
	tests := []struct {
		n           string
		protocol    protocolHeader
		identifier  string
		expected    string
		expectError bool
	}{
		{"none", identifierNone, "testId", "", true},
		{"https lonely", urlProtocolHTTPS, "testId", "", true},
		{"no id 2b", identifier2Byte, "", "", true},
		{"no body 8b", identifier8Byte, "", "", true},
		{"no body 32b", identifier32Byte, "", "", true},
		{"ok 2b", identifier2Byte, "testId", "testId", false},
		{"ok 8b", identifier8Byte, "testId", "testId", false},
		{"ok 32b", identifier32Byte, "testId", "testId", false},
	}

	for _, test := range tests {
		t.Run(test.n, func(t *testing.T) {
			rl := &ResourceLocator{
				protocol:   test.protocol,
				identifier: test.identifier,
			}
			got, err := rl.GetIdentifier()
			if (err != nil) != test.expectError {
				t.Fatalf("expected error: %v, got %v, error: %v", test.expectError, err != nil, err)
			}
			if got != test.expected {
				t.Fatalf("expected identifier: %s, got %s", test.expected, got)
			}
		})
	}
}

func TestProtocolHeaderIdentifierLength(t *testing.T) {
	tests := []struct {
		n      string
		header protocolHeader
		length int
	}{
		{"none-https", urlProtocolHTTPS, identifierNoneLength},
		{"none-none", identifierNone, identifierNoneLength},
		{"2b", identifier2Byte, identifier2ByteLength},
		{"8b", identifier8Byte, identifier8ByteLength},
		{"32b", identifier32Byte, identifier32ByteLength},
		{"relative", protocolHeader(255), 0},
	}

	for _, test := range tests {
		t.Run(test.n, func(t *testing.T) {
			got := test.header.identifierLength()
			if got != test.length {
				t.Fatalf("expected length: %d, got %d", test.length, got)
			}
		})
	}
}

func TestNewResourceLocatorWithIdentifierFromReader(t *testing.T) {
	setupResourceLocator := func(url, identifier string) ([]byte, error) {
		locator := ResourceLocator{}
		if err := locator.setURLWithIdentifier(url, identifier); err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := locator.writeResourceLocator(&buf); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	// 2 Bytes
	t0Data, err := setupResourceLocator("https://example.com", "t0")
	if err != nil {
		t.Fatal(err)
	}
	// 8 Bytes padded (4 bytes)
	ffffData, err := setupResourceLocator("https://example.com", "ffff\u0000\u0000\u0000\u0000")
	if err != nil {
		t.Fatal(err)
	}
	// 8 Bytes
	t1Data, err := setupResourceLocator("https://example.com", "t1t1t1t1")
	if err != nil {
		t.Fatal(err)
	}
	// 32 Bytes
	t2Data, err := setupResourceLocator("https://example.com", "t2t2t2t2t2t2t2t2t2t2t2t2t2t2t2t2")
	if err != nil {
		t.Fatal(err)
	}
	// 0 Bytes no identifier
	t3Data, err := setupResourceLocator("https://example.com", "")
	if err == nil {
		// must error
		t.Fatal(err)
	}

	tests := []struct {
		n                string
		data             []byte
		expectBody       string
		expectIdent      string
		expectCleanIdent string
		expectError      bool
	}{
		{"id2", t0Data, "example.com", "t0", "t0", false},
		{"id4", ffffData, "example.com", "ffff\u0000\u0000\u0000\u0000", "ffff", false},
		{"id8", t1Data, "example.com", "t1t1t1t1", "t1t1t1t1", false},
		{"id32", t2Data, "example.com", "t2t2t2t2t2t2t2t2t2t2t2t2t2t2t2t2", "t2t2t2t2t2t2t2t2t2t2t2t2t2t2t2t2", false},
		{"id0", t3Data, "example.com", "", "", true},
	}

	for _, test := range tests {
		t.Run(test.n, func(t *testing.T) {
			rl, err := NewResourceLocatorFromReader(bytes.NewReader(test.data))
			if test.expectError {
				if err == nil {
					t.Fatalf("expected error, got %v", rl)
				}
				return
			}
			if rl.body != test.expectBody {
				t.Fatalf("expected body: %s, got %s", test.expectBody, rl.body)
			}
			if rl.identifier != test.expectIdent {
				t.Fatalf("expected identifier: %s, got %s", test.expectIdent, rl.identifier)
			}
			cleanIdent, _ := rl.GetIdentifier()
			if cleanIdent != test.expectCleanIdent {
				t.Fatalf("expected identifier: %s, got %s", test.expectCleanIdent, rl.identifier)
			}
		})
	}
}
