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
		protocol    protocolHeader
		body        string
		identifier  string
		expectError bool
	}{
		{urlProtocolHTTP, "test.com", "", false},
		{urlProtocolHTTPS, "test.com", "", false},
		{urlProtocolHTTPS, "test.com", "id", false},
		{urlProtocolHTTPS, "test.com", "id1234567890123456789012345678901", false},
		{123, "test.com", "X", true},
		{identifierNone, "test.com", "i0", false},
		{identifier2Byte, "test.com", "X", true},
		{identifier8Byte, "test.com", "X", true},
		{identifier32Byte, "test.com", "X", true},
	}

	for _, test := range tests {
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
	}
}

func TestGetIdentifier(t *testing.T) {
	tests := []struct {
		protocol    protocolHeader
		identifier  string
		expected    string
		expectError bool
	}{
		{identifierNone, "testId", "", true},
		{urlProtocolHTTPS, "testId", "", true},
		{identifier2Byte, "", "", true},
		{identifier8Byte, "", "", true},
		{identifier32Byte, "", "", true},
		{identifier2Byte, "testId", "testId", false},
		{identifier8Byte, "testId", "testId", false},
		{identifier32Byte, "testId", "testId", false},
	}

	for _, test := range tests {
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
	}
}

func TestProtocolHeaderIdentifierLength(t *testing.T) {
	tests := []struct {
		header protocolHeader
		length int
	}{
		{urlProtocolHTTPS, identifierNoneLength},
		{identifierNone, identifierNoneLength},
		{identifier2Byte, identifier2ByteLength},
		{identifier8Byte, identifier8ByteLength},
		{identifier32Byte, identifier32ByteLength},
		{protocolHeader(255), 0},
	}

	for _, test := range tests {
		got := test.header.identifierLength()
		if got != test.length {
			t.Fatalf("expected length: %d, got %d", test.length, got)
		}
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
		data        []byte
		expectBody  string
		expectIdent string
		expectError bool
	}{
		{t0Data, "example.com", "t0", false},
		{t1Data, "example.com", "t1t1t1t1", false},
		{t2Data, "example.com", "t2t2t2t2t2t2t2t2t2t2t2t2t2t2t2t2", false},
		{t3Data, "example.com", "", true},
	}

	for _, test := range tests {
		rl, err := NewResourceLocatorFromReader(bytes.NewReader(test.data))
		if (err != nil) != test.expectError {
			t.Fatalf("expected error: %v, got %v, error: %v", test.expectError, err != nil, err)
		}
		if !test.expectError && rl.body != test.expectBody {
			t.Fatalf("expected body: %s, got %s", test.expectBody, rl.body)
		}
		if rl.identifier != test.expectIdent {
			t.Fatalf("expected identifier: %s, got %s", test.expectIdent, rl.identifier)
		}
	}
}
