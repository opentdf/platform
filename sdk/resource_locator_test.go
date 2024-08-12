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
