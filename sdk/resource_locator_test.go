package sdk

import (
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
