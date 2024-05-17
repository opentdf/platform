package sdk

import (
	"testing"
)

const (
	resourceLocatorTestUrlHttps = "https://test.virtru.com/kas/endpoint"
	resourceLocatorTestUrlHttp  = "http://test.virtru.com/kas/endpoint"
	resourceLocatorTestUrlBad   = "this is a bad url"
)

func TestResourceLocatorHttps(t *testing.T) {
	rl, err := NewResourceLocator(resourceLocatorTestUrlHttps)
	if err != nil {
		t.Fatal(err)
	}
	if rl.protocol != urlProtocolHTTPS {
		t.Fatalf("expecting protocol %d, got %d", urlProtocolHTTPS, rl.protocol)
	}
	if len(rl.body) != len(resourceLocatorTestUrlHttps)-len(kPrefixHTTPS) {
		t.Fatalf("expecting length %d, got %d", len(resourceLocatorTestUrlHttps), len(rl.body))
	}
}

func TestResourceLocatorHttp(t *testing.T) {
	rl, err := NewResourceLocator(resourceLocatorTestUrlHttp)
	if err != nil {
		t.Fatal(err)
	}
	if rl.protocol != urlProtocolHTTP {
		t.Fatalf("expecting protocol %d, got %d", urlProtocolHTTP, rl.protocol)
	}
	if len(rl.body) != len(resourceLocatorTestUrlHttp)-len(kPrefixHTTP) {
		t.Fatalf("expecting length %d, got %d", len(resourceLocatorTestUrlHttp), len(rl.body))
	}
}

func TestResourceLocatorBad(t *testing.T) {
	_, err := NewResourceLocator(resourceLocatorTestUrlBad)
	if err == nil {
		t.Fatal("expecting error")
	}
}
