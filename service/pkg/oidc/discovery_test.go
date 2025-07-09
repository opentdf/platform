package oidc

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/opentdf/platform/service/logger"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// mockClientDiscover is a helper to mock the client.Discover function
func mockClientDiscover(_ context.Context, issuer string, _ *http.Client) (*oidc.DiscoveryConfiguration, error) {
	if issuer == "https://good-issuer" {
		return &oidc.DiscoveryConfiguration{Issuer: issuer}, nil
	}
	return nil, errors.New("discovery failed")
}

func TestDiscover_Success(t *testing.T) {
	log := logger.CreateTestLogger()

	// Patch client.Discover
	oldDiscover := Discover
	Discover = func(ctx context.Context, _ *logger.Logger, issuer string, tlsNoVerify bool) (*DiscoveryConfiguration, error) {
		return mockClientDiscover(ctx, issuer, nil)
	}
	defer func() { Discover = oldDiscover }()

	issuer := "https://good-issuer"
	conf, err := Discover(t.Context(), log, issuer, false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if conf == nil || conf.Issuer != issuer {
		t.Errorf("unexpected config: got %+v", conf)
	}
}

func TestDiscover_Failure(t *testing.T) {
	log := logger.CreateTestLogger()

	oldDiscover := Discover
	Discover = func(ctx context.Context, _ *logger.Logger, issuer string, tlsNoVerify bool) (*DiscoveryConfiguration, error) {
		return mockClientDiscover(ctx, issuer, nil)
	}
	defer func() { Discover = oldDiscover }()

	issuer := "https://bad-issuer"
	conf, err := Discover(t.Context(), log, issuer, false)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if conf != nil {
		t.Errorf("expected nil config, got %+v", conf)
	}
}
