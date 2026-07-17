package fixtures

import (
	"testing"

	"github.com/Nerzal/gocloak/v13"
)

func TestWithStandardTokenExchangeEnabled(t *testing.T) {
	existingAttributes := map[string]string{
		"client.secret.creation.time": "12345",
	}
	client := gocloak.Client{
		Attributes: &existingAttributes,
	}

	updatedClient := withStandardTokenExchangeEnabled(client)

	if updatedClient.Attributes == nil {
		t.Fatal("expected attributes to be set")
	}
	if got := (*updatedClient.Attributes)[standardTokenExchangeEnabledAttribute]; got != "true" {
		t.Fatalf("expected %s to be true, got %q", standardTokenExchangeEnabledAttribute, got)
	}
	if got := (*updatedClient.Attributes)["client.secret.creation.time"]; got != "12345" {
		t.Fatalf("expected existing attribute to be preserved, got %q", got)
	}
	if _, ok := existingAttributes[standardTokenExchangeEnabledAttribute]; ok {
		t.Fatal("expected original attributes map to remain unchanged")
	}
}

func TestWithStandardTokenExchangeEnabledInitializesAttributes(t *testing.T) {
	updatedClient := withStandardTokenExchangeEnabled(gocloak.Client{})

	if updatedClient.Attributes == nil {
		t.Fatal("expected attributes to be initialized")
	}
	if got := (*updatedClient.Attributes)[standardTokenExchangeEnabledAttribute]; got != "true" {
		t.Fatalf("expected %s to be true, got %q", standardTokenExchangeEnabledAttribute, got)
	}
}
