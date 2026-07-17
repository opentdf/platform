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
	if got := (*updatedClient.Attributes)[standardTokenExchangeEnabledAttribute]; got != keycloakBoolTrue {
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
	if got := (*updatedClient.Attributes)[standardTokenExchangeEnabledAttribute]; got != keycloakBoolTrue {
		t.Fatalf("expected %s to be true, got %q", standardTokenExchangeEnabledAttribute, got)
	}
}

func TestExactClientByClientID(t *testing.T) {
	const clientID = "opentdf"
	clients := []*gocloak.Client{
		{ClientID: gocloak.StringP("opentdf-extra")},
		{ClientID: gocloak.StringP(clientID), ID: gocloak.StringP("uuid-opentdf")},
	}

	client, err := exactClientByClientID(clients, clientID)
	if err != nil {
		t.Fatalf("expected exact client match: %v", err)
	}
	if got := *client.ID; got != "uuid-opentdf" {
		t.Fatalf("expected exact client uuid, got %q", got)
	}
}

func TestExactClientByClientIDReturnsErrorForPrefixOnlyMatch(t *testing.T) {
	clients := []*gocloak.Client{
		{ClientID: gocloak.StringP("opentdf-extra")},
	}

	if _, err := exactClientByClientID(clients, "opentdf"); err == nil {
		t.Fatal("expected exact client match error")
	}
}
