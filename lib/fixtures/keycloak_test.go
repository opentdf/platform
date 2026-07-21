package fixtures

import (
	"testing"

	"github.com/Nerzal/gocloak/v13"
)

func TestWithStandardTokenExchangeEnabled(t *testing.T) {
	existingAttributes := map[string]string{
		"client.secret.creation.time": "12345", // #nosec G101 -- Keycloak metadata key used in unit test, not a credential
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

func TestWithDPoPBoundAccessTokens(t *testing.T) {
	existingAttributes := map[string]string{
		"client.secret.creation.time": "12345", // #nosec G101 -- Keycloak metadata key used in unit test, not a credential
	}
	client := gocloak.Client{
		Attributes: &existingAttributes,
	}

	updatedClient := withDPoPBoundAccessTokens(client)

	if updatedClient.Attributes == nil {
		t.Fatal("expected attributes to be set")
	}
	if got := (*updatedClient.Attributes)[dpopBoundAccessTokensAttribute]; got != keycloakBoolTrue {
		t.Fatalf("expected %s to be true, got %q", dpopBoundAccessTokensAttribute, got)
	}
	if got := (*updatedClient.Attributes)["client.secret.creation.time"]; got != "12345" {
		t.Fatalf("expected existing attribute to be preserved, got %q", got)
	}
	if _, ok := existingAttributes[dpopBoundAccessTokensAttribute]; ok {
		t.Fatal("expected original attributes map to remain unchanged")
	}
}

func TestWithClientAudienceMapper(t *testing.T) {
	client := withClientAudienceMapper(gocloak.Client{}, "opentdf-sdk")

	if client.ProtocolMappers == nil {
		t.Fatal("expected protocol mappers to be set")
	}
	if got := len(*client.ProtocolMappers); got != 1 {
		t.Fatalf("expected one protocol mapper, got %d", got)
	}
	mapper := (*client.ProtocolMappers)[0]
	if got := *mapper.ProtocolMapper; got != "oidc-audience-mapper" {
		t.Fatalf("expected audience mapper, got %q", got)
	}
	if got := (*mapper.Config)["included.client.audience"]; got != "opentdf-sdk" {
		t.Fatalf("expected opentdf-sdk audience, got %q", got)
	}
}

func TestWithClientAudienceMapperDoesNotDuplicateExistingAudience(t *testing.T) {
	client := withClientAudienceMapper(gocloak.Client{}, "opentdf-sdk")
	client = withClientAudienceMapper(client, "opentdf-sdk")

	if client.ProtocolMappers == nil {
		t.Fatal("expected protocol mappers to be set")
	}
	if got := len(*client.ProtocolMappers); got != 1 {
		t.Fatalf("expected one protocol mapper, got %d", got)
	}
}

func TestDefaultProtocolMappersForStandardKeycloakExcludeCustomDPoPMapper(t *testing.T) {
	mappers := defaultProtocolMappers("https://platform.example", false)

	if len(mappers) != 1 {
		t.Fatalf("expected only the audience mapper, got %d mappers", len(mappers))
	}
	if got := *mappers[0].ProtocolMapper; got != "oidc-audience-mapper" {
		t.Fatalf("expected audience mapper, got %q", got)
	}
}

func TestDefaultProtocolMappersForCustomKeycloakIncludeCustomDPoPMapper(t *testing.T) {
	mappers := defaultProtocolMappers("https://platform.example", true)

	found := false
	for _, mapper := range mappers {
		if mapper.ProtocolMapper != nil && *mapper.ProtocolMapper == "virtru-oidc-protocolmapper" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected custom Keycloak setup to include virtru-oidc-protocolmapper")
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
