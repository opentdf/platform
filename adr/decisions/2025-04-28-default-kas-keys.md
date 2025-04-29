---
# Required
status: 'proposed'
date: '2025-04-28'
tags:
 - keymanagement
 - kas
---
# Default Platform KAS Key

> :bulb: **Note** Key Mappings: New implementation of KAS Grants

## Context and Problem Statement

Currently, Policy Enforcement Points (PEPs) using the TDF SDK hardcode the platform endpoint to derive the default Key Access Server (KAS) URL. This default KAS is used when no specific key mappings (grants) are associated with namespaces, definitions, or values during TDF creation.

```go
	tdf, err := ec.sdk.CreateTDF(
		writer,
		bytesReader,
		otdf.WithAssertions(assertions...),
		otdf.WithDataAttributes(dataAttrs...),
		otdf.WithKasInformation(otdf.KASInfo{
			URL:       fmt.Sprintf("%s/kas", ec.PlatformEndpoint),
			PublicKey: "",
		}),
		otdf.WithMimeType(mimeType),
		otdf.WithTargetMode("v4.2.2"),
	)
	if err != nil {
		slog.Error("Error encrypting data string", slog.String("error", err.Error()))
	}
```

This hardcoding presents several problems:

- The core platform endpoint might not host a KAS instance, leading to failures.
- Organizations may want to designate a different KAS instance as the system-wide default.
- It lacks flexibility for diverse deployment topologies.

We need a mechanism to configure the default KAS information (URL and public key) instead of relying on a hardcoded derivation from the platform endpoint. This will allow administrators to explicitly define the fallback KAS used when no specific key mappings apply.

<!-- This is an optional element. Feel free to remove. -->
## Decision Drivers

- **Flexibility:** Need to support deployments where the primary platform endpoint does not host a KAS.
- **Organizational Control:** Allow organizations to specify a preferred default KAS instance.
- **Decoupling:** Reduce coupling between the PEP/SDK and the specific platform deployment topology.
- **Reliability:** Ensure a valid default KAS is available even if the platform endpoint changes or doesn't host KAS functionality.
- **Centralized Configuration:** Preference for managing such configurations centrally rather than embedding them in code.

## Considered Options

* Namespace-Scoped Default KAS: Associate KAS instances with specific namespaces (e.g., demo.com) and designate one namespace's KAS as the default for the entire system.
* Well-Known Configuration Default KAS: Define the default KAS URL and public key within the central `wellknownconfiguration.WellKnownService/GetWellKnownConfiguration` endpoint or a similar service discovery mechanism.


## Decision Outcome

Chosen option: "Well-Known Configuration Default KAS"

Justification:
This option provides the most flexible and manageable solution.

- It leverages an existing configuration mechanism (`wellknownconfiguration.WellKnownService/GetWellKnownConfiguration`) already consumed by SDKs, minimizing integration effort.
- It allows for a clear, centralized definition of the default KAS, including its public key, independent of namespaces.
- It directly addresses the need to decouple the default KAS from the platform endpoint and specific namespace structures.
- It avoids the significant data modeling and migration challenges associated with Option 1.

### Implementation Details (Chosen Option)

The `wellknownconfiguration.WellKnownService/GetWellKnownConfiguration` endpoint will be extended to include a `default_tdf_key` object containing the default KAS URL and its public key details.

Example Well-Known Configuration Extension:

```json
{
  "configuration": {
    "default_tdf_key": {
        "tdf": {
            "kas_url": "https://default-kas.example.com/kas",
            "public_key": {
                "algorithm": "ec:secp256r1", // Or rsa:2048, etc.
                "kid": "default-kas-key-1",
                "pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
            }
        },
        "nanotdf": {
            "kas_url": "https://default-kas.example.com/kas",
            "public_key": {
                "algorithm": "ec:secp256r1",
                "kid": "default-kas-key-1",
                "pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
            }
        }
        
    },
    "health": {
      "endpoint": "/healthz"
    },
    "idp": {
      // ... other configurations
    }
    // ... other configurations
  }
}
```

| Column  | type          |
| ------- | ------------- |
| id      | uuid (string) |
| key_id  | string        |
| .....   | .....         |
| default | bool          |

The TDF SDKs will be updated to:

- Extract the `default_tdf_key` information.
- Use this kas_url and public_key as the default KASInfo when creating TDFs only if no other applicable key mappings are found.

### Consequences

- 🟩 Good: Centralizes default KAS configuration, improving manageability and visibility.
- 🟩 Good: Decouples default KAS selection from the platform endpoint location.
- 🟩 Good: Simplifies SDK integration by reusing an existing configuration fetching mechanism.
- 🟩 Good: Provides the necessary public key alongside the URL, ensuring the SDK has all required default information.
- 🟨 Neutral: Requires updates to all TDF SDKs to consume and utilize the new configuration field.
- 🟨 Neutral: Introduces a dependency on the availability and correctness of the `wellknownconfiguration.WellKnownService/GetWellKnownConfiguration` endpoint for default KAS functionality.
- 🟥 Bad: If the `wellknownconfiguration.WellKnownService/GetWellKnownConfiguration` endpoint is unavailable or misconfigured, TDF creation might fail when relying on the default KAS. Robust error handling and fallback mechanisms (even if just logging a clear error) in the SDK are necessary.

### Validation
- **Unit Tests:** SDK tests will verify that the `default_tdf_key` from the well-known configuration is correctly parsed and used when no other grants apply.
- **Integration Tests:** Tests will ensure that PEPs can successfully create TDFs using the default KAS fetched from a live `wellknownconfiguration.WellKnownService/GetWellKnownConfiguration` endpoint.
- **Manual Testing:** Deployments will be manually configured with different default KAS settings to verify end-to-end functionality.
- **Documentation:** Update SDK and platform documentation to reflect the new configuration option and its usage.

<!-- This is an optional element. Feel free to remove. -->
## Pros and Cons of the Options

### Option 1: Namespace-Scoped Default KAS

**Description:** Define KAS instances within the scope of a namespace. Designate one namespace (e.g., default.com) whose KAS serves as the system-wide default.

- 🟩 Good: Conceptually links KAS instances to namespaces, which might align with some organizational structures.
- 🟥 Bad: Requires significant changes to the current data model where KAS instances are likely global, not namespace-scoped. This implies complex data migration.
- 🟥 Bad: Restricts a namespace to potentially only one associated KAS if used for the default mechanism, reducing flexibility.
- 🟥 Bad: Creates an indirect way of defining the default KAS, making the configuration less explicit.
- 🟥 Bad: Doesn't easily solve providing the default KAS public key without further model changes.

### Option 2: Well-Known Configuration Default KAS

**Description:** Add a specific field (e.g., default_tdf_key) to the existing /wellknown/configuration response, containing the default KAS URL and its public key.

- 🟩 Good: Leverages existing infrastructure (/wellknown/configuration endpoint and SDK consumption).
- 🟩 Good: Provides a clear, explicit, and centralized location for the default KAS configuration.
- 🟩 Good: Easily includes both the KAS URL and its necessary public key information.
- 🟩 Good: No complex data model changes or migrations required for KAS or namespace resources.
- 🟨 Neutral: Requires coordination to update the well-known configuration structure and consuming SDKs.
- 🟥 Bad: Creates a dependency on the well-known endpoint; if it's down or incorrect, default encryption fails.
