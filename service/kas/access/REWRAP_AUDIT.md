# Rewrap audit outcomes

- KAS emits one event per processed key access object (KAO).
- Failures before KAO processing emit one request-level event.
- All events use `action.type: rewrap` and `object.type: key_object`.
- Results are `success` (key returned), `failure` (request rejected), or `error`
  (KAS or a dependency could not finish).

```mermaid
flowchart TD
    A[Rewrap request] --> B{Request can be processed?}
    B -->|no| F1["FAILURE · request level<br/>SRT, body, token, context,<br/>client key, or policy request invalid"]
    B -->|yes| C{Duplicate KAO ID?}
    C -->|yes| F2A["FAILURE<br/>kao_invalid"]
    C -->|no| P{Policy body valid?}
    P -->|no| F3A["FAILURE · suspected_tamper: true<br/>policy_body_invalid"]
    P -->|yes| V{"KAO and key type valid?"}
    V -->|no| F2["FAILURE<br/>kao_invalid · key_type_disabled<br/>unsupported_key_type · invalid_ephemeral_key"]
    V -->|yes| K{Key lookup}
    K -->|not found| F7["FAILURE<br/>key_not_found"]
    K -->|unavailable| E0["ERROR<br/>key_lookup_failed"]
    K -->|ok| M{Key manager available?}
    M -->|no| E3["ERROR<br/>key_manager_unavailable"]
    M -->|yes| D{"DEK decrypts and<br/>binding verifies?"}
    D -->|no| F3["FAILURE · suspected_tamper: true<br/>dek_decrypt_failed · policy_binding_missing<br/>policy_binding_malformed · policy_binding_mismatch"]
    D -->|yes| E{Authorization}
    E -->|deny| F4["FAILURE<br/>policy_denied"]
    E -->|rejected| F5["FAILURE<br/>authz_rejected"]
    E -->|unavailable or cancelled| E1["ERROR<br/>authz_unavailable · context_cancelled"]
    E -->|permit| G{Session key and encapsulation}
    G -->|invalid key or EC disabled| F6["FAILURE<br/>invalid_client_public_key · ec_rewrap_disabled"]
    G -->|KAS fault| E2["ERROR<br/>session_key_error · encapsulation_failed"]
    G -->|ok| S[SUCCESS]

    classDef success fill:#d4edda,stroke:#28a745,color:#000
    classDef failure fill:#fde2e1,stroke:#d9534f,color:#000
    classDef error fill:#e2e3e5,stroke:#6c757d,color:#000
    class S success
    class F1,F2,F2A,F3,F3A,F4,F5,F6,F7 failure
    class E0,E1,E2,E3 error
```

## Outcome matrix

| Stage | Case | Result | `failure_reason` | Tamper | Verified | Scope |
|---|---|---|---|---|---|---|
| Request | SRT parse or claims invalid | failure | `srt_invalid` | false | false | request |
| Request | SRT signature invalid | failure | `srt_signature_invalid` | true | false | request |
| Request | SRT request body invalid | failure | `request_body_invalid` | false | false | request |
| Request | Client key missing, invalid, or unsupported | failure | `invalid_client_public_key` | false | false | request |
| Request | Access token or entity missing | failure | `missing_access_token` | false | false | request |
| Request | Additional context invalid | failure | `invalid_rewrap_context` | false | false | request |
| Policy request | Request or policy nil; policy ID empty | failure | `invalid_request` | false | false | request |
| Policy request | No KAOs; policy valid | failure | `kao_invalid` | false | false | request |
| Policy request | No KAOs; policy invalid | failure | `policy_body_invalid` | true | false | request |
| KAO validation | Duplicate KAO ID | failure | `kao_invalid` | false | false | KAO |
| Integrity | Policy body invalid | failure | `policy_body_invalid` | true | false | KAO |
| KAO validation | KAO nil, wrapped key empty, or required key ID missing | failure | `kao_invalid` | false | false | KAO |
| KAO validation | EC, hybrid, or ML-KEM disabled | failure | `key_type_disabled` | false | false | KAO |
| KAO validation | Key type unsupported | failure | `unsupported_key_type` | false | false | KAO |
| KAO validation | EC ephemeral key invalid | failure | `invalid_ephemeral_key` | false | false | KAO |
| Key lookup | Key ID not found or no legacy RSA key IDs | failure | `key_not_found` | false | false | KAO |
| Key lookup | Registry unavailable | error | `key_lookup_failed` | false | false | KAO |
| Key management | Manager unavailable | error | `key_manager_unavailable` | false | false | KAO |
| Integrity | DEK decryption failed | failure | `dek_decrypt_failed` | true | false | KAO |
| Integrity | Policy binding missing | failure | `policy_binding_missing` | true | false | KAO |
| Integrity | Policy binding malformed | failure | `policy_binding_malformed` | true | false | KAO |
| Integrity | Policy binding mismatch | failure | `policy_binding_mismatch` | true | false | KAO |
| Authorization | Decision denied | failure | `policy_denied` | false | true | KAO |
| Authorization | Service rejected request | failure | `authz_rejected` | false | true | KAO |
| Authorization | Service unavailable | error | `authz_unavailable` | false | true | KAO |
| Authorization | Context cancelled | error | `context_cancelled` | false | true | KAO |
| Rewrap | Client encryptor creation failed | failure | `invalid_client_public_key` | false | true | KAO |
| Rewrap | EC rewrap disabled | failure | `ec_rewrap_disabled` | false | true | KAO |
| Rewrap | Session key serialization failed | error | `session_key_error` | false | true | KAO |
| Rewrap | DEK encapsulation failed | error | `encapsulation_failed` | false | true | KAO |
| Complete | Rewrapped key returned | success | — | false | true | KAO |
| Fallback | KAO unclassified | error | `rewrap_incomplete` | false | preserved | KAO |
| Defensive | Legacy v1 result count invalid | failure | `invalid_request` | false | false | request |

Defensive request events may accompany KAO events.

## Metadata

- Non-success events include `failure_reason`.
- All events include `policy_verified` and `suspected_tamper`; only KAO events
  include `kao_id`.
- `object.id` is the verified policy UUID, then the request policy ID, or empty.
- Unverified parsed UUIDs are recorded as `claimed_policy_uuid` metadata.
- `object.attributes` is populated only after policy verification.
- Stage-wide failures preserve earlier, more specific KAO audit outcomes.
- Downstream mappings must treat denials as `failure`; use
  `suspected_tamper: true` for integrity alerts.
