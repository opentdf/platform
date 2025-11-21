# Rewrap Endpoint Flow Diagram

## Component Overview with Line Numbers

```mermaid
graph TB
    subgraph "Client"
        C[Client Application]
    end
    
    subgraph "KAS Service"
        RH[Rewrap Handler<br/>kas/access/rewrap.go:399]
        SRT[SRT Verification<br/>extractSRTBody:197]
        EI[Entity Info<br/>getEntityInfo:334]
        PDP[Access PDP<br/>canAccess:31<br/>accessPdp.go]
        REWRAP[Rewrap Logic<br/>tdf3Rewrap:668<br/>nanoTDFRewrap:794]
    end
    
    subgraph "Authorization Service V2"
        AS[Authorization Service<br/>GetDecision:107<br/>GetDecisionMultiResource:156<br/>authorization/v2/authorization.go]
        JITPDP[Just-In-Time PDP<br/>NewJustInTimePDP:66<br/>internal/access/v2/pdp.go]
    end
    
    subgraph "Policy Service"
        PS[Policy Service]
        ATTR[Attribute Definitions]
        SM[Subject Mappings]
        RR[Resource Registry]
    end
    
    subgraph "Entity Resolution"
        ERS[Entity Resolution Service<br/>JWT Claims]
    end
    
    C -->|POST /kas/v2/rewrap<br/>with SRT| RH
    RH --> SRT
    RH --> EI
    EI -->|Extract from context| ERS
    RH -->|Extract policies<br/>from KAOs| PDP
    PDP -->|Check attributes:122| AS
    AS --> JITPDP
    JITPDP -->|Load policy data| PS
    PS --> ATTR
    PS --> SM
    PS --> RR
    AS -->|PERMIT/DENY| PDP
    PDP -->|Authorization result| RH
    RH -->|If authorized| REWRAP
    REWRAP -->|Rewrapped keys| C
    RH -->|If denied<br/>403 Forbidden| C
```

## Detailed Sequence Flow with Line Numbers

```mermaid
sequenceDiagram
    participant Client
    participant KAS as KAS Service
    participant AuthZ as Authorization Service V2
    participant Policy as Policy Service
    participant ERS as Entity Resolution
    
    Client->>KAS: POST /kas/v2/rewrap<br/>Request with SRT & KAOs
    
    activate KAS
    KAS->>KAS: extractSRTBody()<br/>rewrap.go:197<br/>Verify signed request token
    KAS->>ERS: getEntityInfo()<br/>rewrap.go:334<br/>Extract entity from JWT
    ERS-->>KAS: Entity token & claims
    
    KAS->>KAS: Decode policies from KAOs<br/>rewrap.go:465 (TDF3)<br/>rewrap.go:884 (NanoTDF)
    
    KAS->>KAS: canAccess()<br/>accessPdp.go:31<br/>Prepare authorization check
    KAS->>AuthZ: GetDecision/GetDecisionMultiResource<br/>authorization.go:107/156<br/>Entity, Action="Read", Resources=[attribute URIs]
    
    activate AuthZ
    AuthZ->>Policy: Load attribute definitions
    Policy-->>AuthZ: Attribute rules & values
    AuthZ->>Policy: Load subject mappings
    Policy-->>AuthZ: Subject mapping conditions
    
    AuthZ->>AuthZ: Evaluate entity claims<br/>pdp.go:66<br/>against subject mappings
    AuthZ->>AuthZ: Apply attribute rules<br/>(ALL_OF, ANY_OF, HIERARCHY)
    AuthZ-->>KAS: Decision: PERMIT/DENY<br/>for each resource
    deactivate AuthZ
    
    alt Authorization Success
        KAS->>KAS: tdf3Rewrap():668 or<br/>nanoTDFRewrap():794<br/>Decrypt DEK, re-encrypt for client
        KAS-->>Client: 200 OK<br/>Rewrapped keys & session info
    else Authorization Failure
        KAS-->>Client: 403 Forbidden<br/>Access denied
    end
    
    KAS->>KAS: Audit log the operation
    deactivate KAS
```

## Key Data Structures

```mermaid
classDiagram
    class RewrapRequest {
        +SignedRequestToken string
        +KeyAccessObjects []KeyAccess
    }
    
    class KeyAccess {
        +Type string (wrapped/remote/shared)
        +URL string
        +Protocol string
        +WrappedKey string
        +PolicyBinding string
        +EncryptedMetadata string
    }
    
    class Policy {
        +UUID string
        +DataAttributes []DataAttribute
        +Dissemination []string
    }
    
    class DataAttribute {
        +URI string (e.g., https://example.com/attr/classification/value/secret)
    }
    
    class AuthorizationRequest {
        +Entity EntityToken
        +Action string ("Read")
        +Resources []Resource
    }
    
    class Resource {
        +Attributes []AttributeValueFQN
    }
    
    class Decision {
        +Decision string (PERMIT/DENY)
        +EntityID string
        +ResourceID string
    }
    
    RewrapRequest --> KeyAccess
    KeyAccess --> Policy
    Policy --> DataAttribute
    AuthorizationRequest --> Resource
```

## Authorization Decision Logic

```mermaid
graph TD
    A[Start: Entity requests rewrap] --> B{Extract policies<br/>from KAOs}
    B --> C{Policy has<br/>data attributes?}
    C -->|No| D[Auto-grant access]
    C -->|Yes| E[Create resource objects<br/>with attribute URIs]
    E --> F[Call Authorization Service]
    F --> G{Load subject mappings<br/>for attributes}
    G --> H{Entity matches<br/>subject conditions?}
    H -->|Yes| I{Evaluate attribute<br/>rules}
    I -->|ALL_OF: Has all attrs| J[PERMIT]
    I -->|ANY_OF: Has any attr| J
    I -->|HIERARCHY: Has parent| J
    I -->|Rules not met| K[DENY]
    H -->|No| K
    J --> L[Rewrap keys]
    K --> M[Return 403]
    D --> L
    L --> N[Return rewrapped keys]
```

## Component Responsibilities with Key File Locations

### KAS Service (Key Access Service)
- **Primary Role**: Handle key rewrap requests
- **Key Files**:
  - Main handler: `service/kas/access/rewrap.go:399`
  - Access control: `service/kas/access/accessPdp.go:31`
  - Service registration: `service/kas/kas.go:37`
- **Responsibilities**:
  - Verify signed request tokens (SRT) - `extractSRTBody():197`
  - Extract and validate policies from Key Access Objects
  - Coordinate with Authorization Service for access decisions - `canAccess():31`
  - Perform actual key rewrapping:
    - RSA/EC for TDF3 - `tdf3Rewrap():668`
    - EC for NanoTDF - `nanoTDFRewrap():794`
  - Audit logging

### Authorization Service V2
- **Primary Role**: Make access control decisions
- **Key Files**:
  - Main service: `service/authorization/v2/authorization.go`
  - PDP implementation: `service/internal/access/v2/pdp.go`
- **Key Functions**:
  - Single resource: `GetDecision():107`
  - Multiple resources: `GetDecisionMultiResource():156`
  - PDP creation: `NewJustInTimePDP():66`
- **Responsibilities**:
  - Evaluate entity claims against subject mappings
  - Apply attribute rules (ALL_OF, ANY_OF, HIERARCHY)
  - Return PERMIT/DENY decisions for resources
  - Support both single and bulk resource decisions

### Policy Service
- **Primary Role**: Store and manage policy configuration
- **Key Files**:
  - Attribute definitions: `service/policy/attributes/`
  - Subject mappings: `service/policy/subjectmapping/`
  - Resource registry: `service/policy/resourcemapping/`
- **Responsibilities**:
  - Maintain attribute definitions and hierarchies
  - Store subject mappings (who can access what)
  - Provide resource registry for registered resources
  - Supply policy data to Authorization Service

### Entity Resolution Service
- **Primary Role**: Manage entity identity
- **Key Integration Points**:
  - Entity info extraction: `service/kas/access/rewrap.go:334`
  - JWT validation through middleware
- **Responsibilities**:
  - Validate JWT tokens
  - Extract entity claims and attributes
  - Provide entity context for authorization

## Key Security Features

1. **Signed Request Tokens (SRT)**: Cryptographically signed tokens prevent replay attacks
2. **DPoP (Demonstrating Proof of Possession)**: Optional additional security layer
3. **Policy Binding**: Cryptographic binding between policy and encrypted data
4. **Attribute-Based Access Control (ABAC)**: Fine-grained access based on data and entity attributes
5. **Audit Logging**: Complete audit trail of all access decisions and operations