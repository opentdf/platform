# Add KAS Name to Registry

```mermaid

erDiagram

    KeyAccessServer {
        uuid       id                PK
        varchar    uri               UK
        varchar    name              UK "new optional name column"
        jsonb      public_key
        jsonb      metadata
    }
```
