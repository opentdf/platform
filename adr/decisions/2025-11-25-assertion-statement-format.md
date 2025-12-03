# ADR: Explicit Typing and Encoding via Hyphenated Format Suffixes for `assertions[].statement`

- Status: proposed
- Date: 2025-11-25

## Context and Problem Statement

OpenTDF manifests (TDF) include assertion statements with `assertions[].statement.format` and `assertions[].statement.value` fields. Ambiguity exists regarding:
1.  **Serialization:** whether `assertions[].statement.value` is a raw JSON object or a serialized string.
2.  **Encoding:** how to represent binary data or compressed content safely.
3.  **Parsing:** Consumers currently have to "guess" if they should unmarshal a string, decode Base64, or traverse a JSON object.

We need a deterministic way to signal both the **Content-Type** (what the data *is*) and the **Content-Encoding** (how the data is *represented* in the manifest) within the `assertions[].statement.format` field.

## Decision

The `assertions[].statement.format` field MUST follow the syntax `<ContentType>-<Encoding>`. This explicitly defines how the `assertions[].statement.value` is serialized and how it should be decoded.

### 1. Format Syntax
The `assertions[].statement.format` string is composed of two parts separated by a hyphen:
```text
assertions[].statement.format = {ContentType}-{Encoding}
```

#### Allowed Encodings
The `<Encoding>` suffix dictates the serialization type of the `assertions[].statement.value`:

| Suffix | Value Type | Description |
| :--- | :--- | :--- |
| **`-object`** | JSON Object/Array | The `assertions[].statement.value` is embedded as a raw JSON structure. (Only valid for structured types like `json`). |
| **`-string`** | String | The `assertions[].statement.value` is the content serialized into a string (e.g., JSON stringified, or plain text). |
| **`-base64`** | String | The `assertions[].statement.value` is the binary byte sequence of the content, encoded as a standard Base64 string. |

#### Common Content Types
The `<ContentType>` prefix indicates the semantic type of the data:
- `json`
- `xml`
- `text`
- `binary` (generic), or specific binary types: `image`, `pdf`, `audio`, `video`
- Structured binary: `protobuf`, `cbor`, `msgpack`
- Compressed: `gzip`

### 2. Standardized Formats

Producers and Consumers MUST support the following combinations:

#### A. JSON Formats
- **`json-object`**:
  - `assertions[].statement.value`: Raw JSON object or array.
  - *Use case:* Human readability, debugging, simple structure.
  - *Warning:* Canonicalization (JCS) is required for stable signatures.
- **`json-string`**:
  - `assertions[].statement.value`: The JSON document serialized as a UTF-8 string.
  - *Use case:* Embedding JSON where strict whitespace preservation or simple string-signing is required.
- **`json-base64`**:
  - `assertions[].statement.value`: The JSON document serialized to bytes, then Base64 encoded.
  - *Use case:* Arbitrary bytes, compressed JSON (e.g. gzipped), or avoiding escaping issues.

#### B. Text/XML Formats
- **`text-string`**: Plain text stored directly in `assertions[].statement.value`.
- **`xml-string`**: XML document stored as a string in `assertions[].statement.value`.
- **`xml-base64`**: XML document bytes as Base64 in `assertions[].statement.value`.

#### C. Binary Formats
- **`binary-base64`**: Generic binary data (equivalent to `application/octet-stream`) in `assertions[].statement.value`.
- **`image-base64`**: Image data (e.g., PNG/JPG bytes) in `assertions[].statement.value`.
- **`pdf-base64`**: PDF document bytes in `assertions[].statement.value`.
- **`audio-base64`**: Audio data (e.g., WAV/MP3 bytes) in `assertions[].statement.value`.
- **`video-base64`**: Video data (e.g., MP4/WebM bytes) in `assertions[].statement.value`.

#### D. Structured Binary Formats
- **`protobuf-base64`**: Protocol Buffers serialized message as Base64 in `assertions[].statement.value`.
- **`cbor-base64`**: CBOR (Concise Binary Object Representation) encoded data as Base64 in `assertions[].statement.value`.
- **`msgpack-base64`**: MessagePack encoded data as Base64 in `assertions[].statement.value`.

#### E. Compressed Formats
- **`gzip-base64`**: Gzip-compressed data as Base64 in `assertions[].statement.value`. The underlying content type should be documented in the `assertions[].statement.schema` field.

### 3. Examples

**Format: `json-object`**
*Equivalent to Content-Type: application/json*
```json
{
  "format": "json-object",
  "value": {
    "roles": ["analyst", "manager"],
    "limit": 100
  }
}
```

**Format: `json-string`**
*Equivalent to Content-Type: application/json (serialized)*
```json
{
  "format": "json-string",
  "value": "{\"roles\":[\"analyst\",\"manager\"],\"limit\":100}"
}
```

**Format: `json-base64`**
*Equivalent to Content-Type: application/json; Content-Encoding: base64*
```json
{
  "format": "json-base64",
  "value": "eyJyb2xlcyI6WyJhbmFseXN0IiwibWFuYWdlciJdLCJsaW1pdCI6MTAwfQ=="
}
```

**Format: `binary-base64` (e.g. compressed data)**
*Equivalent to Content-Type: application/gzip; Content-Encoding: base64*
```json
{
  "format": "binary-base64",
  "value": "H4sIAAAAAAAA/..."
}
```

## Rationale

- **Explicitness:** Parsing logic becomes switch-statement simple. Split `assertions[].statement.format` on the last hyphen; the right side tells you how to read the bytes (Raw, String, Base64), the left side tells you what to do with them.
- **Flexibility:** Supports the user requirement to allow `json-object` for readability while offering `json-string` or `json-base64` for situations requiring strict serialization or binary safety.
- **Handling Binary:** Solves the issue of embedding images or zipped policies by enforcing the `-base64` suffix, ensuring no invalid UTF-8 characters break the JSON manifest.

## Implications

- **For Producers:**
    - Must choose the suffix appropriate for the data.
    - If using `json-object`, must accept that byte-for-byte signature verification is harder (requires canonicalization).
- **For Consumers:**
    - Must parse the `assertions[].statement.format` suffix.
    - If `-object`: Treat `assertions[].statement.value` as structured data.
    - If `-string`: Use `assertions[].statement.value` directly (if text) or unquote (if JSON).
    - If `-base64`: Decode `assertions[].statement.value` string to bytes.
- **For Signing:**
    - Signatures are generated over the byte representation of `assertions[].statement.value` **as it appears in the manifest**.
    - For `json-object`, this means the signature depends on the JSON library's serialization (whitespace/ordering) unless a canonicalization layer is applied prior to signing.

## Considered Options

1. **`assertions[].statement.format` = "json" (Ambiguous)**
   - *Status Quo.* Rejected because it leads to SDK parsing drift (some expect string, some expect object).
2. **MIME Types (`application/json`)**
   - *Rejected.* While standard, it doesn't solve the "Object vs String" serialization ambiguity within the host JSON format without complex rules.
3. **Hyphenated Suffixes (CHOSEN)**
   - *Pros:* Human readable, easy to parse, explicit.
   - *Cons:* Non-standard (custom to OpenTDF), requires registry of allowed prefixes.

## Edge Cases and Assertion Handling

### Format Validation Edge Cases

| Scenario | Expected Behavior |
| :--- | :--- |
| **Empty `format` field** | MUST fail validation. Format is required. |
| **Unknown format suffix** (e.g., `json-unknown`) | SHOULD fail validation or be handled per verification mode (see below). |
| **Unknown content type prefix** (e.g., `custom-base64`) | MAY be accepted if the encoding suffix is valid; consumer treats content as opaque bytes. |
| **Empty `value` field** | Valid only if the format explicitly allows empty content (e.g., `text-string` with empty text). For `*-base64`, empty string decodes to zero bytes. |
| **Null `value` field** | MUST fail validation. Value is required when format is specified. |
| **Whitespace-only `value`** | For `-string`: Valid (whitespace is content). For `-base64`: Invalid if not valid Base64. For `-object`: Invalid JSON. |

### Encoding Edge Cases

| Scenario | Expected Behavior |
| :--- | :--- |
| **Invalid Base64 in `-base64` format** | MUST fail during decode. Consumers MUST NOT silently skip. |
| **Base64 with padding vs without** | Both standard (with `=` padding) and unpadded Base64 SHOULD be accepted for interoperability. |
| **Base64 URL-safe vs standard alphabet** | Producers SHOULD use standard Base64 (RFC 4648 §4). Consumers MAY accept URL-safe (RFC 4648 §5) for compatibility. |
| **UTF-8 BOM in `-string` values** | Producers SHOULD NOT include BOM. Consumers SHOULD handle BOM gracefully if present. |
| **Non-UTF-8 text in `-string`** | Invalid. All `-string` values MUST be valid UTF-8. Use `-base64` for arbitrary byte sequences. |

### JSON-Specific Edge Cases

| Scenario | Expected Behavior |
| :--- | :--- |
| **`json-object` with duplicate keys** | Behavior is undefined per JSON spec. Producers MUST NOT emit duplicate keys. Consumers MAY reject or use last-value-wins. |
| **`json-object` key ordering** | Order is NOT guaranteed. For signing, use JCS (RFC 8785) canonicalization or prefer `json-string`/`json-base64`. |
| **`json-string` with pretty-printed JSON** | Valid. The string is the exact byte sequence. Whitespace is preserved. |
| **`json-string` double-encoding** | Invalid. Producers MUST NOT double-encode. Value should decode to valid JSON in one step. |
| **`json-object` with non-JSON values** (e.g., `undefined`, `NaN`) | Invalid. MUST be valid JSON per RFC 8259. |

### Assertion Binding Edge Cases

| Scenario | Expected Behavior |
| :--- | :--- |
| **Missing `binding` on assertion** | MUST fail in FailFast and Strict modes. May warn in Permissive mode but signature verification is skipped. |
| **Empty `binding.signature`** | MUST fail. Assertions with empty signatures are treated as unsigned. |
| **Signature over wrong hash** | MUST fail verification. Indicates tampering or format mismatch. |
| **Assertion with unknown `schema`** | Behavior depends on verification mode: Strict fails, FailFast/Permissive skip with warning. |
| **Multiple assertions with same `id`** | SHOULD fail validation. Assertion IDs MUST be unique within a manifest. |

### Verification Mode Behavior

Consumers MUST respect the configured verification mode when handling edge cases:

| Mode | Unknown Format | Validation Failure | Missing Binding |
| :--- | :--- | :--- | :--- |
| **Permissive** | Skip + warn | Log + continue | **FAIL** |
| **FailFast** (default) | Skip + warn | **FAIL** | **FAIL** |
| **Strict** | **FAIL** | **FAIL** | **FAIL** |

## Test Guidance

### Parser Logic Tests
1. Check `assertions[].statement.format`.
2. If ends with `-object`: Assert `assertions[].statement.value` is JSON Object/Array. Return `assertions[].statement.value`.
3. If ends with `-string`: Assert `assertions[].statement.value` is String. Return `assertions[].statement.value`.
4. If ends with `-base64`: Assert `assertions[].statement.value` is String. Decode Base64. Return Bytes.

### Format/Encoding Validation Tests
- Create a manifest with `json-object` and ensure it fails if `assertions[].statement.value` is a string.
- Create a manifest with `json-string` and ensure it fails if `assertions[].statement.value` is a raw object.
- Verify `json-base64` correctly decodes to the original JSON bytes.
- Verify invalid Base64 in `*-base64` formats produces a clear error.

### Edge Case Tests
- **Empty value**: Test that `text-string` accepts empty string, `json-object` rejects empty.
- **Null value**: Test that all formats reject null value.
- **Double-encoding**: Test that `json-string` with `"\"{\\\"key\\\":\\\"value\\\"}\""` is detected or handled consistently.
- **Invalid UTF-8**: Test that `-string` formats reject invalid UTF-8 byte sequences.
- **Large payloads**: Test Base64 encoding/decoding of payloads >1MB to ensure no truncation.

### Canonicalization Tests
- Verify that `json-object` values produce consistent hashes when using JCS canonicalization.
- Verify that `json-string` byte sequences are used directly for hash computation (no re-serialization).
- Test that key ordering differences in `json-object` produce different raw hashes but identical JCS-canonicalized hashes.

### Assertion Binding Tests
- Verify signature computation uses the correct byte representation per format.
- Test that modifying `assertions[].statement.value` invalidates the binding signature.
- Test cross-SDK compatibility: assertion signed in Go SDK verifies in Java/JS SDKs and vice versa.
