# ADR: Explicit Typing and Encoding via Hyphenated Format Suffixes

- Status: proposed
- Date: 2025-11-25

## Context and Problem Statement

OpenTDF manifests (TDF) include policy statements with `Format` and `Value` fields. Ambiguity exists regarding:
1.  **Serialization:** whether `Value` is a raw JSON object or a serialized string.
2.  **Encoding:** how to represent binary data or compressed content safely.
3.  **Parsing:** Consumers currently have to "guess" if they should unmarshal a string, decode Base64, or traverse a JSON object.

We need a deterministic way to signal both the **Content-Type** (what the data *is*) and the **Content-Encoding** (how the data is *represented* in the manifest) within the `Format` field.

## Decision

The `Statement.Format` field MUST follow the syntax `<ContentType>-<Encoding>`. This explicitly defines how the `Statement.Value` is serialized and how it should be decoded.

### 1. Format Syntax
The `Format` string is composed of two parts separated by a hyphen:
```text
Format = {ContentType}-{Encoding}
```

#### Allowed Encodings
The `<Encoding>` suffix dictates the serialization type of the `Statement.Value`:

| Suffix | Value Type | Description |
| :--- | :--- | :--- |
| **`-object`** | JSON Object/Array | The `Value` is embedded as a raw JSON structure. (Only valid for structured types like `json`). |
| **`-string`** | String | The `Value` is the content serialized into a string (e.g., JSON stringified, or plain text). |
| **`-base64`** | String | The `Value` is the binary byte sequence of the content, encoded as a standard Base64 string. |

#### Common Content Types
The `<ContentType>` prefix indicates the semantic type of the data:
- `json`
- `xml`
- `text`
- `binary` (or specific types like `image`, `pdf`, etc.)

### 2. Standardized Formats

Producers and Consumers MUST support the following combinations:

#### A. JSON Formats
- **`json-object`**:
  - `Value`: Raw JSON object or array.
  - *Use case:* Human readability, debugging, simple structure.
  - *Warning:* Canonicalization (JCS) is required for stable signatures.
- **`json-string`**:
  - `Value`: The JSON document serialized as a UTF-8 string.
  - *Use case:* Embedding JSON where strict whitespace preservation or simple string-signing is required.
- **`json-base64`**:
  - `Value`: The JSON document serialized to bytes, then Base64 encoded.
  - *Use case:* Arbitrary bytes, compressed JSON (e.g. gzipped), or avoiding escaping issues.

#### B. Text/XML Formats
- **`text-string`**: Plain text stored directly.
- **`xml-string`**: XML document stored as a string.
- **`xml-base64`**: XML document bytes as Base64.

#### C. Binary Formats
- **`binary-base64`**: Generic binary data (equivalent to `application/octet-stream`).
- **`image-base64`**: Image data (e.g., PNG/JPG bytes).

### 3. Examples

**Format: `json-object`**
*Equivalent to Content-Type: application/json*
```json
{
  "Format": "json-object",
  "Value": {
    "roles": ["analyst", "manager"],
    "limit": 100
  }
}
```

**Format: `json-string`**
*Equivalent to Content-Type: application/json (serialized)*
```json
{
  "Format": "json-string",
  "Value": "{\"roles\":[\"analyst\",\"manager\"],\"limit\":100}"
}
```

**Format: `json-base64`**
*Equivalent to Content-Type: application/json; Content-Encoding: base64*
```json
{
  "Format": "json-base64",
  "Value": "eyJyb2xlcyI6WyJhbmFseXN0IiwibWFuYWdlciJdLCJsaW1pdCI6MTAwfQ=="
}
```

**Format: `binary-base64` (e.g. compressed data)**
*Equivalent to Content-Type: application/gzip; Content-Encoding: base64*
```json
{
  "Format": "binary-base64",
  "Value": "H4sIAAAAAAAA/..."
}
```

## Rationale

- **Explicitness:** Parsing logic becomes switch-statement simple. Split the format on the last hyphen; the right side tells you how to read the bytes (Raw, String, Base64), the left side tells you what to do with them.
- **Flexibility:** Supports the user requirement to allow `json-object` for readability while offering `json-string` or `json-base64` for situations requiring strict serialization or binary safety.
- **Handling Binary:** Solves the issue of embedding images or zipped policies by enforcing the `-base64` suffix, ensuring no invalid UTF-8 characters break the JSON manifest.

## Implications

- **For Producers:**
    - Must choose the suffix appropriate for the data.
    - If using `json-object`, must accept that byte-for-byte signature verification is harder (requires canonicalization).
- **For Consumers:**
    - Must parse the suffix.
    - If `-object`: Treat `Value` as structured data.
    - If `-string`: Use directly (if text) or unquote (if JSON).
    - If `-base64`: Decode string to bytes.
- **For Signing:**
    - Signatures are generated over the byte representation of `Value` **as it appears in the manifest**.
    - For `json-object`, this means the signature depends on the JSON library's serialization (whitespace/ordering) unless a canonicalization layer is applied prior to signing.

## Considered Options

1. **Format = "json" (Ambiguous)**
   - *Status Quo.* Rejected because it leads to SDK parsing drift (some expect string, some expect object).
2. **MIME Types (`application/json`)**
   - *Rejected.* While standard, it doesn't solve the "Object vs String" serialization ambiguity within the host JSON format without complex rules.
3. **Hyphenated Suffixes (CHOSEN)**
   - *Pros:* Human readable, easy to parse, explicit.
   - *Cons:* Non-standard (custom to OpenTDF), requires registry of allowed prefixes.

## Test Guidance

- **Parser Logic:**
    1. Check `Format`.
    2. If ends with `-object`: Assert `Value` is JSON Object/Array. Return `Value`.
    3. If ends with `-string`: Assert `Value` is String. Return `Value`.
    4. If ends with `-base64`: Assert `Value` is String. Decode Base64. Return Bytes.
- **Validation:**
    - Create a manifest with `json-object` and ensure it fails if `Value` is a string.
    - Create a manifest with `json-string` and ensure it fails if `Value` is a raw object.
