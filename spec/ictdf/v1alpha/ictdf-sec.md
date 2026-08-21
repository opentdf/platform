# ICTDF-SEC: Security Considerations

| | |
|---|---|
| Document | ICTDF-SEC |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Draft |
| Depends on | None |
| Referenced by | All IC-TDF components |

## 1. Parser limits

An IC-TDF instance is an XML document from an untrusted source. Every parser MUST apply
the following before schema validation, binding verification, or key retrieval.

| Input | Required handling |
|---|---|
| External entities | Disable entity expansion and external DTD loading; IC-TDF uses no DTD |
| Entity expansion | Reject recursive and quadratic expansion regardless of entity source |
| `xsi:schemaLocation` | Ignore for validation; resolve schemas from a trusted local catalog only |
| Element depth | Enforce a finite maximum; TDC nesting is recursive and unbounded in the schema |
| Document and node count | Enforce finite maxima before building a tree |
| `base64Binary` content | Bound the decoded length before allocation |
| `ReferenceValuePayload/@uri` | Never dereferenced during validation; see ICTDF-LOC |
| `RemoteStoredKey/@uri` | Never dereferenced during validation; see ICTDF-KAS |

`StructuredPayload` and `StructuredStatement` admit `xs:any` with
`processContents="skip"`. The XSD therefore imposes no constraint on their content, and
a validator MUST treat that content as hostile until ICTDF-VAL Step 2 has validated it in
isolation against its own governing schema.

## 2. Trust boundaries

- A TDF instance carries handling metadata; it does not carry authority. Trust in an
  IC-EDH or ARH security block derives from the binding over it and from the trust anchor
  of the signer, never from its presence in the document.
- `Signer/@subject`, `@issuer`, and `@serial` are RFC 5280 identifiers, not certificates.
  The verifier resolves them to a certificate through trusted local configuration and
  performs path building, validity, and revocation checking outside this suite.
- `RemoteStoredKey/@uri` and `ReferenceValuePayload/@uri` identify resources; URI
  ownership gives uniqueness, not trust. Resolution policy is a deployment decision.
- `PreSharedKey/@alias` and `@store` name a key in an out-of-band arrangement. The
  document proves nothing about that arrangement.
- `AttachedKey` places key material in the document. It has no confidentiality value and
  MUST NOT be used for data requiring protection in transit or at rest.

## 3. Binding and verification order

- A binding authenticates the normalized bytes enumerated for its scope, and nothing
  else. Content outside the scope's coverage table is unauthenticated even when it sits
  inside the same TDO. See ICTDF-BND.
- The `Signer`, `SignatureValue`, `BoundValueList` child order exists so that a streaming
  parser can verify in a single pass. Implementations MUST NOT rely on that order for
  security; a streaming verifier MUST NOT act on any part of a TDO before the signature
  covering it verifies.
- `SignatureValue/@normalizationMethod` and `@signatureAlgorithm` are attacker-controlled
  inputs. A verifier MUST reject values outside its configured allow-list before
  performing any canonicalization or signature operation, and MUST NOT infer a default.
- `@includesStatementMetadata` changes what the signature covers. A verifier MUST use the
  declared value, and MUST reject a document that omits it when `BoundValueList` is
  absent (`IC-TDF-ID-00010`), because an absent declaration makes coverage ambiguous.
- Canonicalization is a rewriting step over untrusted input. Comment-preserving
  normalization methods enlarge the signed surface; comment-stripping methods leave
  comments unauthenticated and removable. Neither is safe by default; a deployment MUST
  choose and enforce one.
- SHA-1 and `SHA1with*` are permitted by the source controlled vocabularies. Producers
  MUST NOT emit them, and verifiers SHOULD reject them, because collision resistance is
  broken.

## 4. Encryption and key access

- An encrypted part is described by `EncryptionInformation`. Presence of that element and
  the value of `@isEncrypted` MUST agree (`IC-TDF-ID-00014`, `IC-TDF-ID-00015`); a
  mismatch is a validation failure, not a hint to be repaired.
- Layered encryption is ordered by `@sequenceNum`, highest outermost. A gap, duplicate,
  or missing sequence number makes the layering ambiguous and MUST be rejected
  (`IC-TDF-ID-00040`, `IC-TDF-ID-00041`).
- `EncryptionMethod/@algorithm` is a URI chosen by the producer. A consumer MUST reject
  unknown algorithm URIs rather than guessing a near match, and MUST validate that the
  supplied `IVParams`, `Nonce`, `Tweak`, `AuthenticationTag`, and
  `AdditionalAuthenticatedData` are those the algorithm requires.
- Nonce and IV reuse under one key breaks the selected mode. Producers MUST use a secure
  random source and MUST NOT reuse an IV across encryptions with the same key.
- Unauthenticated modes leave ciphertext malleable. Where the payload is not covered by a
  binding and the encryption method provides no authentication tag, the object provides
  no integrity for that payload at all.
- Failures to unwrap, decrypt, or authenticate MUST be reported as a single opaque class.
  Distinguishing "wrong key" from "bad padding" from "policy denied" is an oracle.
- Key material, plaintext, and unwrapped keys MUST NOT be logged or returned on failure.

## 5. Markings, states, and disclosure

- The handling assertion for a TDO or TDC MUST NOT be encrypted. Its cleartext is what
  allows a guard to route the object, and it is therefore visible to everyone who can see
  the object at all.
- An encrypted part needs two markings: one describing the ciphertext as it travels and
  one describing the plaintext it protects. The `unencrypted` marking is carried
  externally, as `edh:ExternalEdh` or `arh:ExternalSecurity`, and is deliberately outside
  the rollup so that it does not raise the object's visible classification. See
  ICTDF-POL §5.
- Rollup means the TDO- or TDC-scope handling assertion reflects the most restrictive
  markings of everything it covers. A producer that fails to roll up under-marks the
  object; a producer that rolls up the plaintext marking of an encrypted part over-marks
  it and may itself be a disclosure.
- Filenames, media types, URIs, and identifiers are unencrypted metadata. `@filename`,
  `@mediaType`, and `ReferenceValuePayload/@uri` leak information about the protected
  content and MUST be treated as part of the object's disclosure surface.
- A linked resource's classification does not raise the classification of the TDO that
  links to it, but an embedded resource's does. A producer that inlines a reference
  changes the object's marking obligations.

## 6. Validation hazards

- ISM and NTK constraint rules are not TDO-aware. Running them across a whole TDF
  produces both false positives and false negatives; they MUST be run only on the
  fragments ICTDF-VAL defines.
- Extension-point content is validated in isolation. A validator that skips Step 2
  accepts arbitrary foreign XML inside a conforming-looking TDO.
- `xs:ID` and `xs:IDREF` are document-scoped. `IC-TDF-ID-00011` requires that a bound
  `@idRef` resolve to a descendant of the same TDO; a validator relying only on XML ID
  uniqueness will accept cross-TDO references inside a TDC.
- Version consistency rules (`IC-TDF-ID-00046` through `IC-TDF-ID-00053`) exist because
  mixed versions of a dependent specification inside one skeleton make marking semantics
  undecidable. They are not stylistic.
- A validator MUST fail closed. An unresolvable schema, an unsupported normalization
  method, an unrecognized CVE value, or an unrunnable rule set is a rejection, not a
  warning.
