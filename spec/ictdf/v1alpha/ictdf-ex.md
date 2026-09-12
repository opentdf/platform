# ICTDF-EX: Worked Examples

| | |
|---|---|
| Document | ICTDF-EX |
| Version | 1 Alpha |
| Source spec | IC-TDF.XML.V2014-DEC-r2017-JUL |
| TDF version | 201412.201707 |
| Status | Informational |
| Depends on | ICTDF-CORE |
| Referenced by | None |

All classification markings below are illustrative. No example contains real classified
data. Examples are non-normative; the modules and the source artifacts govern.

## 1. Conventions used here

Every example declares the TDF namespace and version on the root:

```xml
<TrustedDataObject xmlns="urn:us:gov:ic:tdf"
                   xmlns:tdf="urn:us:gov:ic:tdf"
                   tdf:version="201412.201707">
```

Handling statements repeat a bulky IC-EDH block. It is written out once in §2 and
thereafter abbreviated as:

```xml
<!-- EDH: see §2, with arh:Security ism:classification="U" -->
```

Namespace bindings used throughout:

| Prefix | Namespace |
|---|---|
| `tdf` | `urn:us:gov:ic:tdf` |
| `edh` | `urn:us:gov:ic:edh` |
| `arh` | `urn:us:gov:ic:arh` |
| `ism` | `urn:us:gov:ic:ism` |
| `ntk` | `urn:us:gov:ic:ntk` |
| `icid` | `urn:us:gov:ic:id` |
| `usagency` | `urn:us:gov:ic:usagency` |

## 2. Minimal TDO

The smallest conforming object: a string payload, an object-scope handling assertion, and a
payload-scope handling assertion.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<TrustedDataObject xmlns="urn:us:gov:ic:tdf"
                   xmlns:tdf="urn:us:gov:ic:tdf"
                   tdf:version="201412.201707">
  <tdf:HandlingAssertion tdf:scope="TDO">
    <tdf:HandlingStatement>
      <edh:Edh xmlns:edh="urn:us:gov:ic:edh"
               xmlns:usagency="urn:us:gov:ic:usagency"
               xmlns:icid="urn:us:gov:ic:id"
               xmlns:arh="urn:us:gov:ic:arh"
               xmlns:ism="urn:us:gov:ic:ism"
               usagency:CESVersion="201609"
               icid:DESVersion="1"
               edh:DESVersion="201609"
               arh:DESVersion="3"
               ism:DESVersion="201609.201707"
               ism:ISMCATCESVersion="201709">
        <icid:Identifier>guide://999001/EdhExample</icid:Identifier>
        <edh:DataItemCreateDateTime>2012-05-29T09:00:00Z</edh:DataItemCreateDateTime>
        <edh:ResponsibleEntity edh:role="Custodian">
          <edh:Country>USA</edh:Country>
          <edh:Organization>DIA</edh:Organization>
        </edh:ResponsibleEntity>
        <arh:Security ism:compliesWith="OtherAuthority"
                      ism:resourceElement="true"
                      ism:createDate="2012-05-29"
                      ism:classification="U"
                      ism:ownerProducer="ABW"/>
      </edh:Edh>
    </tdf:HandlingStatement>
  </tdf:HandlingAssertion>
  <tdf:HandlingAssertion tdf:scope="PAYL">
    <tdf:HandlingStatement>
      <!-- EDH: as above -->
    </tdf:HandlingStatement>
  </tdf:HandlingAssertion>
  <tdf:StringPayload>I am an example payload of a string</tdf:StringPayload>
</TrustedDataObject>
```

What makes it conforming:

| Requirement | Where satisfied |
|---|---|
| `@tdf:version` on the root (`IC-TDF-ID-00002`) | Root attribute |
| Exactly one `TDO`-scope handling assertion with an EDH (`IC-TDF-ID-00004`) | First assertion |
| It is first in document order (`IC-TDF-ID-00042`) | First assertion |
| Its ARH block bears `@ism:resourceElement="true"` (`IC-TDF-ID-00016`) | `arh:Security` |
| At least one `PAYL` handling assertion (`IC-TDF-ID-00003`) | Second assertion |
| No `@appliesToState`, because nothing is encrypted (`IC-TDF-ID-00025`) | Absent |
| Exactly one payload | `tdf:StringPayload` |

## 3. Signed assertions

A binding on each handling assertion. Coverage comes from each assertion's scope, not from
the binding.

```xml
<tdf:HandlingAssertion tdf:id="handlingAssertion1" tdf:scope="TDO">
  <tdf:HandlingStatement>
    <!-- EDH: see §2 -->
  </tdf:HandlingStatement>
  <tdf:Binding>
    <tdf:Signer tdf:subject="CN=Example Signer,O=Example,C=US" tdf:issuer="C=US"/>
    <tdf:SignatureValue
        tdf:signatureAlgorithm="SHA256withECDSA"
        tdf:normalizationMethod="http://www.w3.org/2006/12/xml-c14n11"
        tdf:includesStatementMetadata="false"
      >RXhwZWN0ZWQgU3RyaW5nIFZhbHVl</tdf:SignatureValue>
  </tdf:Binding>
</tdf:HandlingAssertion>

<tdf:HandlingAssertion tdf:id="handlingAssertion2" tdf:scope="PAYL">
  <tdf:HandlingStatement>
    <!-- EDH: see §2 -->
  </tdf:HandlingStatement>
  <tdf:Binding>
    <tdf:Signer tdf:subject="CN=Example Signer,O=Example,C=US" tdf:issuer="C=US"/>
    <tdf:SignatureValue
        tdf:signatureAlgorithm="SHA256withECDSA"
        tdf:normalizationMethod="http://www.w3.org/2006/12/xml-c14n11"
        tdf:includesStatementMetadata="false"
      >RXhwZWN0ZWQgU3RyaW5nIFZhbHVl</tdf:SignatureValue>
  </tdf:Binding>
</tdf:HandlingAssertion>

<tdf:Assertion tdf:id="assertion1" tdf:scope="TDO">
  <tdf:StringStatement tdf:isEncrypted="false">This is the first assertion</tdf:StringStatement>
</tdf:Assertion>
<tdf:Assertion tdf:id="assertion2" tdf:scope="TDO">
  <tdf:Base64BinaryStatement tdf:isEncrypted="false"
    >VGhpcyBpcyBhIGJpbmFyeSBzdGF0ZW1lbnQ=</tdf:Base64BinaryStatement>
</tdf:Assertion>
<tdf:StringPayload tdf:filename="myText.txt" tdf:id="payload1" tdf:isEncrypted="false"
  >This is a text document</tdf:StringPayload>
```

Points to read off:

- The `TDO`-scope binding covers all handling statements, both assertion statements, and
  the payload. The `PAYL`-scope binding covers only its own statement and the payload
  (ICTDF-BND §2.1).
- `@includesStatementMetadata` is present because no `BoundValueList` is
  (`IC-TDF-ID-00010`). Its value is `false`, so no `StatementMetadata` is inside either
  signature.
- `Signer` gives `@issuer` and `@subject`, satisfying `IC-TDF-ID-00038`. It names a
  certificate; it does not carry one.
- Two bindings on one object are two independent claims. Requiring both is a deployment
  decision, not something the document states.
- The source example writes `tdf:normalizationMethod="Normalization Method"`, a placeholder.
  A real object MUST use a URI from ICTDF-ALG §2.

## 4. Encrypted payload

AES-GCM over the payload, with the two markings an encrypted part requires.

```xml
<TrustedDataObject xmlns="urn:us:gov:ic:tdf"
                   xmlns:tdf="urn:us:gov:ic:tdf"
                   tdf:version="201412.201707">
  <tdf:HandlingAssertion tdf:scope="TDO">
    <tdf:HandlingStatement>
      <!-- EDH: see §2, ism:classification="U" -->
    </tdf:HandlingStatement>
  </tdf:HandlingAssertion>

  <tdf:HandlingAssertion tdf:scope="PAYL" tdf:appliesToState="unencrypted">
    <tdf:HandlingStatement>
      <edh:ExternalEdh xmlns:edh="urn:us:gov:ic:edh"
                       xmlns:arh="urn:us:gov:ic:arh"
                       xmlns:ism="urn:us:gov:ic:ism"
                       edh:DESVersion="201609" arh:DESVersion="3"
                       ism:DESVersion="201609.201707">
        <!-- identifier, create time, responsible entity elided -->
        <arh:ExternalSecurity ism:compliesWith="USGov USIC"
                              ism:resourceElement="true"
                              ism:createDate="2012-05-28"
                              ism:classification="U"
                              ism:ownerProducer="USA"
                              ism:excludeFromRollup="true"/>
      </edh:ExternalEdh>
    </tdf:HandlingStatement>
  </tdf:HandlingAssertion>

  <tdf:HandlingAssertion tdf:scope="PAYL" tdf:appliesToState="encrypted">
    <tdf:HandlingStatement>
      <!-- EDH: regular edh:Edh, describing the ciphertext -->
    </tdf:HandlingStatement>
  </tdf:HandlingAssertion>

  <tdf:EncryptionInformation>
    <tdf:KeyAccess>
      <tdf:AttachedKey>
        <tdf:KeyValue>abcdefghijklmnop</tdf:KeyValue>
      </tdf:AttachedKey>
    </tdf:KeyAccess>
    <tdf:EncryptionMethod tdf:algorithm="AES">
      <tdf:KeySize>32</tdf:KeySize>
      <tdf:IVParams>YW55IGNhcm5hbCBwbGVhcwYW55IGNhcm5hbCBwbGVhcw</tdf:IVParams>
      <tdf:AdditionalAuthenticatedData>5sA55IG49d5hbCBwbGVhcwa3</tdf:AdditionalAuthenticatedData>
      <tdf:AuthenticationTag>B20abww4lLmNOqa43sas</tdf:AuthenticationTag>
    </tdf:EncryptionMethod>
  </tdf:EncryptionInformation>

  <tdf:Base64BinaryPayload tdf:isEncrypted="true">rTLZ0kO2c3g9</tdf:Base64BinaryPayload>
</TrustedDataObject>
```

Points to read off:

- Two `PAYL` handling assertions, one per data state (`IC-TDF-ID-00026`). The `unencrypted`
  one uses `edh:ExternalEdh` (`IC-TDF-ID-00027`); the `encrypted` one uses a regular
  `edh:Edh` (`IC-TDF-ID-00028`).
- `@ism:excludeFromRollup="true"` keeps the plaintext marking out of the object's rolled-up
  classification (ICTDF-POL §4).
- `@tdf:isEncrypted="true"` and the presence of `EncryptionInformation` agree
  (`IC-TDF-ID-00014`, `IC-TDF-ID-00015`).
- No `@sequenceNum`, because there is one layer (`IC-TDF-ID-00040`).
- `AuthenticationTag` is the payload's only integrity protection here — no binding covers
  the payload.
- Two things in this example are deliberately not production-safe. `@algorithm="AES"` names
  a family rather than a mode, and `AttachedKey` places the key in the document, so the
  object provides no confidentiality (ICTDF-KAO §3.6). The source examples use both for
  brevity.

## 5. Layered encryption

Two layers over one payload. Layer 2 is outermost, so decryption removes it first.

```xml
<tdf:EncryptionInformation tdf:sequenceNum="1">
  <tdf:KeyAccess>
    <tdf:WrappedKey tdf:keyIdentifier="mission-kek-2017">
      <tdf:KeyValue>d3JhcHBlZC1pbm5lci1rZXk=</tdf:KeyValue>
    </tdf:WrappedKey>
  </tdf:KeyAccess>
  <tdf:EncryptionMethod tdf:algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm">
    <tdf:KeySize>32</tdf:KeySize>
    <tdf:IVParams>MTIzNDU2Nzg5MDEy</tdf:IVParams>
    <tdf:AuthenticationTag>dGFnLWZvci1sYXllci0x</tdf:AuthenticationTag>
  </tdf:EncryptionMethod>
</tdf:EncryptionInformation>

<tdf:EncryptionInformation tdf:sequenceNum="2">
  <tdf:KeyAccess>
    <tdf:RemoteStoredKey tdf:protocol="kas" tdf:uri="https://kas.example.gov/keys/9f2a"/>
  </tdf:KeyAccess>
  <tdf:EncryptionMethod tdf:algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm">
    <tdf:KeySize>32</tdf:KeySize>
    <tdf:IVParams>OTg3NjU0MzIxMDk4</tdf:IVParams>
    <tdf:AuthenticationTag>dGFnLWZvci1sYXllci0y</tdf:AuthenticationTag>
  </tdf:EncryptionMethod>
</tdf:EncryptionInformation>
```

Points to read off:

- `@sequenceNum` is required on each because there is more than one (`IC-TDF-ID-00040`),
  and the numbers run 1, 2 with no gap or duplicate (`IC-TDF-ID-00041`).
- Encryption applied layer 1 then layer 2; decryption removes layer 2 then layer 1.
- Each layer has its own IV. Reusing one across layers or objects breaks GCM.
- `@protocol="kas"` is not an IC-TDF-registered name. A consumer matches it against local
  configuration and rejects it otherwise (ICTDF-KAS §2), and resolves the URI through a
  catalog rather than dereferencing it.

## 6. Collection

A TDC with two member TDOs, one collection-scope assertion, and no payload of its own.

```xml
<TrustedDataCollection xmlns="urn:us:gov:ic:tdf"
                       xmlns:tdf="urn:us:gov:ic:tdf"
                       tdf:version="201412.201707">
  <tdf:HandlingAssertion tdf:scope="TDC">
    <tdf:HandlingStatement>
      <!-- EDH: rolled up over both members -->
    </tdf:HandlingStatement>
  </tdf:HandlingAssertion>

  <tdf:Assertion tdf:scope="TDC">
    <tdf:StringStatement>Collection-level description</tdf:StringStatement>
  </tdf:Assertion>

  <tdf:TrustedDataObject>
    <tdf:HandlingAssertion tdf:scope="TDO">
      <tdf:HandlingStatement><!-- EDH --></tdf:HandlingStatement>
    </tdf:HandlingAssertion>
    <tdf:HandlingAssertion tdf:scope="PAYL">
      <tdf:HandlingStatement><!-- EDH --></tdf:HandlingStatement>
    </tdf:HandlingAssertion>
    <tdf:Assertion tdf:scope="PAYL">
      <tdf:StringStatement>First member</tdf:StringStatement>
    </tdf:Assertion>
    <tdf:StringPayload>First payload</tdf:StringPayload>
  </tdf:TrustedDataObject>

  <tdf:TrustedDataObject>
    <tdf:HandlingAssertion tdf:scope="TDO">
      <tdf:HandlingStatement><!-- EDH --></tdf:HandlingStatement>
    </tdf:HandlingAssertion>
    <tdf:HandlingAssertion tdf:scope="PAYL">
      <tdf:HandlingStatement><!-- EDH --></tdf:HandlingStatement>
    </tdf:HandlingAssertion>
    <tdf:StringPayload>Second payload</tdf:StringPayload>
  </tdf:TrustedDataObject>
</TrustedDataCollection>
```

Points to read off:

- Exactly one `TDC`-scope handling assertion with an EDH (`IC-TDF-ID-00005`), first in
  document order (`IC-TDF-ID-00042`), with `@ism:resourceElement="true"`
  (`IC-TDF-ID-00017`).
- Collection assertions use TDC-legal scopes only (`IC-TDF-ID-00007`); member assertions
  use TDO-legal scopes only (`IC-TDF-ID-00006`).
- Member TDOs omit `@tdf:version`; they inherit the collection's (`IC-TDF-ID-00052`
  requires one version across the skeleton).
- The TDC handling assertion is rolled up over both members, including their `ntk:Access`
  (`IC-TDF-ID-00044`).
- Validation recurses: the collection is validated by ICTDF-VAL §5, then each member by §4.

## 7. Scope under extraction

Given a collection carrying:

```xml
<tdf:Assertion tdf:scope="DESC_PAYL">
  <tdf:StringStatement>Applies to every descendant payload</tdf:StringStatement>
</tdf:Assertion>
<tdf:Assertion tdf:scope="TDC_MEMBER">
  <tdf:StringStatement>Applies to each member individually</tdf:StringStatement>
</tdf:Assertion>
```

Extracting one member TDO yields:

```xml
<tdf:Assertion tdf:scope="PAYL">
  <tdf:StringStatement>Applies to every descendant payload</tdf:StringStatement>
</tdf:Assertion>
<!-- the TDC_MEMBER assertion is not carried -->
```

The `DESC_PAYL` assertion is transitive, so it travels and its scope is rewritten to `PAYL`
in the extracted TDO. The `TDC_MEMBER` assertion is non-transitive and describes the
container, which no longer exists.

The extractor also copies in the version declarations inherited from the enclosing TDF,
recomputes rollup, sets `@tdf:version` on the new root, and discards any binding whose
coverage set changed (ICTDF-CORE §5).

## 8. Non-conforming: what each failure looks like

| Document | Rule violated |
|---|---|
| TDO whose first handling assertion is `@scope="PAYL"` | `IC-TDF-ID-00042` |
| TDO with two `TDO`-scope handling assertions | `IC-TDF-ID-00004` |
| `@tdf:appliesToState` on an unencrypted payload's handling assertion | `IC-TDF-ID-00025` |
| Encrypted payload with only one `PAYL` handling assertion | `IC-TDF-ID-00026` |
| `@tdf:isEncrypted="true"` with no `EncryptionInformation` | `IC-TDF-ID-00015` |
| Two `EncryptionInformation` numbered 1 and 3 | `IC-TDF-ID-00041` |
| `SignatureValue` with no `@includesStatementMetadata` and no `BoundValueList` | `IC-TDF-ID-00010` |
| `Signer` with `@subject` but no `@issuer` | `IC-TDF-ID-00038` |
| `tdf:Assertion tdf:scope="DESC_TDO"` inside a TDO | `IC-TDF-ID-00006` |
| Any assertion with `@tdf:scope="EXPLICIT"` | `IC-TDF-ID-00008` |
| `ReferenceValuePayload` with no `edh:ExternalEdh` in the `PAYL` handling assertion | `IC-TDF-ID-00033` |
| Two different `@ism:DESVersion` values in one skeleton | `IC-TDF-ID-00046` |
| `tdf:scope=" "` | `IC-TDF-ID-00001` |
| `@tdf:version="201412"` | `IC-TDF-ID-00054`, Warning |
