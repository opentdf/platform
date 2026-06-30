# BaseTDF KAO Conformance Test Vectors

Machine-readable conformance vectors for the BaseTDF Key Access Object.

## Layout

```
testvectors/kao/
├── README.md          this file
├── PROVENANCE.md      key generation, security note, regeneration procedure
├── vector.schema.json JSON Schema for a single vector
├── index.json         enumerates every vector with summary metadata
├── keys/              test keys (PEM and JSON) with companion .meta.json
└── vectors/           one file per vector (e.g. pos-rsa-oaep-256-001.json)
```

## How to use

Any language implementation can act as a conformance harness:

1. Parse `index.json` to get the list of vectors.
2. For each entry, load the vector file from `vectors/<id>.json`.
3. Run the inputs through the implementation under test.
4. Assert the result matches `expected.outcome`, `expected.errorCode` (when
   `reject`), and `expected.recoveredDek` (when `accept`).
5. Report pass/fail per vector; cite the `conformance` IDs in the vector to
   indicate which assertions in
   [`../../basetdf/basetdf-kao-conformance.md`](../../basetdf/basetdf-kao-conformance.md)
   the implementation has exercised.

The reference Python harness at [`../../tools/python/`](../../tools/python/)
runs every vector via pytest. The browser-side harness at
[`../../tools/explorer/`](../../tools/explorer/) runs the same vectors
client-side and is parity-tested against the Python implementation.

## Adding a new vector

1. Allocate a new ID following the pattern `<category>-<descriptor>-NNN`
   (`pos-`, `neg-`, `legacy-`, or `kat-`).
2. Add an entry to `index.json` with the conformance assertions it exercises.
3. Author the vector file under `vectors/<id>.json`. It MUST validate against
   `vector.schema.json`.
4. If the vector requires a new test key, add it under `keys/` along with a
   `.meta.json` companion and update
   [`../../tools/python/scripts/gen_test_keys.py`](../../tools/python/scripts/gen_test_keys.py)
   so the CI `fixtures-fresh` job can regenerate it.
5. Run `pytest spec/tools/python -q` and the explorer's Vitest suite to
   confirm both reference implementations agree.

## Versioning

The vector schema is independently versioned via `index.json`'s `version`
field. Breaking schema changes bump the major version; the corresponding
spec version is in `specVersion`.
