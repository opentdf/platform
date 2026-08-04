# BaseTDF Specification Tooling

Reference implementations and developer tooling that consume the BaseTDF
specifications under `../basetdf/` and the conformance test vectors under
`../testvectors/`.

> **Non-production warning.** The cryptographic code in this directory exists
> to verify the spec, exercise conformance vectors, and provide an interactive
> teaching surface. It is NOT hardened for production use. Use the production
> SDKs in [`../../sdk/`](../../sdk/) and the platform service in
> [`../../service/`](../../service/) for real workloads.

## Subdirectories

| Path | What it is | Status |
|---|---|---|
| [`python/`](python/) | Reference Python validator and conformance test harness for the Key Access Object. The pytest suite is the canonical conformance gate. | Phase 2 |
| [`explorer/`](explorer/) | Astro static site for browsing the KAO format, walking through algorithms, and validating KAOs in the browser. | Phase 3 |

The `Phase 2`/`Phase 3` markers refer to the implementation phases described
in the parent PR; not all directories may be present yet.

## Versioning

The tooling here is versioned in lockstep with the spec under `../basetdf/`.
The Python package's `__version__` and the explorer's `package.json` version
both equal the spec version in [`../VERSION`](../VERSION).
