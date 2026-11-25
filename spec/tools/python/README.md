# basetdf-kao

Reference validator and conformance test harness for the BaseTDF v4.4 Key
Access Object.

> **Non-production warning.** This package validates the spec and exercises
> conformance vectors. Its cryptographic operations are NOT hardened for
> production use (no constant-time guarantees beyond `hmac.compare_digest`,
> no key zeroization, no FIPS validation, no side-channel review). Use the
> production OpenTDF SDKs in [`../../../sdk/`](../../../sdk/) for real workloads.

## Install

From a checkout of the platform repo:

```sh
pip install -e 'spec/tools/python[dev]'
```

The `pqc` extra pulls [`kyber-py`](https://pypi.org/project/kyber-py/) for
ML-KEM. If you don't install it, structural validation and the RSA / ECDH
algorithms still work; ML-KEM-related test vectors are skipped with a
`pending` marker.

```sh
# minimum (validation only, no PQC)
pip install -e spec/tools/python

# with PQC
pip install -e 'spec/tools/python[pqc]'

# full dev environment (PQC + lint + type-check + tests)
pip install -e 'spec/tools/python[dev]'
```

Python 3.11 or 3.12 is required.

## Usage

### As a library

```python
from basetdf_kao import validate_kao

report = validate_kao(my_kao_dict)
if report.ok:
    print(report.normalized)  # v4.4 canonical form, aliases resolved
else:
    for finding in report.errors:
        print(finding.conformance_id, finding.code, finding.message)
```

### As a CLI

```sh
basetdf-kao validate path/to/kao.json
basetdf-kao run-vectors                 # the conformance gate
basetdf-kao run-vectors --filter pos-mlkem
basetdf-kao explain path/to/kao.json
basetdf-kao gen-keys --out /tmp/keys    # regenerate test fixtures
```

## Layout

```
src/basetdf_kao/
├── __init__.py        public API surface
├── errors.py          ErrorCode StrEnum (lockstep with conformance doc)
├── schema.py          loads spec/schema/BaseTDF/kao.schema.json
├── model.py           pydantic KAO model with v4.3/v4.4 alias resolution
├── validate.py        structural validation tagged with KAO-C-NNN ids
├── binding.py         policy-binding compute and verify
├── _crypto/           per-algorithm protect/unprotect (lazy ML-KEM import)
├── testvectors.py     loads and runs spec/testvectors/kao/ vectors
└── cli.py             click-based CLI

scripts/
└── gen_test_keys.py   reproducible test key generator (CI fixtures-fresh gate)

tests/
├── test_schema.py
├── test_validation_unit.py
├── test_binding_unit.py
├── test_vectors.py    parametrized over every entry in index.json
└── test_cli.py
```

## Development

```sh
ruff check src
ruff format --check src
mypy src
pytest -q
```

The `pytest` run loads every test vector under
`../../testvectors/kao/index.json` and asserts each one. Failure is the
authoritative signal that the implementation under test has a conformance
gap.
