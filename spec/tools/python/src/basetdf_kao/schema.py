"""JSON Schema loader for the KAO and the test-vector format.

Locates the spec directory by walking up from this file (the package lives at
spec/tools/python/, so the spec root is two parents up). The location can be
overridden by the BASETDF_SPEC_ROOT environment variable, which is useful when
the package is installed elsewhere or when a single test run targets multiple
spec versions.
"""

from __future__ import annotations

import json
import os
from functools import cache
from pathlib import Path
from typing import Any, cast

import jsonschema


@cache
def spec_root() -> Path:
    override = os.environ.get("BASETDF_SPEC_ROOT")
    if override:
        return Path(override).resolve()
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "schema" / "BaseTDF" / "kao.schema.json").is_file():
            return candidate
    raise FileNotFoundError(
        f"Could not locate BaseTDF spec root from {here}. "
        "Set BASETDF_SPEC_ROOT to the absolute path of the spec/ directory."
    )


@cache
def kao_schema() -> dict[str, Any]:
    return cast(
        "dict[str, Any]",
        json.loads((spec_root() / "schema" / "BaseTDF" / "kao.schema.json").read_text()),
    )


@cache
def vector_schema() -> dict[str, Any]:
    return cast(
        "dict[str, Any]",
        json.loads((spec_root() / "testvectors" / "kao" / "vector.schema.json").read_text()),
    )


@cache
def kao_validator() -> jsonschema.Draft7Validator:
    return jsonschema.Draft7Validator(kao_schema())


@cache
def vector_validator() -> jsonschema.Draft7Validator:
    return jsonschema.Draft7Validator(vector_schema())
