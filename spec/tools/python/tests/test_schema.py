"""Smoke tests for the schema loader."""

from __future__ import annotations

import jsonschema

from basetdf_kao.schema import kao_schema, kao_validator, vector_schema, vector_validator


def test_kao_schema_is_valid_draft7() -> None:
    jsonschema.Draft7Validator.check_schema(kao_schema())


def test_vector_schema_is_valid_draft7() -> None:
    jsonschema.Draft7Validator.check_schema(vector_schema())


def test_kao_validator_loadable() -> None:
    assert isinstance(kao_validator(), jsonschema.Draft7Validator)


def test_vector_validator_loadable() -> None:
    assert isinstance(vector_validator(), jsonschema.Draft7Validator)
