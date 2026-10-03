"""Reference validator and conformance harness for the BaseTDF Key Access Object.

This package validates KAOs against the BaseTDF v4.4.0 specification and
exercises the conformance test vectors at spec/testvectors/kao/. It is NOT
production cryptographic code; use the production OpenTDF SDKs for real
workloads.
"""

from basetdf_kao.errors import ErrorCode
from basetdf_kao.model import KAO, AlgorithmCategory, PolicyBinding
from basetdf_kao.validate import ConformanceFinding, ValidationReport, validate_kao

__version__ = "4.4.0"

__all__ = [
    "KAO",
    "AlgorithmCategory",
    "ConformanceFinding",
    "ErrorCode",
    "PolicyBinding",
    "ValidationReport",
    "__version__",
    "validate_kao",
]
