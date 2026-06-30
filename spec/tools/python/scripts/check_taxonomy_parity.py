"""CI gate: error codes are identical across the markdown table, Python
StrEnum, and TypeScript const.

The single source of truth is the table in
``spec/basetdf/basetdf-kao-conformance.md`` §3. If any of the three drifts,
this script exits non-zero and prints the diff.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


CODE_PATTERN = re.compile(r"`(kao\.[a-z_]+)`")


def _spec_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "schema" / "BaseTDF" / "kao.schema.json").is_file():
            return parent
    raise SystemExit("could not locate spec/ root")


def _from_markdown() -> set[str]:
    text = (_spec_root() / "basetdf" / "basetdf-kao-conformance.md").read_text()
    section_start = text.find("## 3. Error Taxonomy")
    section_end = text.find("\n## ", section_start + 1)
    if section_start < 0 or section_end < 0:
        raise SystemExit("could not locate §3. Error Taxonomy in the conformance doc")
    return set(CODE_PATTERN.findall(text[section_start:section_end]))


def _from_python() -> set[str]:
    src = (
        _spec_root() / "tools" / "python" / "src" / "basetdf_kao" / "errors.py"
    ).read_text()
    return set(re.findall(r'"(kao\.[a-z_]+)"', src))


def _from_typescript() -> set[str]:
    src = (
        _spec_root() / "tools" / "explorer" / "src" / "data" / "errors.ts"
    ).read_text()
    return set(re.findall(r'"(kao\.[a-z_]+)"', src))


def main() -> int:
    md = _from_markdown()
    py = _from_python()
    ts = _from_typescript()

    ok = True
    for label, names in [("markdown", md), ("python", py), ("typescript", ts)]:
        if not names:
            print(f"FAIL: {label} produced an empty error-code set", file=sys.stderr)
            ok = False

    pairs = [
        ("markdown vs python", md, py),
        ("markdown vs typescript", md, ts),
        ("python vs typescript", py, ts),
    ]
    for label, a, b in pairs:
        if a != b:
            missing_in_b = sorted(a - b)
            missing_in_a = sorted(b - a)
            print(f"FAIL: {label} differ", file=sys.stderr)
            if missing_in_b:
                print(f"  missing on the right: {missing_in_b}", file=sys.stderr)
            if missing_in_a:
                print(f"  missing on the left:  {missing_in_a}", file=sys.stderr)
            ok = False

    if ok:
        print(f"OK: {len(md)} error codes consistent across md, Python, TypeScript")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
