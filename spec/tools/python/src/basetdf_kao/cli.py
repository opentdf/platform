"""``basetdf-kao`` CLI.

Subcommands:

  - ``validate <file>`` — run the validator on a KAO JSON file.
  - ``run-vectors [--filter ...]`` — exercise every test vector.
  - ``explain <file>`` — pretty-print a KAO with field-by-field annotations.
  - ``gen-keys [--out ...]`` — regenerate test-key fixtures.
  - ``gen-vectors [--out ...]`` — regenerate test vectors.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from basetdf_kao.testvectors import load_vectors, run_vector
from basetdf_kao.validate import validate_kao

console = Console()


@click.group(help="Reference validator for the BaseTDF v4.4 Key Access Object.")
def main() -> None: ...


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def validate(path: Path) -> None:
    """Validate a single KAO JSON file (or a vector file, in which case we
    validate its `inputs.kao`)."""
    obj = json.loads(path.read_text())
    if isinstance(obj, dict) and "inputs" in obj and isinstance(obj["inputs"], dict):
        obj = obj["inputs"].get("kao", obj)
    report = validate_kao(obj)
    if report.ok:
        console.print(f"[green]✓[/] {path}: structurally valid")
        console.print_json(data=report.normalized)
        return
    table = Table(title=f"Validation failed: {path}")
    table.add_column("Conformance")
    table.add_column("Code")
    table.add_column("Path")
    table.add_column("Message")
    for f in report.errors:
        table.add_row(f.conformance_id, f.code.value, f.path, f.message)
    console.print(table)
    if report.warnings:
        wtable = Table(title="Warnings")
        wtable.add_column("Conformance")
        wtable.add_column("Code")
        wtable.add_column("Message")
        for f in report.warnings:
            wtable.add_row(f.conformance_id, f.code.value, f.message)
        console.print(wtable)
    sys.exit(1)


@main.command(name="run-vectors")
@click.option("--filter", "filter_", default="", help="Substring filter on vector id.")
def run_vectors(filter_: str) -> None:
    """Run every conformance test vector."""
    vectors = [v for v in load_vectors() if filter_ in v.id]
    if not vectors:
        console.print("[yellow]no vectors matched[/]")
        sys.exit(0)
    table = Table(title=f"Conformance vectors ({len(vectors)})")
    table.add_column("Vector")
    table.add_column("Cat")
    table.add_column("Alg")
    table.add_column("Result")
    table.add_column("Detail")
    fail = 0
    for v in vectors:
        r = run_vector(v)
        if r.passed:
            verdict = "[green]✓[/]"
        else:
            verdict = "[red]✗[/]"
            fail += 1
        table.add_row(v.id, v.category, v.algorithm, verdict, r.detail or "")
    console.print(table)
    if fail:
        console.print(f"[red]{fail} vector(s) failed[/]")
        sys.exit(1)
    console.print(f"[green]all {len(vectors)} vectors passed[/]")


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def explain(path: Path) -> None:
    """Pretty-print a KAO with field annotations."""
    from basetdf_kao.model import KAO, algorithm_category

    obj = json.loads(path.read_text())
    try:
        kao = KAO.from_obj(obj)
    except Exception as e:
        console.print(f"[red]parse failed:[/] {e}")
        sys.exit(1)

    alg = kao.resolved_algorithm()
    table = Table(title=f"KAO: {path.name}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_column("Note")
    table.add_row("alg (resolved)", str(alg), str(algorithm_category(alg)) if alg else "")
    table.add_row("kas (resolved)", str(kao.resolved_kas()), "")
    table.add_row("kid", str(kao.kid), "")
    table.add_row("sid", str(kao.sid), "")
    table.add_row(
        "protectedKey",
        f"{(kao.resolved_protected_key() or '')[:40]}…"
        if kao.resolved_protected_key()
        else "<absent>",
        "",
    )
    table.add_row(
        "ephemeralKey",
        f"{(kao.resolved_ephemeral_key() or '')[:40]}…"
        if kao.resolved_ephemeral_key()
        else "<absent>",
        "",
    )
    table.add_row("policyBinding", str(type(kao.policy_binding).__name__), "")
    table.add_row("encryptedMetadata", "present" if kao.encrypted_metadata else "absent", "")
    console.print(table)


def _run_script(script_name: str, out: str) -> None:
    """Execute one of the dev scripts in spec/tools/python/scripts/.

    Located via importlib.resources on the package's parent directory; works
    whether the package is installed editable or as a wheel.
    """
    import runpy

    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "scripts" / script_name
        if candidate.is_file():
            runpy.run_path(str(candidate), run_name="__main__", init_globals={"sys": sys})
            return
    raise click.ClickException(f"could not locate scripts/{script_name}")


@main.command(name="gen-keys")
@click.option("--out", default="spec/testvectors/kao/keys", help="Output directory.")
def gen_keys(out: str) -> None:
    """Regenerate test-key fixtures."""
    sys.argv = ["gen_test_keys.py", out]
    _run_script("gen_test_keys.py", out)


@main.command(name="gen-vectors")
@click.option("--out", default="spec/testvectors/kao", help="Output testvector directory.")
def gen_vectors(out: str) -> None:
    """Regenerate test vectors."""
    sys.argv = ["gen_test_vectors.py", out]
    _run_script("gen_test_vectors.py", out)
