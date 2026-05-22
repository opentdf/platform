# Dora improvement plan for Go workspaces

## Recommendation

The change Dora should surface is **first-class Go workspace awareness**, not just a cookbook workaround.

In practice, that means Dora should understand that a repository can be:

1. a **single Go module**,
2. a **Go workspace (`go.work`) with multiple modules**, or
3. a **generic multi-index repo** built from multiple SCIP fragments.

The best product shape is:

- a **workspace-aware indexer mode** for Go,
- **native support for multiple SCIP inputs/fragments**, and
- **module-aware status/query surfaces** so users can see and filter by workspace module.

---

## Why this matters

This repo is a good example of the current gap:

- it has a `go.work` at the repo root,
- it does **not** have a root `go.mod`,
- and it contains many separate Go modules.

Today, Dora effectively assumes a single-module flow:

- `dora init` writes a single `commands.index` shell command,
- `dora index` expects one repo-level indexing invocation to produce one usable `.scip`,
- and the import path / project root assumptions line up best with a single `go.mod` root.

That falls down in a Go workspace repo because:

1. `scip-go` cannot be reliably run from the workspace root when there is no root `go.mod`.
2. Each module needs its own module root and usually its own indexing pass.
3. Each resulting SCIP file is rooted at the module directory, so document paths must be normalized back to **repo-relative** paths before Dora ingests them.
4. A simple shell workaround is possible, but it is too much hidden complexity for what should be a first-class repo shape.

In this repo, making Dora work required a local-only workaround that:

- discovered modules from `go.work`,
- indexed each module separately,
- rewrote module-relative document paths to repo-relative paths,
- merged multiple SCIP payloads into one valid index,
- and then fed that merged index back into Dora.

That is exactly the kind of logic Dora should own.

---

## The change to surface in Dora

### 1. First-class workspace/indexer mode

Add a structured config mode instead of requiring all indexing behavior to live in one opaque shell string.

Suggested shape:

```json
{
  "root": "/path/to/repo",
  "db": ".dora/dora.db",
  "language": "go",
  "indexer": {
    "type": "go-workspace",
    "workspaceFile": "go.work",
    "fragmentsDir": ".dora/scip",
    "moduleDiscovery": "auto",
    "includeTests": false
  }
}
```

Backwards compatibility:

- keep `commands.index` for existing repos,
- add `indexer` as the preferred structured mode when Dora can provide first-class support.

Why this matters:

- Dora can now reason about module boundaries,
- `dora status` can report module-level progress and health,
- and users no longer need to maintain custom scripts just to index a standard Go workspace.

---

### 2. Native support for multiple SCIP fragments

Dora should support ingesting **multiple module-scoped SCIP indexes** and merging them internally.

That support should be generic enough to help with other multi-index repo shapes later, but Go workspaces should be the first concrete consumer.

Suggested config surface:

```json
{
  "indexer": {
    "type": "go-workspace",
    "fragmentsDir": ".dora/scip"
  },
  "scip": {
    "merged": ".dora/index.scip"
  }
}
```

Behavior:

- Dora writes one fragment per module into `.dora/scip/`.
- Dora merges those fragments before conversion to SQLite.
- Dora rewrites each document path from **module-relative** to **repo-relative**.
- Dora normalizes metadata so the final index is rooted at the repo root.

This is the missing primitive that makes Go workspace support feel native instead of bolted on.

---

### 3. Module-aware user surface

If Dora understands workspaces internally, it should expose that to the user.

#### `dora status`

Show workspace information explicitly, for example:

```text
initialized: true
indexed: true
workspace: go.work
modules: 10
files: 479
symbols: 44496

module breakdown:
- service      files 182  symbols 19874
- sdk          files 11   symbols 3240
- protocol/go  files 37   symbols 11290
...
```

#### `dora map`

Group by module before package/type summaries.

#### New `dora modules` command

Add a new command to list detected modules with:

- module directory
- Go module path
- files/symbols
- last indexed time
- whether the fragment is stale

Example:

```text
dora modules

service         github.com/opentdf/platform/service
sdk             github.com/opentdf/platform/sdk
protocol/go     github.com/opentdf/platform/protocol/go
...
```

#### Module filtering across existing commands

Add `--module <name-or-path>` where it makes sense:

- `dora ls --module service`
- `dora symbol Client --module sdk`
- `dora changes main --module service`

This is not required for day-one support, but it is the most useful thing to surface once Dora becomes workspace-aware.

---

## Proposed indexing behavior

For a Go workspace repo, `dora index` should do roughly this:

### Step 1: detect workspace mode

If:

- `go.work` exists at repo root, and/or
- no root `go.mod` exists,

then Dora should switch to Go workspace indexing automatically.

### Step 2: discover module directories

Parse `go.work` and capture all `use (...)` entries.

### Step 3: discover indexable packages per module

For each module directory, use Go tooling to identify real packages that should be indexed.

A good default is something equivalent to:

```bash
go list -e -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' ./...
```

Why this matters:

- it avoids indexing empty/test-only package directories as primary packages,
- it gives Dora stable import paths to pass to `scip-go`,
- and it avoids some of the edge cases we saw when treating `./...` as a monolithic pattern from the wrong root.

### Step 4: run `scip-go` per module

For each discovered module:

```bash
scip-go index <import-paths...> --module-root <module-dir> --output <fragment>
```

Optional policy:

- make test inclusion configurable (`includeTests: true|false`),
- default to whatever Dora decides is most useful for navigation, but make it explicit.

### Step 5: normalize and merge

Before Dora converts SCIP to SQLite, it should:

- rewrite `metadata.project_root` to the repo root,
- rewrite each `document.relative_path` from module-relative to repo-relative,
- reject or warn on any document paths that fall outside the module root,
- dedupe duplicate documents/symbol metadata where needed,
- and then convert the merged logical index as one repo.

### Step 6: store module metadata for status/filtering

Track enough module metadata to power `status`, `modules`, and future incremental behavior.

---

## Proposed schema / metadata additions

Dora can likely keep most of its current query model, but Go workspace support would benefit from explicit module metadata.

Suggested additions:

### Config

- `indexer.type = go-workspace`
- `indexer.workspaceFile`
- `indexer.fragmentsDir`
- `indexer.moduleDiscovery = auto | explicit`
- `indexer.modules = [...]` (optional override)
- `indexer.includeTests = true | false`

### Database / cached metadata

A lightweight `modules` table or metadata file with:

- `module_dir`
- `module_path`
- `fragment_path`
- `last_indexed`
- `file_count`
- `symbol_count`
- `stale` / `hash`

Optional but useful:

- `files.module_dir` or `files.module_id`

That would make module-scoped filters easy and avoid recomputing the same workspace information on every command.

---

## Suggested UX changes in `dora init`

`dora init` should detect Go workspace repos and say so explicitly.

Example:

```text
Detected Go workspace (go.work)
Detected 10 modules
Configured workspace-aware Go indexer
```

Instead of writing:

```json
"commands": {
  "index": "scip-go --output .dora/index.scip"
}
```

it should write a workspace-aware structured config.

This alone would eliminate most of the current confusion.

---

## Incremental indexing opportunity

Once Dora has module awareness, it can do better than reindexing the entire workspace every time.

Natural next step:

- only reindex modules whose files changed,
- or whose `go.mod`, `go.sum`, or `go.work` inputs changed,
- then re-merge fragments into the final logical index.

That would be a major quality-of-life win in large Go monorepos.

---

## Acceptance criteria

A good first version should satisfy all of the following:

1. `dora init` detects `go.work` and configures workspace mode automatically.
2. `dora index` succeeds in a repo with **no root `go.mod`**.
3. Dora returns **repo-relative file paths**, e.g. `service/authorization/authorization.go`, not `authorization.go`, `main.go`, or Go build cache paths.
4. Dora builds one SQLite view of the whole repo, not disconnected module-level islands.
5. `dora status` surfaces workspace/module information.
6. Users do **not** need a custom script or helper binary in `.dora/`.
7. Docs include a first-class Go workspace recipe and troubleshooting guidance.

---

## Recommended implementation order

### Phase 1 — productize the minimum viable path

- Add `go.work` detection to `dora init`
- Add structured `indexer.type = go-workspace`
- Implement per-module indexing + repo-relative path normalization
- Merge multiple SCIP fragments internally
- Surface workspace info in `dora status`

### Phase 2 — improve observability and ergonomics

- Add `dora modules`
- Add `--module` filtering where useful
- Show per-module counts in `status` / `map`
- Add troubleshooting messages for bad module roots or unsupported layouts

### Phase 3 — incremental performance

- Cache fragment-level state
- Reindex only changed modules
- Preserve merged repo view

---

## Bottom line

The most important change to surface in Dora is:

> **Treat `go.work` repositories as a first-class indexing mode, not as a custom shell-script edge case.**

Concretely, that means:

- native Go workspace detection,
- native multi-fragment SCIP ingest/merge,
- repo-relative path normalization,
- and module-aware status/query surfaces.

That would remove the need for the local workaround we had to build here, and it would make Dora feel correct out of the box on modern Go monorepos.
