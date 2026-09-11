# BaseTDF KAO Explorer

Static, client-side companion to the BaseTDF v4.4 KAO specification. Renders
the prose docs into a navigable interactive surface backed by a TypeScript
mirror of the Python reference validator.

## What's here

- **Inspector** — paste a KAO, see structural validation, alias resolution,
  and the v4.4 normalised form.
- **Algorithm walkthroughs** — encrypt/decrypt steps for each algorithm,
  with field shape and conformance pointers.
- **Vector runner** — loads `spec/testvectors/kao/index.json` and runs each
  vector through the browser-side validator.
- **Binding playground** — compute and verify HMAC-SHA256 policy bindings,
  including legacy hex-then-base64 detection.
- **Error code reference** — the canonical taxonomy from BaseTDF-KAO-CONF §3,
  TypeScript-mirrored from `spec/tools/python/src/basetdf_kao/errors.py`.

## Develop

```sh
pnpm install
pnpm dev
```

Open http://localhost:4321/ — Astro hot-reloads on file changes.

## Build (this PR ships build-only)

```sh
pnpm build
pnpm preview
```

The static output lands in `dist/`. Hosting (e.g. GitHub Pages) is intentionally
deferred to a follow-up PR.

## Test

```sh
pnpm test
```

The Vitest parity suite runs every vector under `spec/testvectors/kao/` against
the browser-side validator and asserts outcomes. CI fails on any drift between
this validator and the Python reference.

## Layout

```
src/
├── pages/
│   ├── index.astro
│   ├── inspector.astro
│   ├── algorithms/[algorithm].astro
│   ├── vectors.astro
│   ├── binding.astro
│   └── errors.astro
├── components/
│   ├── KAOInspector.tsx           Preact island
│   ├── VectorRunner.tsx           Preact island
│   └── BindingPlayground.tsx      Preact island
├── layouts/Layout.astro
├── lib/
│   └── kao-runtime.ts             Browser-side mirror of validate.py
├── data/
│   ├── errors.ts                  Lockstep with errors.py
│   └── vectors.ts                 Build-time import of vector index
└── styles/global.css
```

## Spec source-of-truth imports

The Astro `vite.alias` maps `@spec` → `spec/`. Pages and components import:

- `@spec/schema/BaseTDF/kao.schema.json`
- `@spec/testvectors/kao/index.json`

These imports are resolved at build time, so the rendered site freezes the
spec version it shipped against.
