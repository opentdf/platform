# Configuration Annotation and Helm Values Generation Specification

Status: proposed
Version: `v1alpha1`
Decision record: [ADR-0001](../../adr/0001-configuration-annotations-for-generated-helm-values.md)

## Purpose

This specification defines how OpenTDF configuration metadata is collected from Go configuration structs and used to generate deployment artifacts such as Helm chart values, Helm JSON schema, Kubernetes Secret/ConfigMap mappings, and configuration documentation.

The design is intentionally portable. Another Cobra/Viper Go service should be able to apply the same behavior by supplying its own root config structs, environment variable prefix, and optional service registry.

## Goals

* Generate chart-facing configuration artifacts from the same source of truth used by the OpenTDF binary.
* Preserve existing Viper config paths, environment variable behavior, defaults, and validation semantics.
* Make secret handling explicit and reviewable.
* Make Kubernetes projection behavior explicit where config-file/env-var generation is not enough.
* Produce deterministic artifacts that can be checked into this repository or consumed by an external Helm chart repository.
* Support incremental adoption without requiring every field to be annotated on day one.

## Non-goals

* Replacing Viper, Cobra, or existing config loading behavior.
* Rendering a complete Helm chart from the application binary at runtime.
* Encoding long-form human documentation inside Go struct tags.
* Inferring production-safe values for secrets or external dependencies.
* Making Helm the only supported deployment target.

## Source model

The generator MUST read configuration metadata from registered Go config roots. For OpenTDF, the initial root is expected to be `service/pkg/config.Config`.

Existing tags remain authoritative where they already define runtime behavior:

| Tag | Purpose |
| --- | --- |
| `mapstructure` | Canonical Viper config path segment. |
| `json` | Serialization name and fallback field name when needed. |
| `default` | Runtime default consumed by the existing default settings loader. |
| `validate` | Validation constraints compatible with `go-playground/validator`. |

New metadata tags provide behavior that cannot be inferred safely:

| Tag | Purpose |
| --- | --- |
| `config` | Cross-platform config metadata such as sensitivity, deprecation, aliases, enum values, and explicit ignore. |
| `helm` | Helm/Kubernetes projection metadata such as Secret vs ConfigMap, values path, render mode, mounts, and external dependency hints. |

## Annotation grammar

The `config` and `helm` tags use comma-separated tokens:

```go
Field string `mapstructure:"field" config:"sensitive,format=uri" helm:"source=secret,render=env"`
```

Rules:

* A token without `=` is a boolean flag with value `true`.
* A token with `=` is a key/value pair.
* Tokens are trimmed of surrounding whitespace.
* Empty tokens are ignored.
* Duplicate keys are invalid unless a key explicitly allows repeated values.
* Values SHOULD avoid commas. If comma-containing values are needed, move that metadata to a sidecar registry rather than overloading struct tags.
* Tags are for machine behavior. Long descriptions SHOULD come from Go doc comments or a sidecar documentation registry.

## `config` tag keys

| Key | Value | Meaning |
| --- | --- | --- |
| `ignore` | boolean | Exclude the field from generated schema and artifacts. Requires an explanatory comment or sidecar reason. |
| `sensitive` | boolean | Field contains a secret or credential and MUST NOT be emitted as a literal non-secret Helm value. |
| `internal` | boolean | Runtime/internal field that is not operator-facing. Implies exclusion from Helm values unless overridden. |
| `deprecated` | string | Marks the field deprecated. The value SHOULD identify a version, replacement path, or reason. |
| `alias` | config path | Legacy config path accepted for compatibility. May be repeated if the parser supports repeated keys. |
| `enum` | pipe-separated list | Allowed scalar values, for example `enum=all|core|kas`. |
| `format` | string | Semantic type hint such as `duration`, `size`, `uri`, `hostname`, `port`, `pem`, or `json`. |
| `example` | scalar | Example value for docs and generated samples. MUST NOT be used for sensitive values. |

## `helm` tag keys

| Key | Value | Meaning |
| --- | --- | --- |
| `source` | `configmap`, `secret`, `values`, or `none` | Kubernetes source used by generated chart artifacts. |
| `render` | `env`, `file`, `yaml`, or `json` | How the chart should project the value into the workload. |
| `path` | Helm values path | Overrides the generated values path. |
| `env` | environment variable name | Overrides the generated Viper environment variable name. |
| `modes` | pipe-separated list | Deployment modes where the value is relevant. |
| `dependency` | string | External dependency hint such as `postgresql`, `oidc`, `redis`, `otel`, or `tls`. |
| `existingSecret` | Helm values path | Values path that can reference an externally managed Kubernetes Secret. |
| `existingSecretKey` | string | Default key name for externally managed Secret data. |
| `mountPath` | path | Container mount path when `render=file`. |
| `fileName` | string | File name when a value is rendered as a mounted file. |
| `omitEmpty` | boolean | Omit the value from generated manifests when unset. |
| `as` | `string`, `json`, `yaml`, or `literal` | Serialization override for env/file rendering. |

## Field discovery

The generator MUST walk registered exported struct fields recursively.

A field MUST be skipped when any of the following are true:

* the field is unexported;
* `mapstructure:"-"` or `json:"-"` is present;
* `config:"ignore"` is present;
* the field type is known to be runtime-only, such as `sync.Mutex`, `context.Context`, function types, channels, or embedded filesystem handles.

A field path is resolved as follows:

1. Use the `mapstructure` tag name when present.
2. Otherwise use the `json` tag name when present.
3. Otherwise derive a lower snake-case name from the Go field name.
4. Concatenate nested path segments with `.`.
5. Honor `mapstructure` squash/inline behavior if present.

For dynamic maps such as `services`, reflection alone is insufficient. The generator MUST support an explicit registry of schema providers. A provider registers a logical path prefix and a concrete Go type or field list, for example:

```go
configschema.RegisterService("kas", kas.Config{})
configschema.RegisterService("authorization", authorization.Config{})
configschema.RegisterService("entityresolution", entityresolution.Config{})
configschema.RegisterService("policy", policy.Config{})
```

Registered service fields are emitted under `services.<service-name>.*` unless the provider specifies another path.

## Defaults

Defaults SHOULD be derived using the same semantics as runtime config loading. For OpenTDF this means using the existing default tag behavior used by `DefaultSettingsLoader`.

Rules:

* Defaults MUST be serialized in their typed form in the intermediate schema.
* A missing default is different from a zero-value default.
* Sensitive defaults MUST NOT be emitted into non-secret Helm values. If a sensitive field has a development default, generated chart samples MUST replace it with an empty value or explicit placeholder.
* Invalid default literals MUST fail generation.

## Environment variable names

The default environment variable name is derived from the canonical config path:

1. Start with the configured prefix, `OPENTDF` for this repository.
2. Replace `.`, `-`, and other non-alphanumeric path separators with `_`.
3. Uppercase the result.
4. Join prefix and path with `_`.

Example:

| Config path | Environment variable |
| --- | --- |
| `db.host` | `OPENTDF_DB_HOST` |
| `server.port` | `OPENTDF_SERVER_PORT` |
| `services.policy.list_request_limit_default` | `OPENTDF_SERVICES_POLICY_LIST_REQUEST_LIMIT_DEFAULT` |

Use `helm:"env=..."` only for backward-compatible exceptions.

## Intermediate schema

Generators MUST emit a normalized intermediate schema before producing Helm or documentation artifacts. Consumers SHOULD depend on this schema rather than parsing Go source.

The schema MUST be deterministic and sorted by `path`.

Example shape:

```json
{
  "apiVersion": "opentdf.io/config-schema/v1alpha1",
  "envPrefix": "OPENTDF",
  "fields": [
    {
      "path": "db.host",
      "env": "OPENTDF_DB_HOST",
      "type": "string",
      "default": "localhost",
      "required": false,
      "sensitive": false,
      "source": {
        "file": "service/pkg/db/db.go",
        "type": "Config",
        "field": "Host"
      },
      "helm": {
        "source": "configmap",
        "path": "config.db.host",
        "render": "env",
        "dependency": "postgresql"
      }
    }
  ]
}
```

Each field record SHOULD include:

| Property | Required | Description |
| --- | --- | --- |
| `path` | yes | Canonical Viper config path. |
| `env` | yes | Canonical environment variable name. |
| `type` | yes | JSON-compatible type or semantic type. |
| `default` | no | Typed default value when one exists. |
| `required` | yes | Derived from validation tags or explicit metadata. |
| `sensitive` | yes | Derived from `config:"sensitive"` or policy registry. |
| `deprecated` | no | Deprecation metadata. |
| `aliases` | no | Legacy config paths. |
| `description` | no | Human-facing description from comments or registry. |
| `source` | yes | Go source location for traceability. |
| `helm` | no | Helm projection metadata. |

## Type mapping

The generator MUST map Go types to JSON-schema-compatible types.

| Go type | Schema type |
| --- | --- |
| `string` | `string` |
| `bool` | `boolean` |
| signed/unsigned integers | `integer` |
| floats | `number` |
| slices/arrays | `array` |
| maps | `object` |
| structs | `object` |
| pointers | nullable form of the element type |
| duration-like strings | `string` with `format=duration` when annotated |
| byte slices containing PEM or key material | `string` with `format=pem` when annotated |

Unsupported types MUST be skipped only with explicit `config:"ignore"`; otherwise generation MUST fail.

## Helm values generation

The generator SHOULD produce the following chart-facing artifacts:

* `values.generated.yaml`: a deterministic values skeleton containing safe defaults and placeholders.
* `values.schema.generated.json`: Helm-compatible JSON Schema validation.
* `config-schema.generated.json`: the normalized intermediate schema.
* optional Markdown docs generated from the same schema.

Default Helm values paths:

| Field kind | Default values path |
| --- | --- |
| non-sensitive runtime config | `config.<field-path>` |
| sensitive runtime config | `secrets.<field-path>` |
| chart-only setting | explicit `helm:"source=values,path=..."` |
| excluded setting | no values path |

Sensitive values SHOULD use an object shape that supports both inline development values and externally managed Secrets:

```yaml
secrets:
  db:
    password:
      value: ""
      existingSecret: ""
      existingSecretKey: password
```

The chart MUST prefer `existingSecret` when provided. Inline `value` is intended for local development and tests, not production recommendations.

## Kubernetes projection rules

The `helm.source` and `helm.render` metadata decide how values are projected into workloads.

Recommended defaults:

| Condition | Source | Render |
| --- | --- | --- |
| scalar, non-sensitive | `configmap` | `env` |
| object/list, non-sensitive | `configmap` | `file` or `yaml` |
| sensitive scalar | `secret` | `env` |
| sensitive object/list | `secret` | `file` |
| TLS/key material | `secret` | `file` |

The generated chart MUST NOT put `config:"sensitive"` values into a ConfigMap. The generator MUST fail if annotations request an unsafe combination unless an explicit, reviewed override mechanism is added later.

## Examples

### Database host

```go
Host string `mapstructure:"host" json:"host" default:"localhost" helm:"dependency=postgresql"`
```

Derived metadata:

* config path: `db.host`
* env var: `OPENTDF_DB_HOST`
* Helm path: `config.db.host`
* Kubernetes source: `configmap`

### Database password

```go
Password string `mapstructure:"password" json:"password" default:"changeme" config:"sensitive" helm:"source=secret,dependency=postgresql,existingSecretKey=password"`
```

Derived metadata:

* config path: `db.password`
* env var: `OPENTDF_DB_PASSWORD`
* Helm path: `secrets.db.password`
* Kubernetes source: `secret`
* generated samples must not recommend the literal default for production

### TLS private key file

```go
Key string `mapstructure:"key" json:"key" config:"sensitive,format=pem" helm:"source=secret,render=file,mountPath=/etc/opentdf/tls,fileName=tls.key,dependency=tls"`
```

Derived behavior:

* store content in a Secret;
* mount it as a file;
* set the runtime config value to the mounted file path when rendering the config file or environment.

### Deployment mode

```go
Mode []string `mapstructure:"mode" json:"mode" default:"[\"all\"]" config:"enum=all|core|kas|ers" helm:"path=mode"`
```

Derived behavior:

* generated JSON Schema restricts known mode values;
* chart logic can use mode metadata to include or omit service-specific blocks.

## Cobra integration

Cobra flags MAY be inspected to enrich CLI documentation, but Cobra is not the source of truth for Helm generation. Many config fields are file/env-only and are not represented as flags.

If a config field is intentionally controlled by a Cobra flag, the generator MAY include optional metadata linking the field path to the command and flag name. That metadata MUST NOT override the canonical Viper path unless explicitly configured.

## Validation and lint rules

Generation MUST fail when:

* two fields resolve to the same canonical config path;
* two fields resolve to the same environment variable without an explicit compatibility alias;
* an exported field is unsupported and not explicitly ignored;
* a `helm.path` is invalid or collides with an incompatible field;
* `config:"sensitive"` is combined with `helm:"source=configmap"`;
* a field name matches common secret terms such as `password`, `secret`, `token`, `private`, or `credential` but lacks either `config:"sensitive"` or an explicit non-sensitive override;
* a required field has no chart input path;
* a default value cannot be parsed into the field type;
* a service config map lacks a registered schema provider for chart-facing fields.

Generation SHOULD warn when:

* a field has no description;
* a deprecated field has no replacement or removal version;
* a sensitive field has a non-empty development default;
* a Helm dependency hint is unknown to the chart generator.

## Regeneration workflow

A future implementation SHOULD provide commands or Make targets equivalent to:

```bash
opentdf config schema --output config-schema.generated.json
opentdf config helm-values --output values.generated.yaml
opentdf config helm-schema --output values.schema.generated.json
opentdf config docs --output docs/Configuring.generated.md
```

CI SHOULD run the generator and fail if checked-in generated files are stale.

External Helm chart repositories SHOULD consume generated artifacts from one of these sources:

* release assets;
* a versioned generated-artifacts directory in this repository;
* a published module/package containing the intermediate schema;
* a pinned Git reference.

External repositories SHOULD NOT parse OpenTDF Go source directly.

## Portability profile

To apply this specification to another Cobra/Viper service, provide:

1. root config struct registrations;
2. environment variable prefix;
3. optional dynamic map/service schema registry;
4. optional sidecar documentation registry;
5. generator configuration for Helm values path conventions;
6. CI drift check.

Projects MAY change the tag names if needed, but generated intermediate schemas SHOULD preserve equivalent semantics so downstream tooling can be reused.

## Migration plan

1. Implement schema collection for root config structs using existing `mapstructure`, `json`, `default`, and `validate` tags.
2. Add `config` and `helm` annotations to high-value fields: database, server TLS, auth/OIDC, KAS key material, cache, tracing, and service enablement.
3. Add a service config schema registry for `services.*` entries.
4. Generate the intermediate schema and add golden tests.
5. Generate Helm values and Helm JSON Schema artifacts.
6. Replace manually maintained config docs sections with generated documentation where practical.
7. Publish generated artifacts for the external chart workflow.
