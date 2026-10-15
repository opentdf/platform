# Typed config extensions

A consumer registers its JSON shape independently for global and profile scopes on an existing profiler. Registrations are local to this `extensions.Config`, not persisted or registered globally. Extensions are not included in CLI output by default. **`extensions.WriteGlobal` and `extensions.WriteProfile` fully replace one namespace:** fields not present in the replacement value are not merged or retained. The extender owns payload compatibility, unknown-field retention, validation, and versioning, and must supply every field it intends to keep. Typed writes do not preserve existing payload fields.

```go
// Shape and version rules belong to the namespace owner.
type GlobalSettings struct {
    Version int `json:"version"`
    Enabled bool `json:"enabled"`
}
type ProfileSettings struct { Label string `json:"label"` }

profiler, err := profiles.CreateProfiler(profiles.ProfileDriverFileSystem)
if err != nil { return err }
ext, err := extensions.NewConfig(profiler,
    extensions.WithGlobal[GlobalSettings]("my-app"),
    extensions.WithProfile[ProfileSettings]("my-app"),
)
if err != nil { return err } // invalid or duplicate registration
// Named profile reads/writes require an existing profile; create it first.
if _, err := profiles.RegisterProfile(profiler, &profiles.ProfileConfig{Name: "alice", Endpoint: "https://example.invalid"}); err != nil { return err }

settings, present, err := extensions.ReadGlobal[GlobalSettings](ext, "my-app")
if err != nil { return err } // malformed stored JSON or incompatible shape
if !present { settings = GlobalSettings{Version: 1, Enabled: true} } // absence != JSON null
if settings.Version != 1 { return fmt.Errorf("unsupported my-app config version: %d", settings.Version) }
settings.Enabled = true
// Full replacement of my-app's global namespace, not a merge.
if err := extensions.WriteGlobal(ext, "my-app", settings); err != nil { return err }

profile, present, err := extensions.ReadProfile[ProfileSettings](ext, "alice", "my-app")
if err != nil { return err }
if !present { profile = ProfileSettings{} }
profile.Label = "work"
// Full replacement of my-app's namespace in alice's profile.
return extensions.WriteProfile(ext, "alice", "my-app", profile)
```

## Public profile lifecycle

External consumers can retain `*profiles.Profiler` in their own fields and interfaces;
no internal engine imports are required. `profiles.ListProfiles(profiler)` returns a
detached inventory, and `profiles.GetDefault(profiler)` returns the current name,
including an intentionally empty default. Both read cached global configuration
without writing or selecting a profile. `profiles.LoadProfile(profiler, name)`
loads a public profile store for existing credential/endpoint setters.

`profiles.RegisterProfile` normalizes a new configuration and registers it without
choosing a default, including when it is the first profile. It rejects invalid
names, registered duplicates and unregistered stored-record collisions. Supplied
authentication is retained. Call `profiles.SetDefault(profiler, name)` only when
explicit default selection is intended; the name must already be registered.
Missing names and failed writes leave the cached default unchanged. These APIs
use the existing engine's opaque-field and extension-preserving persistence.
Legacy `profiler.AddProfile` and `profiles.NewOtdfctlProfileStore` still implicitly
choose the first default when it is empty.

These are not transactions across global/profile records or processes. Failed
registration may leave an unregistered record, which a retry rejects rather than
overwriting. Create-only checks propagate lookup errors instead of relying on the
legacy boolean existence check; an observed record is never merged as an update.
These checks are not atomic against concurrent writers. Custom drivers without an
error-aware presence method must return `nil, nil` or `fs.ErrNotExist` from `Get`
for genuine absence; any successful non-nil payload is considered present.
Registration endpoint-validation failures return `profiles.ErrProfileEndpointInvalid`
without exposing URL-bearing parse errors through text or error chains.
Inventory is cached, not a live cross-process snapshot. Constructors
`CreateProfiler`/`NewProfiler` initialize missing global records and can upgrade
the stored version; they are **not read-only inspection**. The facade does not
invoke driver migration. Nil, zero-value or cleaned-up profilers return
`profiles.ErrInvalidProfiler`. Named-profile round trips retain the existing
filesystem/keyring requirement; the memory driver limitation is unchanged.

`extensions.Read*` returns `(zero, false, nil)` for an absent namespace, and `(zero, true, extensions.ErrExtensionDecode)` for invalid typed data. The example requires `fmt` and imports of `github.com/opentdf/platform/otdfctl/pkg/profiles` and `github.com/opentdf/platform/otdfctl/pkg/profiles/extensions`; its version check is consumer-owned, not a platform-wide version policy. JSON null is present and can be explicitly replaced with a typed value. Registration conflicts and invalid namespace names fail at construction; unregistered scope or wrong type fails before storage access. Typed writes replace stored payloads as supplied, even when the previous payload contains unknown fields or cannot be decoded into the registered shape. Encoding failures return a sanitized `extensions.ErrExtensionEncode` without exposing custom marshaler errors. The extender must handle payload compatibility, unknown-field retention, validation, and versioning explicitly. Core operations and migration preserve opaque unknown data; explicit typed namespace replacements do not promise that preservation. A freshly created profiler reloads changes from other filesystem/keyring invocations. The existing in-memory driver creates a separate store for each profile load, so this named-profile API requires filesystem or keyring; global-only memory use remains supported within one profiler invocation.
