# Typed config extensions

A consumer registers its JSON shape independently for global and profile scopes on an existing profiler. Registrations are local to this `ExtensionConfig`, not persisted or registered globally. Extensions are not included in CLI output by default. **`WriteGlobalExtension` and `WriteProfileExtension` fully replace one namespace:** fields not present in the replacement value are not merged or retained. Namespace owners must deliberately supply all fields they intend to keep; typed writes are not a lossless opaque-data preservation API.

```go
// Shape and version rules belong to the namespace owner.
type GlobalSettings struct {
    Version int `json:"version"`
    Enabled bool `json:"enabled"`
}
type ProfileSettings struct { Label string `json:"label"` }

profiler, err := profiles.CreateProfiler(profiles.ProfileDriverFileSystem)
if err != nil { return err }
ext, err := profiles.NewExtensionConfig(profiler,
    profiles.WithGlobalExtension[GlobalSettings]("my-app"),
    profiles.WithProfileExtension[ProfileSettings]("my-app"),
)
if err != nil { return err } // invalid or duplicate registration
// Named profile reads/writes require an existing profile; create it first.
if err := profiler.AddProfile(&profiles.ProfileConfig{Name: "alice", Endpoint: "https://example.invalid"}, false); err != nil { return err }

settings, present, err := profiles.ReadGlobalExtension[GlobalSettings](ext, "my-app")
if err != nil { return err } // malformed stored JSON or incompatible shape
if !present { settings = GlobalSettings{Version: 1, Enabled: true} } // absence != JSON null
if settings.Version != 1 { return fmt.Errorf("unsupported my-app config version: %d", settings.Version) }
settings.Enabled = true
// Full replacement of my-app's global namespace, not a merge.
if err := profiles.WriteGlobalExtension(ext, "my-app", settings); err != nil { return err }

profile, present, err := profiles.ReadProfileExtension[ProfileSettings](ext, "alice", "my-app")
if err != nil { return err }
if !present { profile = ProfileSettings{} }
profile.Label = "work"
// Full replacement of my-app's namespace in alice's profile.
return profiles.WriteProfileExtension(ext, "alice", "my-app", profile)
```

`Read*` returns `(zero, false, nil)` for an absent namespace, and `(zero, true, ErrExtensionDecode)` for invalid typed data. The example requires `fmt` and an import of `github.com/opentdf/platform/otdfctl/pkg/profiles`; its version check is consumer-owned, not a platform-wide version policy. JSON null is present and can be explicitly replaced with a typed value. Registration conflicts and invalid namespace names fail at construction; unregistered scope or wrong type fails before storage access. Before a typed write replaces an existing non-null payload, a conservative guard decodes and re-encodes the declared shape: if compact JSON changes (including field order, duplicate keys, or number spelling), it returns `ErrExtensionUnsafeUpdate` without mutating storage. This can reject harmless edits, and passing the guard does **not** guarantee lossless typed writes or merge absent fields from the replacement. Encoding failures return a sanitized `ErrExtensionEncode` without exposing custom marshaler errors. Namespace owners should handle validation and payload versions explicitly. Core operations and migration preserve opaque unknown data; explicit typed namespace replacements do not promise that preservation. A freshly created profiler reloads changes from other filesystem/keyring invocations. The existing in-memory driver creates a separate store for each profile load, so this named-profile API requires filesystem or keyring; global-only memory use remains supported within one profiler invocation.
