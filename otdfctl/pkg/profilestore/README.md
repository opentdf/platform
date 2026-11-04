# Profile store for Go applications

`github.com/opentdf/platform/otdfctl/pkg/profilestore` stores named,
application-defined JSON profiles and a global profile index. Use it when your
application owns its profile schema. It is part of the `github.com/opentdf/platform/otdfctl`
Go module, not a separate module; select an `otdfctl` module version that includes
this package and satisfies its Go toolchain requirement.

For the CLI's OpenTDF connection/authentication schema, use
[`pkg/profiles`](../profiles) instead; its typed settings extensions are documented
in [`pkg/profiles/extensions`](../profiles/extensions/EXTENSIONS.md). Neither API
performs login, token refresh, or token revocation for your application.

## Integrate a custom profile

1. Define a JSON-serializable struct with a `GetName() string` method. Use exported
   fields and stable JSON tags; the application owns validation and schema evolution.
   Reserve the top-level `extensions` key for the store's namespaced payload envelope.
2. Choose a stable application namespace and an explicit writable directory.
   Namespaces accept ASCII letters, digits, underscores, and hyphens. Profile names
   accept only lowercase ASCII letters and digits, with optional single underscores
   or hyphens between alphanumeric characters (no leading, trailing, or adjacent
   separators). Filename-length limits also apply. Do not use the CLI's namespace
   for an unrelated application.
3. Open the profiler with `New(namespace, WithFileStore(directory))`. This initializes
   or loads its global record. `Open` defers global initialization/version writes;
   it does not make the returned profiler immutable or prevent driver setup.
4. Use `RegisterProfile` for create-only registration: it rejects existing indexed
   or orphaned records without selecting a default. Call `SetDefaultProfile`
   separately when desired. `AddProfile` selects the first profile as default even
   when `setDefault` is false, but can overwrite a record missing from the index.
5. Load using the same concrete pointer type, modify it, and call `Save`. Propagate
   read errors; an inaccessible keyring or corrupt record is not a missing profile.

The following standalone program corresponds to the compiled (not executed)
[`ExampleNew`](example_test.go). It uses the OS credential store; never substitute
a test keyring in production.

```go
package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"

    "github.com/opentdf/platform/otdfctl/pkg/profilestore"
)

type applicationProfile struct {
    Name         string `json:"profile"`
    RefreshToken string `json:"refreshToken"`
}

func (p *applicationProfile) GetName() string { return p.Name }

func main() {
    configDir, err := os.UserConfigDir()
    if err != nil {
        log.Fatal(err)
    }
    p, err := profilestore.New("example_app", profilestore.WithFileStore(filepath.Join(configDir, "example_app")))
    if err != nil {
        log.Fatal(err)
    }
    const name = "personal"
    if !profilestore.GetGlobalConfig(p).ProfileExists(name) {
        if _, err := profilestore.RegisterProfile(p, &applicationProfile{Name: name}); err != nil {
            log.Fatal(err)
        }
        if err := profilestore.SetDefaultProfile(p, name); err != nil {
            log.Fatal(err)
        }
    }
    stored, err := profilestore.GetProfile[*applicationProfile](p, name)
    if err != nil {
        log.Fatal(err)
    }
    profile, err := profilestore.GetStoredProfile[*applicationProfile](stored)
    if err != nil {
        log.Fatal(err)
    }
    profile.RefreshToken = "replace-with-token-from-your-authentication-flow"
    if err := stored.Save(); err != nil {
        log.Fatal(err)
    }
    fmt.Println("Profile saved")
}
```

`ListProfiles`, `UseProfile`, `UseDefaultProfile`, `UpdateCurrentProfile`,
`SetDefaultProfile`, and `DeleteProfile` provide the remaining lifecycle operations.
Deleting the current default is rejected; choose another default first.
`GetGlobalConfig(p)` exposes global index/default and extension methods; its
concrete type remains internal, so callers should not name or construct that type.

## Storage and security contract

- `WithFileStore(directory)` stores JSON encrypted with AES-256-GCM in `.enc`
  files. A random per-record key is held in the OS credential store via
  `github.com/zalando/go-keyring`: macOS Keychain, Linux Secret Service, or Windows
  Credential Manager. This is **not** a keyring-free/headless fallback. Linux needs
  an available, unlocked Secret Service in the current D-Bus session.
- Files are named `urn.goosprofiles.<namespace>.profile.v1.<key>.enc`, where
  `<key>` is `global` or `profile-<name>`. The keyring service is
  `urn.goosprofiles.<namespace>.profile.v1` and its account is `<key>`. Preserve
  namespace, directory, names, JSON tags, and keyring access when reusing existing
  records; ciphertext alone is not a portable backup.
- The companion `.nfo` metadata is **unencrypted**, including profile name,
  creation time, algorithm, and version. New directories request `0700` and files
  `0600`; existing directory permissions are not repaired. Do not put secrets in
  profile names, filenames, logs, or diagnostics.
- `WithKeyringStore()` stores the JSON directly in the keyring, not in encrypted
  files. Its service identity is the raw namespace; it is not interchangeable
  with the filesystem driver's encryption-key entries. `WithInMemoryStore()` is
  ephemeral and creates an isolated map per store instance; do not rely on it for
  persistent reloads by profile name.
- Filesystem directories and custom factories use package-level state, not
  independent per-profiler configuration. Even serially opening a second profiler
  with a different directory or factory can redirect later operations on the first
  profiler while its existing global record remains in the original store. Use one
  filesystem directory/custom factory per process; serial startup alone does not
  isolate instances. There is no transaction, compare-and-swap, concurrent-writer
  guarantee, or automatic migration. Serialize filesystem-store initialization
  across goroutines and processes sharing a directory, including initialization
  triggered by reads such as `GetProfile`: constructors create and remove the same
  `.tmp_profile_rw_test` file, so concurrent initialization can panic. Serializing
  writes alone is insufficient. Also serialize writes and design application-level
  recovery for partial multi-record operations.
- Directory setup can panic on executable-path or permission failures. `Get` may
  create an encryption-key entry if it is missing; a subsequent decryption failure
  is an error, not an instruction to overwrite existing data. Deleting filesystem
  records does not remove their keyring encryption-key entries.

## Extensions and lower-level storage

`ProfileStore.Extension`/`SetExtension` and the equivalent global methods store
opaque JSON under a namespace in `extensions`. A write replaces the complete
payload for that namespace, including dropping omitted fields. Other namespaces
survive core saves, but arbitrary unknown fields outside `extensions` do not.
Applications own payload validation and version evolution.

For a single JSON record without a profile index, import
`github.com/opentdf/platform/otdfctl/pkg/profilestore/pkg/store` and call
`store.NewFileStore(namespace, key, store.WithStoreDirectory(directory))`.
It returns `store.Interface` (`Exists`, `Get`, `Set`, `Delete`); `Set` JSON-encodes
its argument and `Get` returns decoded plaintext bytes for the caller to unmarshal.
`WithCustomStore` accepts a `store.NewStoreInterface` factory for application-owned
drivers. Do not implement encryption or filename derivation separately.

Run `cd otdfctl && go test ./pkg/profilestore/... ./pkg/profiles/...` for the
engine's compatibility fixtures, lifecycle and extension tests, CLI integration,
and public-import example compilation. Tests mock the keyring and use synthetic
credentials; they do not validate access to a real OS credential store. See
[PROVENANCE.md](PROVENANCE.md) and [LICENSE](LICENSE) for source and attribution.
