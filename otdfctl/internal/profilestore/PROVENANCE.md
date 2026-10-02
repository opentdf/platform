# In-tree profile store provenance

Copied mechanically from `github.com/jrschumacher/go-osprofiles` at commit
`3d077c5481e5a991d6bc473f0d0cab70fbdb5f89` (Go module
`v0.0.0-20251201220924-3d077c5481e5`,
`h1:NRqBTDlgz/9hwlLPQlkfoIOJE0leWwCO9PwMrSAiY34=`).
Original source: https://github.com/jrschumacher/go-osprofiles/tree/3d077c5481e5

The original MIT copyright and permission notice is reproduced in `LICENSE`.
The initial copy changed only Go package names, internal import paths, and
formatting. A follow-up lint pass renamed internal Go types, reordered two
methods, simplified one global-load conditional without changing its branches,
and removed one blank line. Persisted store paths, JSON, encryption-key
derivation, and keyring identities were not changed.
The encrypted filesystem fixture files in `testdata/original-files` were generated
by calling the pinned original module's `New("otdfctl_fixture",
WithFileStore(dir))` and `AddProfile` for synthetic `alpha` and `beta` profiles,
with `alpha` set as default. Before writing, `go-keyring.MockInit` was used to
install the public test key `0123456789abcdef0123456789abcdef` under service
`urn.goosprofiles.otdfctl_fixture.profile.v1` and keys `global`,
`profile-alpha`, `profile-beta`. The keyring fixture strings in
`compatibility_test.go` were captured from the same original module after
`New("otdfctl_keyring_fixture", WithKeyringStore())` and `AddProfile(alpha,
true)` using `keyring.Get(namespace, key)` on `global` and `profile-alpha`.
No OS keyring or user profile was accessed. Do not use this key or fixture data
for real profiles.

OpenTDF /otdfctl maintainers own this as an independent in-tree fork, including
future fixes and security updates; there is no ongoing upstream-sync obligation.
Review provenance and notice compliance before merging.
