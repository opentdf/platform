## Summary

We are planning to migrate the `otdfctl` CLI from this standalone repository into the [`opentdf/platform`](https://github.com/opentdf/platform) monorepo. After migration, this repository will be archived and marked read-only.

## Why

- otdfctl already depends heavily on platform (SDK, protocol, libs) and uses platform's reusable CI workflows
- Both repos run each other's e2e tests in CI — consolidating eliminates cross-repo coordination overhead
- The platform monorepo already supports per-component releases (service, sdk, libs), so otdfctl can maintain independent release cadence

## What changes for users

- **Go module path** will change from `github.com/opentdf/otdfctl` to `github.com/opentdf/platform/otdfctl`
- **Release tags** will change from `v0.X.Y` to `otdfctl/v0.X.Y`
- **This repository** will be archived (read-only) — all existing releases and tags will remain accessible
- A notice will be added to this README pointing to the new location

## What stays the same

- The `otdfctl` binary name and CLI interface
- Separate release cadence (not coupled to platform service releases)
- All existing CI tests continue to run

## Feedback

If you have concerns or questions about this migration, please comment on this issue.
