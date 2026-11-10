# Changelog

## [0.5.0](https://github.com/opentdf/platform/compare/lib/fixtures/v0.4.0...lib/fixtures/v0.5.0) (2026-01-28)


### Features

* **sdk:** add automatic token refresh for Keycloak operations ([#3019](https://github.com/opentdf/platform/issues/3019)) ([3b0834e](https://github.com/opentdf/platform/commit/3b0834e7e8f9b34666305b1b13b3d6df7d2c6bec))

## [0.4.0](https://github.com/opentdf/platform/compare/lib/fixtures/v0.3.0...lib/fixtures/v0.4.0) (2025-12-19)


### Features

* Update Go toolchain version to 1.24.11 across all modules ([#2943](https://github.com/opentdf/platform/issues/2943)) ([a960eca](https://github.com/opentdf/platform/commit/a960eca78ab8870599f0aa2a315dbada355adf20))


### Bug Fixes

* **deps:** bump toolchain to go1.24.9 for CVEs found by govulncheck ([#2849](https://github.com/opentdf/platform/issues/2849)) ([23f76c0](https://github.com/opentdf/platform/commit/23f76c034cfb4c325d868eb96c95ba616e362db4))

## [0.3.0](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.10...lib/fixtures/v0.3.0) (2025-05-20)


### ⚠ BREAKING CHANGES

* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979))

### Features

* bulk keycloak provisioning ([#2205](https://github.com/opentdf/platform/issues/2205)) ([59e4485](https://github.com/opentdf/platform/commit/59e4485bdd0ced85c69604130505553f447918d1))
* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979)) ([164c922](https://github.com/opentdf/platform/commit/164c922af74b1265fe487362c356abb7f1503ada))


### Bug Fixes

* **deps:** bump toolchain in /lib/fixtures and /examples to resolve CVE GO-2025-3563 ([#2061](https://github.com/opentdf/platform/issues/2061)) ([9c16843](https://github.com/opentdf/platform/commit/9c168437db3b138613fe629419dd6bd9f837e881))
* perfsprint lint issues ([#2209](https://github.com/opentdf/platform/issues/2209)) ([7cf8b53](https://github.com/opentdf/platform/commit/7cf8b5372a1f90f12a3b6e4038305bea9a877ee9))

## [0.2.10](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.9...lib/fixtures/v0.2.10) (2024-12-17)


### Features

* **kas:** collect metrics ([#1702](https://github.com/opentdf/platform/issues/1702)) ([def28d1](https://github.com/opentdf/platform/commit/def28d1984b0b111a07330a3eb59c1285206062d))

## [0.2.9](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.8...lib/fixtures/v0.2.9) (2024-11-14)


### Features

* **sdk:** add collections for nanotdf  ([#1695](https://github.com/opentdf/platform/issues/1695)) ([6497bf3](https://github.com/opentdf/platform/commit/6497bf3a7cee9b6900569bc6cc2c39b2f647fb52))

## [0.2.8](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.7...lib/fixtures/v0.2.8) (2024-11-13)


### Features

* **authz:** Remove org-admin role, move privileges to admin role ([#1740](https://github.com/opentdf/platform/issues/1740)) ([ae931d0](https://github.com/opentdf/platform/commit/ae931d02f347edea468d4c5d48ab3e07ce7d3abe))

## [0.2.7](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.6...lib/fixtures/v0.2.7) (2024-06-20)


### Bug Fixes

* **ci:** Ensure unmanaged attributes is enabled during kc provisioning ([#1002](https://github.com/opentdf/platform/issues/1002)) ([58393ef](https://github.com/opentdf/platform/commit/58393efce711dc9ee2df14c78ab65b02c23aaded))

## [0.2.6](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.5...lib/fixtures/v0.2.6) (2024-06-04)


### Bug Fixes

* **core:** bump golang.org/x/net from 0.17.0 to 0.23.0 in /lib/fixtures ([#626](https://github.com/opentdf/platform/issues/626)) ([1201145](https://github.com/opentdf/platform/commit/1201145aafaac89c8ebe49d2ee577e83048ddad7))

## [0.2.5](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.4...lib/fixtures/v0.2.5) (2024-06-03)


### Bug Fixes

* **core:** update default casbin auth policy ([#927](https://github.com/opentdf/platform/issues/927)) ([c354fdb](https://github.com/opentdf/platform/commit/c354fdb118af4e4a222f3c65fcbf5de581d08bee))

## [0.2.4](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.3...lib/fixtures/v0.2.4) (2024-05-24)


### Bug Fixes

* **ci:** Handle provisioning of keycloak clients without service accounts enabled ([#865](https://github.com/opentdf/platform/issues/865)) ([16af636](https://github.com/opentdf/platform/commit/16af63687e0be55cbbb59c13f96c5490b9c30c87))

## [0.2.3](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.2...lib/fixtures/v0.2.3) (2024-05-14)


### Bug Fixes

* **core:** Updates logs statements to log errors ([#796](https://github.com/opentdf/platform/issues/796)) ([7a3379b](https://github.com/opentdf/platform/commit/7a3379b6878562e4958e61516335e912716588b7))

## [0.2.2](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.1...lib/fixtures/v0.2.2) (2024-05-13)


### Bug Fixes

* **core:** Bump libs patch version ([#779](https://github.com/opentdf/platform/issues/779)) ([3b68dea](https://github.com/opentdf/platform/commit/3b68dea867609071047554a6a7697becaaee2805))

## [0.2.1](https://github.com/opentdf/platform/compare/lib/fixtures/v0.2.0...lib/fixtures/v0.2.1) (2024-05-07)


### Features

* **ers:** Create entity resolution service, replace idp plugin ([#660](https://github.com/opentdf/platform/issues/660)) ([ff44112](https://github.com/opentdf/platform/commit/ff441128a4b2ef97c3f739ee3f6f42be273b31dc))
* **sdk:** Adds TLS Certificate Exchange Flow  ([#667](https://github.com/opentdf/platform/issues/667)) ([0e59213](https://github.com/opentdf/platform/commit/0e59213e127e8b6a0b071a04f3ce380907fe494e))

## [0.2.0](https://github.com/opentdf/platform/compare/lib/fixtures/v0.1.0...lib/fixtures/v0.2.0) (2024-04-26)


### Features

* allow --insecure in provision keycloak cmd ([#629](https://github.com/opentdf/platform/issues/629)) ([a672325](https://github.com/opentdf/platform/commit/a67232553ccf89be752e79093b536dee5dd62f14))
* **provisioning:** Keycloak provisioning from custom config  ([#573](https://github.com/opentdf/platform/issues/573)) ([f9e9d72](https://github.com/opentdf/platform/commit/f9e9d7288c1f63fdc1ffb0916fdb9ae4c390cee8))

## [0.1.0](https://github.com/opentdf/platform/compare/lib/fixtures-v0.1.0...lib/fixtures/v0.1.0) (2024-04-22)


### Features

* **sdk:** normalize token exchange ([#546](https://github.com/opentdf/platform/issues/546)) ([9059dff](https://github.com/opentdf/platform/commit/9059dff17c1f6cb3c0b7a8cad0b7b603dae4a9a7))


### Bug Fixes

* **service:** go.mod version fix sync ([#604](https://github.com/opentdf/platform/issues/604)) ([6323efd](https://github.com/opentdf/platform/commit/6323efdcd8fd44a0777ef433575ededf2a99d846))
