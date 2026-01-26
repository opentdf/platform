# Changelog

## [0.15.0](https://github.com/opentdf/platform/compare/protocol/go/v0.14.0...protocol/go/v0.15.0) (2026-01-26)


### ⚠ BREAKING CHANGES

* remove nanotdf support ([#3013](https://github.com/opentdf/platform/issues/3013))

### Features

* **core:** add direct entitlement support ([#2630](https://github.com/opentdf/platform/issues/2630)) ([cc8337a](https://github.com/opentdf/platform/commit/cc8337a4d4b6be4cb1f4117711109c2d8d599cb9))
* **policy:** add allow_traversal to attribute definitions ([#3014](https://github.com/opentdf/platform/issues/3014)) ([bbbe21b](https://github.com/opentdf/platform/commit/bbbe21bb671f5ffedd116a08ff15779ce7034fcb))


### Bug Fixes

* Connect RPC v1.19.1  ([#3009](https://github.com/opentdf/platform/issues/3009)) ([c354fd3](https://github.com/opentdf/platform/commit/c354fd387f2e17f764feacf302488d9afdbac5f0))
* remove nanotdf support ([#3013](https://github.com/opentdf/platform/issues/3013)) ([90ff7ce](https://github.com/opentdf/platform/commit/90ff7ce50754a1f37ba1cc530507c1f6e15930a0))

## [0.14.0](https://github.com/opentdf/platform/compare/protocol/go/v0.13.0...protocol/go/v0.14.0) (2025-12-19)


### Features

* Update Go toolchain version to 1.24.11 across all modules ([#2943](https://github.com/opentdf/platform/issues/2943)) ([a960eca](https://github.com/opentdf/platform/commit/a960eca78ab8870599f0aa2a315dbada355adf20))


### Bug Fixes

* **deps:** bump toolchain to go1.24.9 for CVEs found by govulncheck ([#2849](https://github.com/opentdf/platform/issues/2849)) ([23f76c0](https://github.com/opentdf/platform/commit/23f76c034cfb4c325d868eb96c95ba616e362db4))
* **kas:** document rewrap proto fields used in bulk flow ([#2826](https://github.com/opentdf/platform/issues/2826)) ([32a7e91](https://github.com/opentdf/platform/commit/32a7e919c57fd724f5c4f01148861ebccb1a9989))

## [0.13.0](https://github.com/opentdf/platform/compare/protocol/go/v0.12.0...protocol/go/v0.13.0) (2025-10-16)


### Features

* **policy:** Protos List obligation triggers ([#2803](https://github.com/opentdf/platform/issues/2803)) ([b32df81](https://github.com/opentdf/platform/commit/b32df81f6fe35f9db07e58f49ca71b43d7a02a13))

## [0.12.0](https://github.com/opentdf/platform/compare/protocol/go/v0.11.0...protocol/go/v0.12.0) (2025-10-14)


### Features

* **authz:** defer to request auth as decision/entitlements entity ([#2789](https://github.com/opentdf/platform/issues/2789)) ([feb34d8](https://github.com/opentdf/platform/commit/feb34d85a3cd9324a95cc7a2fac92a2e658170fe))
* **policy:** Proto - root certificates by namespace ([#2800](https://github.com/opentdf/platform/issues/2800)) ([0edb359](https://github.com/opentdf/platform/commit/0edb3591bc0c12b3ffb47b4e43d19b56dae3d016))


### Bug Fixes

* **core:** deprecated stale protos and add better upgrade comments ([#2793](https://github.com/opentdf/platform/issues/2793)) ([f2678cc](https://github.com/opentdf/platform/commit/f2678cc6929824ae3d73d2c808ce8412086011ee))

## [0.11.0](https://github.com/opentdf/platform/compare/protocol/go/v0.10.0...protocol/go/v0.11.0) (2025-09-18)


### Features

* **authz:** obligations protos within auth service ([#2745](https://github.com/opentdf/platform/issues/2745)) ([41ee5a8](https://github.com/opentdf/platform/commit/41ee5a8c0caaa99d5b80d6ebb23696d13053938f))
* **policy:** Return obligations from GetAttributeValue calls ([#2742](https://github.com/opentdf/platform/issues/2742)) ([aa9b393](https://github.com/opentdf/platform/commit/aa9b393ac27522a3db69131a48409d8f297ebe56))

## [0.10.0](https://github.com/opentdf/platform/compare/protocol/go/v0.9.0...protocol/go/v0.10.0) (2025-09-16)


### Features

* **policy:** add protovalidate for obligation defs + vals ([#2699](https://github.com/opentdf/platform/issues/2699)) ([af5c049](https://github.com/opentdf/platform/commit/af5c049435355646b7b59fd3a4b0191875a4b88d))

## [0.9.0](https://github.com/opentdf/platform/compare/protocol/go/v0.8.0...protocol/go/v0.9.0) (2025-09-11)


### Features

* **policy:** add FQN of obligation definitions/values to protos ([#2703](https://github.com/opentdf/platform/issues/2703)) ([45ded0e](https://github.com/opentdf/platform/commit/45ded0e2717cca7ca8465e642c05e02ca4acd6c5))
* **policy:** Add obligation triggers ([#2675](https://github.com/opentdf/platform/issues/2675)) ([22d0837](https://github.com/opentdf/platform/commit/22d08378c06eef1ec5d59250d3e22f81d230c49d))
* **policy:** Allow creation and update of triggers on Obligation Values ([#2691](https://github.com/opentdf/platform/issues/2691)) ([b1e7ba1](https://github.com/opentdf/platform/commit/b1e7ba14a34c719d711db45cc9401c332c1175a5))
* **policy:** Allow for additional context to be added to obligation triggers ([#2705](https://github.com/opentdf/platform/issues/2705)) ([7025599](https://github.com/opentdf/platform/commit/7025599b30e76bb5b546f5d68f5fee9405f8a0b5))
* **policy:** obligations + values CRUD ([#2545](https://github.com/opentdf/platform/issues/2545)) ([c194e35](https://github.com/opentdf/platform/commit/c194e3522b9dfab74a5a21747d012f88a188f989))


### Bug Fixes

* **deps:** update protovalidate to v0.14.2 to use new buf validate MessageOneofRule ([#2698](https://github.com/opentdf/platform/issues/2698)) ([1cae18e](https://github.com/opentdf/platform/commit/1cae18e6b6f4a72869b0cdb65d775e108da07872))

## [0.8.0](https://github.com/opentdf/platform/compare/protocol/go/v0.7.0...protocol/go/v0.8.0) (2025-09-04)


### ⚠ BREAKING CHANGES

* **policy:** Add manager column to provider configuration for  multi-instance support ([#2601](https://github.com/opentdf/platform/issues/2601))

### Features

* **policy:** Add manager column to provider configuration for  multi-instance support ([#2601](https://github.com/opentdf/platform/issues/2601)) ([a5fc994](https://github.com/opentdf/platform/commit/a5fc994acc5491bf8cbf751b675302b459e1f3b0))

## [0.7.0](https://github.com/opentdf/platform/compare/protocol/go/v0.6.2...protocol/go/v0.7.0) (2025-08-08)

### Features

* **policy:** Add legacy keys. ([#2613](https://github.com/opentdf/platform/issues/2613)) ([57370b0](https://github.com/opentdf/platform/commit/57370b0f76605ec2ed375728ec9b60a829072d99))
* **policy:** add obligation protos ([#2579](https://github.com/opentdf/platform/issues/2579)) ([50882e1](https://github.com/opentdf/platform/commit/50882e10abff64e14548e0c51851a4b671ef8b11))
* **policy:** add values to CreateObligationRequest ([#2614](https://github.com/opentdf/platform/issues/2614)) ([94535cc](https://github.com/opentdf/platform/commit/94535cc0c1622b7499dad8e91a02a93f1eb1531b))
* **policy:** Allow the deletion of a key. ([#2575](https://github.com/opentdf/platform/issues/2575)) ([82b96f0](https://github.com/opentdf/platform/commit/82b96f023662c0a6c76af6d1196f78ab28a6acf0))

## [0.6.2](https://github.com/opentdf/platform/compare/protocol/go/v0.6.1...protocol/go/v0.6.2) (2025-07-22)

### Features

* **policy:** Add validation to delete keys [backport to release/protocol/go/v0.6] ([#2577](https://github.com/opentdf/platform/issues/2577)) ([f1f5819](https://github.com/opentdf/platform/commit/f1f5819f95eda5b98cf002a43bd47a4e5b2c62d0))

## [0.6.1](https://github.com/opentdf/platform/compare/protocol/go/v0.6.0...protocol/go/v0.6.1) (2025-07-22)

### Features

* **policy:** Change return type for delete key proto. [backport to release/protocol/go/v0.6] ([#2568](https://github.com/opentdf/platform/issues/2568)) ([bb38eca](https://github.com/opentdf/platform/commit/bb38ecaf75feee91484b1a2f8e835e2fc57633d7))

## [0.6.0](https://github.com/opentdf/platform/compare/protocol/go/v0.5.0...protocol/go/v0.6.0) (2025-07-09)

### Features

* **authz:** sensible request limit upper bounds ([#2526](https://github.com/opentdf/platform/issues/2526)) ([b3093cc](https://github.com/opentdf/platform/commit/b3093cce2ffd1f1cdaec884967dc96a40caa2903))
* **policy:** Add list key mappings rpc. ([#2533](https://github.com/opentdf/platform/issues/2533)) ([fbc2724](https://github.com/opentdf/platform/commit/fbc2724a066b5e4121838a958cb926a1ab5bdcde))

### Bug Fixes

* **core:** Allow 521 curve to be used ([#2485](https://github.com/opentdf/platform/issues/2485)) ([aaf43dc](https://github.com/opentdf/platform/commit/aaf43dc368b4cabbc9affa0a6075abd335aa57e3))
