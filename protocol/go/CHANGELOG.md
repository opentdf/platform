# Changelog

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
