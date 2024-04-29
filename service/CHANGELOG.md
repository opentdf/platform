# Changelog

## [0.2.0](https://github.com/opentdf/platform/compare/service/v0.1.0...service/v0.2.0) (2024-04-26)


### Features

* **policy:** move key access server registry under policy ([#655](https://github.com/opentdf/platform/issues/655)) ([7b63394](https://github.com/opentdf/platform/commit/7b633942cc5b929122b9f765a5f35cb7b4dd391f))
* **provisioning:** Keycloak provisioning from custom config  ([#573](https://github.com/opentdf/platform/issues/573)) ([f9e9d72](https://github.com/opentdf/platform/commit/f9e9d7288c1f63fdc1ffb0916fdb9ae4c390cee8))
* **sdk:** make enforcement of DPoP optional ([#617](https://github.com/opentdf/platform/issues/617)) ([028064c](https://github.com/opentdf/platform/commit/028064c606b99762d30414e05c9e36b5214d6c9c))


### Bug Fixes

* **core:** remove unused db argument ([#653](https://github.com/opentdf/platform/issues/653)) ([cfbd168](https://github.com/opentdf/platform/commit/cfbd168b8cf25a95cc29ca1b727fbbf811373352))
* **db:** invalid uuid error message ([#633](https://github.com/opentdf/platform/issues/633)) ([c8f61aa](https://github.com/opentdf/platform/commit/c8f61aa066927f92de89d48485ee3c561751a2bf))
* **sdk:** this (`enforceDPoP`) flag needs to be flipped ([#649](https://github.com/opentdf/platform/issues/649)) ([dd65db1](https://github.com/opentdf/platform/commit/dd65db18d5b4e4d51a6a1a0ae3ca0bc6533dc85a))

## [0.1.0](https://github.com/opentdf/platform/compare/service-v0.1.0...service/v0.1.0) (2024-04-22)


### ⚠ BREAKING CHANGES

* Singular platform/service ([#511](https://github.com/opentdf/platform/issues/511))

### Features

* ability to add public routes that bypass authn middleware ([#601](https://github.com/opentdf/platform/issues/601)) ([7c65308](https://github.com/opentdf/platform/commit/7c6530846eb7df86ac6421435a2cc27d17f10af6))
* ability to set config key or config file from root cmd ([#502](https://github.com/opentdf/platform/issues/502)) ([56a0131](https://github.com/opentdf/platform/commit/56a01312915a50ada08db4e877718741ffcdba0f))
* allow --insecure in provision keycloak cmd ([#629](https://github.com/opentdf/platform/issues/629)) ([a672325](https://github.com/opentdf/platform/commit/a67232553ccf89be752e79093b536dee5dd62f14))
* **kas:** support HSM and standard crypto ([#497](https://github.com/opentdf/platform/issues/497)) ([f0cbe03](https://github.com/opentdf/platform/commit/f0cbe03b2c935ab141a3f296558f2d26a016fdc5))
* **opa:** Adding jq OPA builtin for selection ([#527](https://github.com/opentdf/platform/issues/527)) ([d4ab17a](https://github.com/opentdf/platform/commit/d4ab17a9a838cc11032f14d6c9dfe6ee2be973df))
* **policy:** add `created_at` and `updated_at` timestamps to metadata ([#538](https://github.com/opentdf/platform/issues/538)) ([e812563](https://github.com/opentdf/platform/commit/e812563654f18f1a9a6b3dada3918a59172e6bb4))
* **policy:** update fixtures, proto comments, and proto field names to reflect use of jq selector syntax within Conditions of Subject Sets ([#523](https://github.com/opentdf/platform/issues/523)) ([16f40f7](https://github.com/opentdf/platform/commit/16f40f7727f7c695f9b5d9f5aac26c348dbee4a2))
* **sdk:** don't require `client_id` in the auth token ([#544](https://github.com/opentdf/platform/issues/544)) ([a1e70f9](https://github.com/opentdf/platform/commit/a1e70f9db0d64c61086f2e94a812d735d0aee094))
* **sdk:** normalize token exchange ([#546](https://github.com/opentdf/platform/issues/546)) ([9059dff](https://github.com/opentdf/platform/commit/9059dff17c1f6cb3c0b7a8cad0b7b603dae4a9a7))


### Bug Fixes

* **authorization:** Hierarchy working in GetDecisions ([#519](https://github.com/opentdf/platform/issues/519)) ([2856485](https://github.com/opentdf/platform/commit/2856485687bd71d650f15ec17cc490babd8ffd55))
* **core:** allow org-admin casbin role to call KAS rewrap endpoint ([#579](https://github.com/opentdf/platform/issues/579)) ([a64c62a](https://github.com/opentdf/platform/commit/a64c62abecdd4580d6074435b0e06462ea7f11a4))
* **core:** fix panic on nil pointer dereference by passing KAS the SDK instance on registration ([#574](https://github.com/opentdf/platform/issues/574)) ([327bfca](https://github.com/opentdf/platform/commit/327bfca1302a90a7b0ba8085800f15209417693d))
* **core:** fixes fixtures provisioning after filepath change with repo restructuring ([#521](https://github.com/opentdf/platform/issues/521)) ([f128e9f](https://github.com/opentdf/platform/commit/f128e9fb23fef35200faac756f04683627a46344))
* load extraprops for a service config with remainder values ([#524](https://github.com/opentdf/platform/issues/524)) ([d3d72dc](https://github.com/opentdf/platform/commit/d3d72dc4eeca92253da080e66523de9a0de78542))
* **PLAT-3069:** opentdf/platform, gRPC: Namespace with existed attribute(s) can be deactivated w/o any prompts ([#489](https://github.com/opentdf/platform/issues/489)) ([e5a3324](https://github.com/opentdf/platform/commit/e5a33244cff4e3004f5b65779c04c6c2300760d5))
* **policy:** remove hardcoded schema in goose migration 20240405000000 ([#596](https://github.com/opentdf/platform/issues/596)) ([36c3b16](https://github.com/opentdf/platform/commit/36c3b16ec2583af8e8cedd70f463b3ff8a92e247))
* **policy:** return `created_at` and `updated_at` timestamps in CREATE metadata ([#557](https://github.com/opentdf/platform/issues/557)) ([fcaaeea](https://github.com/opentdf/platform/commit/fcaaeea52f9c49a2d9bef976e5319fe31813ff3b))
* resolves issues auth policy configuration ([#498](https://github.com/opentdf/platform/issues/498)) ([08e67cf](https://github.com/opentdf/platform/commit/08e67cf2fdfe33dabcbab0110887e7fdf8412fe2))
* **service:** go.mod version fix sync ([#604](https://github.com/opentdf/platform/issues/604)) ([6323efd](https://github.com/opentdf/platform/commit/6323efdcd8fd44a0777ef433575ededf2a99d846))
* url encode db password field to handle special characters ([#624](https://github.com/opentdf/platform/issues/624)) ([5069f9d](https://github.com/opentdf/platform/commit/5069f9dc7f0be62562f3d4b9b699778aef5e6a3b))


### Code Refactoring

* Singular platform/service ([#511](https://github.com/opentdf/platform/issues/511)) ([40c8b97](https://github.com/opentdf/platform/commit/40c8b971b249622301e73a74753ded132492a089))
