# Changelog

## [0.9.0](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.8.0...lib/ocrypto/v0.9.0) (2026-01-26)


### ⚠ BREAKING CHANGES

* remove nanotdf support ([#3013](https://github.com/opentdf/platform/issues/3013))

### Bug Fixes

* remove nanotdf support ([#3013](https://github.com/opentdf/platform/issues/3013)) ([90ff7ce](https://github.com/opentdf/platform/commit/90ff7ce50754a1f37ba1cc530507c1f6e15930a0))

## [0.8.0](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.7.0...lib/ocrypto/v0.8.0) (2025-12-19)


### Features

* Update Go toolchain version to 1.24.11 across all modules ([#2943](https://github.com/opentdf/platform/issues/2943)) ([a960eca](https://github.com/opentdf/platform/commit/a960eca78ab8870599f0aa2a315dbada355adf20))


### Bug Fixes

* **deps:** bump toolchain to go1.24.9 for CVEs found by govulncheck ([#2849](https://github.com/opentdf/platform/issues/2849)) ([23f76c0](https://github.com/opentdf/platform/commit/23f76c034cfb4c325d868eb96c95ba616e362db4))
* **sdk:** more efficient encryption in experiment TDF Writer ([#2904](https://github.com/opentdf/platform/issues/2904)) ([3ec0518](https://github.com/opentdf/platform/commit/3ec05180ab567e78def51be90b10dd137f3a1f61))

## [0.7.0](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.6.0...lib/ocrypto/v0.7.0) (2025-10-15)


### Features

* **core:** Adds helper `KeyType` method ([#2735](https://github.com/opentdf/platform/issues/2735)) ([7147c4b](https://github.com/opentdf/platform/commit/7147c4bcee9f691b6e9684e9922c16b55f0b2950))
* use public AES protected key from lib/ocrypto ([#2600](https://github.com/opentdf/platform/issues/2600)) ([75d7590](https://github.com/opentdf/platform/commit/75d7590ec062f822045027d4eb0b59a48bdea465))

## [0.6.0](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.5.0...lib/ocrypto/v0.6.0) (2025-09-11)


### Bug Fixes

* have export call encrypt instead of encapsulate ([#2709](https://github.com/opentdf/platform/issues/2709)) ([cdff893](https://github.com/opentdf/platform/commit/cdff893a09b66a386ec7ff19490ff777cdb84a14))

## [0.5.0](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.4.0...lib/ocrypto/v0.5.0) (2025-09-04)


### Features

* **core:** Encapsulate&gt;Encrypt ([#2676](https://github.com/opentdf/platform/issues/2676)) ([3c5a614](https://github.com/opentdf/platform/commit/3c5a6145c9bcac47001639bdcf2576a444493dd5))

## [0.4.0](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.3.0...lib/ocrypto/v0.4.0) (2025-09-02)


### Features

* add AES protected key interface and implementation ([#2599](https://github.com/opentdf/platform/issues/2599)) ([2bb7eb0](https://github.com/opentdf/platform/commit/2bb7eb06858b2b53e608dd016d5a7a15e4092db2))

## [0.3.0](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.2.0...lib/ocrypto/v0.3.0) (2025-06-30)


### Features

* **sdk:** Adds rsa:4096 support to ocrypto; fix larger curves ([#2478](https://github.com/opentdf/platform/issues/2478)) ([44d800e](https://github.com/opentdf/platform/commit/44d800e262258325a4a24e5633686103d8914212))

## [0.2.0](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.9...lib/ocrypto/v0.2.0) (2025-05-22)


### ⚠ BREAKING CHANGES

* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979))

### Features

* **core:** Adds EC withSalt options ([#2126](https://github.com/opentdf/platform/issues/2126)) ([67b6fb8](https://github.com/opentdf/platform/commit/67b6fb8fc1263a4ddfa8ae1c8d451db50be77988))
* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979)) ([164c922](https://github.com/opentdf/platform/commit/164c922af74b1265fe487362c356abb7f1503ada))


### Bug Fixes

* perfsprint lint issues ([#2209](https://github.com/opentdf/platform/issues/2209)) ([7cf8b53](https://github.com/opentdf/platform/commit/7cf8b5372a1f90f12a3b6e4038305bea9a877ee9))

## [0.1.9](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.8...lib/ocrypto/v0.1.9) (2025-03-07)


### Bug Fixes

* **core:** Updates ec-wrapped to newer salt ([#1961](https://github.com/opentdf/platform/issues/1961)) ([0e17968](https://github.com/opentdf/platform/commit/0e17968e4bd4e69ddf7f676733327d6f0e0e36f0))

## [0.1.8](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.7...lib/ocrypto/v0.1.8) (2025-02-25)


### Features

* **core:** EXPERIMENTAL: EC-wrapped key support ([#1902](https://github.com/opentdf/platform/issues/1902)) ([652266f](https://github.com/opentdf/platform/commit/652266f212ba10b2492a84741f68391a1d39e007))
* **kas:** collect metrics ([#1702](https://github.com/opentdf/platform/issues/1702)) ([def28d1](https://github.com/opentdf/platform/commit/def28d1984b0b111a07330a3eb59c1285206062d))

## [0.1.7](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.6...lib/ocrypto/v0.1.7) (2024-11-15)


### Features

* **sdk:** add collections for nanotdf  ([#1695](https://github.com/opentdf/platform/issues/1695)) ([6497bf3](https://github.com/opentdf/platform/commit/6497bf3a7cee9b6900569bc6cc2c39b2f647fb52))

## [0.1.6](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.5...lib/ocrypto/v0.1.6) (2024-10-03)


### Features

* **sdk:** Improve KAS key lookup and caching ([#1556](https://github.com/opentdf/platform/issues/1556)) ([fb6c47a](https://github.com/opentdf/platform/commit/fb6c47a95f2e91748436a76aeef46a81273bb10d))

## [0.1.5](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.4...lib/ocrypto/v0.1.5) (2024-05-31)


### Features

* **sdk:** Support for ECDSA policy binding on both KAS and SDK ([#877](https://github.com/opentdf/platform/issues/877)) ([7baf039](https://github.com/opentdf/platform/commit/7baf03928eb3d29f615359860f9217a69b51c1fe))

## [0.1.4](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.3...lib/ocrypto/v0.1.4) (2024-05-29)


### Features

* **core:** Allow app specified session keys ([#882](https://github.com/opentdf/platform/issues/882)) ([529fb0e](https://github.com/opentdf/platform/commit/529fb0ec775eca93f8cdd83388eba950a5e81bba))
* **sdk:** PLAT-3082 nanotdf encrypt ([#744](https://github.com/opentdf/platform/issues/744)) ([6c82536](https://github.com/opentdf/platform/commit/6c8253689ec65e68c2114750c10c501423cbe03c))

## [0.1.3](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.2...lib/ocrypto/v0.1.3) (2024-05-20)


### Features

* **core:** Adds opentdf.hsm build constraint ([#830](https://github.com/opentdf/platform/issues/830)) ([e13e52a](https://github.com/opentdf/platform/commit/e13e52a5fb860213b195a14a5d2be087ffb49cb3))

## [0.1.2](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.1...lib/ocrypto/v0.1.2) (2024-05-13)


### Bug Fixes

* **core:** Bump libs patch version ([#779](https://github.com/opentdf/platform/issues/779)) ([3b68dea](https://github.com/opentdf/platform/commit/3b68dea867609071047554a6a7697becaaee2805))

## [0.1.1](https://github.com/opentdf/platform/compare/lib/ocrypto/v0.1.0...lib/ocrypto/v0.1.1) (2024-05-07)


### Features

* **crypto:** nanotdf crypto helper methods ([#592](https://github.com/opentdf/platform/issues/592)) ([9374f04](https://github.com/opentdf/platform/commit/9374f044621936cbf40ff7b9913a68e289059219))

## [0.1.0](https://github.com/opentdf/platform/compare/lib/ocrypto-v0.1.0...lib/ocrypto/v0.1.0) (2024-04-22)


### Features

* **kas:** support HSM and standard crypto ([#497](https://github.com/opentdf/platform/issues/497)) ([f0cbe03](https://github.com/opentdf/platform/commit/f0cbe03b2c935ab141a3f296558f2d26a016fdc5))
* **PLAT-3112:** Add Elliptic Curve functionality to support nanotdf ([#576](https://github.com/opentdf/platform/issues/576)) ([504482a](https://github.com/opentdf/platform/commit/504482af216e0d91586e92e79554da9b7ffe6571))
* **PLAT-3112:** Initial consumption of ec_key_pair functions by nanotdf ([#586](https://github.com/opentdf/platform/issues/586)) ([5e2cba0](https://github.com/opentdf/platform/commit/5e2cba0a6a44bda440cf624f2131a9439d31f997))
