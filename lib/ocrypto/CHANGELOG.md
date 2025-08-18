# Changelog

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
