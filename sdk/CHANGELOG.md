# Changelog

## [0.2.8](https://github.com/opentdf/platform/compare/sdk/v0.2.7...sdk/v0.2.8) (2024-06-24)


### Features

* Audit GetDecisions ([#976](https://github.com/opentdf/platform/issues/976)) ([55bdfeb](https://github.com/opentdf/platform/commit/55bdfeb4dd4a846d244febd23825ced38e8e91b1))
* **core:** New cryptoProvider config ([#939](https://github.com/opentdf/platform/issues/939)) ([8150623](https://github.com/opentdf/platform/commit/81506237e2e640af34df8c745b71c3f20358d5a4))


### Bug Fixes

* **core:** Update to lib/fixtures 0.2.7 ([#1017](https://github.com/opentdf/platform/issues/1017)) ([dbae6ff](https://github.com/opentdf/platform/commit/dbae6ff10aadbfc805d9acef8440a7930f3c684e))
* **core:** Updates to protos 0.2.4 ([#1014](https://github.com/opentdf/platform/issues/1014)) ([43e11a3](https://github.com/opentdf/platform/commit/43e11a34c47c76fe2845d0a9d60a686ea394c131))

## [0.2.7](https://github.com/opentdf/platform/compare/sdk/v0.2.6...sdk/v0.2.7) (2024-06-10)


### Bug Fixes

* **sdk:** convert platform endpoint to grpc dial format ([#941](https://github.com/opentdf/platform/issues/941)) ([3a72a54](https://github.com/opentdf/platform/commit/3a72a54a31d35d31dfcc13ac6e716d68c9c909d1))

## [0.2.6](https://github.com/opentdf/platform/compare/sdk/v0.2.5...sdk/v0.2.6) (2024-06-04)


### Bug Fixes

* **core:** Bumps lib/fixtures ([#932](https://github.com/opentdf/platform/issues/932)) ([18586f9](https://github.com/opentdf/platform/commit/18586f9c96421ac63ddc4bb904604cbb8bdbed8c))
* **core:** update default casbin auth policy ([#927](https://github.com/opentdf/platform/issues/927)) ([c354fdb](https://github.com/opentdf/platform/commit/c354fdb118af4e4a222f3c65fcbf5de581d08bee))

## [0.2.5](https://github.com/opentdf/platform/compare/sdk/v0.2.4...sdk/v0.2.5) (2024-06-03)


### Features

* **sdk:** leverage platform wellknown configuration endpoint ([#895](https://github.com/opentdf/platform/issues/895)) ([53b3f42](https://github.com/opentdf/platform/commit/53b3f4231501c6e6ea54ee002c7420436bb44000))
* **sdk:** Support for ECDSA policy binding on both KAS and SDK ([#877](https://github.com/opentdf/platform/issues/877)) ([7baf039](https://github.com/opentdf/platform/commit/7baf03928eb3d29f615359860f9217a69b51c1fe))


### Bug Fixes

* **sdk:** bump ocrypto to 0.1.5 ([#912](https://github.com/opentdf/platform/issues/912)) ([6de799b](https://github.com/opentdf/platform/commit/6de799bc848b974120254575d3c211c553c2e2c0))

## [0.2.4](https://github.com/opentdf/platform/compare/sdk/v0.2.3...sdk/v0.2.4) (2024-05-30)


### Features

* **core:** Allow app specified session keys ([#882](https://github.com/opentdf/platform/issues/882)) ([529fb0e](https://github.com/opentdf/platform/commit/529fb0ec775eca93f8cdd83388eba950a5e81bba))
* **sdk:** Adds Option to Pass in RSA Keys to SDK ([#867](https://github.com/opentdf/platform/issues/867)) ([739a828](https://github.com/opentdf/platform/commit/739a828a65c4d4448dcb77c12d2bbae7cd18a060))
* **sdk:** PLAT-3082 nanotdf encrypt ([#744](https://github.com/opentdf/platform/issues/744)) ([6c82536](https://github.com/opentdf/platform/commit/6c8253689ec65e68c2114750c10c501423cbe03c))


### Bug Fixes

* **sdk:** if we encounter an error getting an access token then don't make the request ([#872](https://github.com/opentdf/platform/issues/872)) ([19188d5](https://github.com/opentdf/platform/commit/19188d5f713b3cca3c9f4568cf58cc54c86bd262))

## [0.2.3](https://github.com/opentdf/platform/compare/sdk/v0.2.2...sdk/v0.2.3) (2024-05-21)


### Features

* **authz:** Handle jwts as entity chains in decision requests ([#759](https://github.com/opentdf/platform/issues/759)) ([65612e0](https://github.com/opentdf/platform/commit/65612e08b418eb17c9576903c002685daed21ec1))
* **sdk:** Allow setting TDF mime type ([#797](https://github.com/opentdf/platform/issues/797)) ([97926a1](https://github.com/opentdf/platform/commit/97926a1c323f95bbc96b82acce00c1d2bd6eb378))


### Bug Fixes

* bump internal versions ([#840](https://github.com/opentdf/platform/issues/840)) ([8f45f18](https://github.com/opentdf/platform/commit/8f45f184eaa2512fd0633c4afaf9f148d415cb74))

## [0.2.2](https://github.com/opentdf/platform/compare/sdk/v0.2.1...sdk/v0.2.2) (2024-05-15)


### Bug Fixes

* **core:** Updates logs statements to log errors ([#796](https://github.com/opentdf/platform/issues/796)) ([7a3379b](https://github.com/opentdf/platform/commit/7a3379b6878562e4958e61516335e912716588b7))
* **sdk:** Reduces sdk go requirement to 1.21 ([#795](https://github.com/opentdf/platform/issues/795)) ([6baee80](https://github.com/opentdf/platform/commit/6baee801f7189aac95e6bf0235eeeca57fbc9bd2))

## [0.2.1](https://github.com/opentdf/platform/compare/sdk/v0.2.0...sdk/v0.2.1) (2024-05-10)


### Features

* **sdk:** Adds TLS Certificate Exchange Flow  ([#667](https://github.com/opentdf/platform/issues/667)) ([0e59213](https://github.com/opentdf/platform/commit/0e59213e127e8b6a0b071a04f3ce380907fe494e))
* **sdk:** insecure plaintext and skip verify conn ([#670](https://github.com/opentdf/platform/issues/670)) ([5c94d02](https://github.com/opentdf/platform/commit/5c94d027478314d703bf70885d6a80cdde585542))


### Bug Fixes

* **core:** Fix Lint ([#714](https://github.com/opentdf/platform/issues/714)) ([2b0cb09](https://github.com/opentdf/platform/commit/2b0cb099784110d2f812b050222d07fa5a22eafe)), closes [#701](https://github.com/opentdf/platform/issues/701)
* **core:** Fix several misspellings  ([#738](https://github.com/opentdf/platform/issues/738)) ([8d61db3](https://github.com/opentdf/platform/commit/8d61db343fd68291f80686496fec47b08aaf4746))

## [0.2.0](https://github.com/opentdf/platform/compare/sdk/v0.1.0...sdk/v0.2.0) (2024-04-26)


### Features

* **policy:** move key access server registry under policy ([#655](https://github.com/opentdf/platform/issues/655)) ([7b63394](https://github.com/opentdf/platform/commit/7b633942cc5b929122b9f765a5f35cb7b4dd391f))

## [0.1.0](https://github.com/opentdf/platform/compare/sdk-v0.1.0...sdk/v0.1.0) (2024-04-22)


### Features

* add structured schema policy config ([#51](https://github.com/opentdf/platform/issues/51)) ([8a6b876](https://github.com/opentdf/platform/commit/8a6b8762e62acb037544da47ddabdf60cd42b227))
* **auth:** add authorization via casbin ([#417](https://github.com/opentdf/platform/issues/417)) ([292f2bd](https://github.com/opentdf/platform/commit/292f2bd46a856aaac3b4c996b481f6b4872613cb))
* in-process service to service communication ([#311](https://github.com/opentdf/platform/issues/311)) ([ec5eb76](https://github.com/opentdf/platform/commit/ec5eb76725d81dfbe9eed0f49b8470b2669bcc26))
* **kas:** support HSM and standard crypto ([#497](https://github.com/opentdf/platform/issues/497)) ([f0cbe03](https://github.com/opentdf/platform/commit/f0cbe03b2c935ab141a3f296558f2d26a016fdc5))
* key access server assignments ([#111](https://github.com/opentdf/platform/issues/111)) ([a48d686](https://github.com/opentdf/platform/commit/a48d6864be6b9aa283c87e02f1f06673ad3ad899)), closes [#117](https://github.com/opentdf/platform/issues/117)
* key access server registry impl ([#66](https://github.com/opentdf/platform/issues/66)) ([cf6b3c6](https://github.com/opentdf/platform/commit/cf6b3c64cf4ab0a02cf369f28a504a9fe505b003))
* **namespaces CRUD:** protos, generated SDK, db interactivity for namespaces table ([#54](https://github.com/opentdf/platform/issues/54)) ([b3f32b1](https://github.com/opentdf/platform/commit/b3f32b1954a8a75399720ada2d170f334bcb2721))
* **PLAT-3112:** Initial consumption of ec_key_pair functions by nanotdf ([#586](https://github.com/opentdf/platform/issues/586)) ([5e2cba0](https://github.com/opentdf/platform/commit/5e2cba0a6a44bda440cf624f2131a9439d31f997))
* **policy:** add FQN pivot table ([#208](https://github.com/opentdf/platform/issues/208)) ([abb734c](https://github.com/opentdf/platform/commit/abb734c926950c6bfa942feb57d1b1652efc2434))
* **policy:** add soft-delete/deactivation to namespaces, attribute definitions, attribute values [#96](https://github.com/opentdf/platform/issues/96) [#108](https://github.com/opentdf/platform/issues/108) ([#191](https://github.com/opentdf/platform/issues/191)) ([02e92a6](https://github.com/opentdf/platform/commit/02e92a69785bb93d47dd78b1a702122a485830da))
* **resourcemapping:** resource mapping implementation ([#83](https://github.com/opentdf/platform/issues/83)) ([c144db1](https://github.com/opentdf/platform/commit/c144db1e0186367c95b8c946692e5035c1f8c319))
* **sdk:** BACK-1966 get auth wired up to SDK using `Options` ([#271](https://github.com/opentdf/platform/issues/271)) ([f1bacab](https://github.com/opentdf/platform/commit/f1bacabc763a3410962f18a3c7e85fdf1d4445ac))
* **sdk:** BACK-1966 implement fetching a DPoP token ([#45](https://github.com/opentdf/platform/issues/45)) ([dbd3cf9](https://github.com/opentdf/platform/commit/dbd3cf92d62e9ef68b492546b00cb21f00ef65f8))
* **sdk:** BACK-1966 make the unwrapper retrieve public keys as well ([#260](https://github.com/opentdf/platform/issues/260)) ([7d051a1](https://github.com/opentdf/platform/commit/7d051a15c83e87cdd1cfcab3f52472dfac5f2bfc))
* **sdk:** BACK-1966 pull rewrap into auth config ([#252](https://github.com/opentdf/platform/issues/252)) ([84017aa](https://github.com/opentdf/platform/commit/84017aaabf81421e548c6055741489e67f588c08))
* **sdk:** Include auth token in grpc ([#367](https://github.com/opentdf/platform/issues/367)) ([75cb5cd](https://github.com/opentdf/platform/commit/75cb5cd4109debf8cbdc1f878c2605610f86dfbc))
* **sdk:** normalize token exchange ([#546](https://github.com/opentdf/platform/issues/546)) ([9059dff](https://github.com/opentdf/platform/commit/9059dff17c1f6cb3c0b7a8cad0b7b603dae4a9a7))
* **sdk:** Pass dpop key through to `rewrap` ([#435](https://github.com/opentdf/platform/issues/435)) ([2d283de](https://github.com/opentdf/platform/commit/2d283de497c8db1e5a914c360dfde62d806014df))
* **sdk:** read `expires_in` from token response and use it to refresh access tokens ([#445](https://github.com/opentdf/platform/issues/445)) ([8ecbe79](https://github.com/opentdf/platform/commit/8ecbe798d7730057f7811e062c2a933848e696b1))
* **sdk:** sdk stub ([#10](https://github.com/opentdf/platform/issues/10)) ([8dfca6a](https://github.com/opentdf/platform/commit/8dfca6a159a8bf3ef422604524c67e689bcd9ebc))
* **sdk:** take a function so that callers can use this the way that they want ([#340](https://github.com/opentdf/platform/issues/340)) ([72059cb](https://github.com/opentdf/platform/commit/72059cbc3710f023f88fc1009dc6d3fe0e9898af))
* **subject-mappings:** refactor to meet db schema ([#59](https://github.com/opentdf/platform/issues/59)) ([59a073b](https://github.com/opentdf/platform/commit/59a073b5d1cabc991c689a584298ad9adc3f977e))
* **tdf:** implement tdf3 encrypt and decrypt ([#73](https://github.com/opentdf/platform/issues/73)) ([9d0e0a0](https://github.com/opentdf/platform/commit/9d0e0a0c51f05739b3737bc7c481b3bfc1b46165))
* **tdf:** sdk interface changes ([#123](https://github.com/opentdf/platform/issues/123)) ([2aa2422](https://github.com/opentdf/platform/commit/2aa24220297dada1b408758ac7ca2daa21706319))
* **tdf:** sdk interface cleanup ([#201](https://github.com/opentdf/platform/issues/201)) ([6f7d815](https://github.com/opentdf/platform/commit/6f7d815c45c417084b0e9c7745c996e91dbc821b))
* **tdf:** TDFOption varargs interface ([#235](https://github.com/opentdf/platform/issues/235)) ([b3fb720](https://github.com/opentdf/platform/commit/b3fb720f3b126dcd182d3133c603204646d5294d))


### Bug Fixes

* **archive:** remove 10gb zip file test ([#373](https://github.com/opentdf/platform/issues/373)) ([6548f55](https://github.com/opentdf/platform/commit/6548f55625201aead80347c4e48da3127559c6e4))
* attribute missing rpc method for listing attribute values ([#69](https://github.com/opentdf/platform/issues/69)) ([1b3a831](https://github.com/opentdf/platform/commit/1b3a831c5ad99afec3736b85dbef84bbdb76aa9e))
* **attribute value:** fixes attribute value crud ([#86](https://github.com/opentdf/platform/issues/86)) ([568df9c](https://github.com/opentdf/platform/commit/568df9ccc18d34a404ea37ad6879c384ddd1ad1e))
* **issue 90:** remove duplicate attribute_id from attribute value create/update, and consumes schema setup changes in namespaces that were introduced for integration testing ([#100](https://github.com/opentdf/platform/issues/100)) ([e0f6d07](https://github.com/opentdf/platform/commit/e0f6d074d90325100a49d951bb3792cb38dc65d3))
* **issue-124:** SDK kas registry import name mismatch ([#125](https://github.com/opentdf/platform/issues/125)) ([112638b](https://github.com/opentdf/platform/commit/112638bc493793a2d0dbd1ace3e6a8763632d973)), closes [#124](https://github.com/opentdf/platform/issues/124)
* **proto/acre:** fix resource encoding service typo ([#30](https://github.com/opentdf/platform/issues/30)) ([fe709d2](https://github.com/opentdf/platform/commit/fe709d2a08c776d614537b3f7638bd722028f93e))
* remove padding when b64 encoding ([#437](https://github.com/opentdf/platform/issues/437)) ([d40e94a](https://github.com/opentdf/platform/commit/d40e94a7081d2c666aa033d6bf596a753decdc6b))
* SDK Quickstart ([#628](https://github.com/opentdf/platform/issues/628)) ([f27ab98](https://github.com/opentdf/platform/commit/f27ab98e49a284cbebfbaa0ba0104cad101696af))
* **sdk:** change unwrapper creation ([#346](https://github.com/opentdf/platform/issues/346)) ([9206435](https://github.com/opentdf/platform/commit/920643565122c7adeaa3a955f4c26fedc424448e))
* **sdk:** double bearer token in auth config ([#350](https://github.com/opentdf/platform/issues/350)) ([1bf4699](https://github.com/opentdf/platform/commit/1bf469942886f9d2c353d6f804aee4b48934d112))
* **sdk:** fixes Manifests JSONs with OIDC ([#140](https://github.com/opentdf/platform/issues/140)) ([a4b6937](https://github.com/opentdf/platform/commit/a4b69378644e09ed71d4478293f856a4ee2ffae8))
* **sdk:** handle err ([#548](https://github.com/opentdf/platform/issues/548)) ([ebabb6c](https://github.com/opentdf/platform/commit/ebabb6c56bcf16105a65c1526b83d2397af19e75))
* **sdk:** make KasInfo fields public ([#320](https://github.com/opentdf/platform/issues/320)) ([9a70498](https://github.com/opentdf/platform/commit/9a704987920eedcc515d7c280cbe7be4f9f60f1c))
* **sdk:** shutdown conn ([#352](https://github.com/opentdf/platform/issues/352)) ([3def038](https://github.com/opentdf/platform/commit/3def0380e6e602f122580a0ec77e6dce274f27d7))
* **sdk:** temporarily move unwrapper creation into options func. ([#309](https://github.com/opentdf/platform/issues/309)) ([b34c2fe](https://github.com/opentdf/platform/commit/b34c2fe9ad708b0d6c7cd0d1839de8fc3ace5ce9))
* **sdk:** use the dialoptions even with no client credentials ([#400](https://github.com/opentdf/platform/issues/400)) ([a7f1908](https://github.com/opentdf/platform/commit/a7f1908bec322f27a5397013286741950a372394))
* **security:** add a new encryption keypair different from dpop keypair ([#461](https://github.com/opentdf/platform/issues/461)) ([7deb51e](https://github.com/opentdf/platform/commit/7deb51eca8bc9414d20913e7984ec76345312da0))
