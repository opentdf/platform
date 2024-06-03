# Changelog

## [0.4.4](https://github.com/opentdf/platform/compare/service/v0.4.3...service/v0.4.4) (2024-05-30)


### Features

* **sdk:** PLAT-3082 nanotdf encrypt ([#744](https://github.com/opentdf/platform/issues/744)) ([6c82536](https://github.com/opentdf/platform/commit/6c8253689ec65e68c2114750c10c501423cbe03c))


### Bug Fixes

* **kas:** lowercase config mapstructure for kas key paths ([#891](https://github.com/opentdf/platform/issues/891)) ([b205926](https://github.com/opentdf/platform/commit/b205926bad5b6787c04a5f02cdf0040bc103b98d)), closes [#890](https://github.com/opentdf/platform/issues/890)
* **policy:** downgrade policy SQL statement info level logs to debug ([#853](https://github.com/opentdf/platform/issues/853)) ([771abd6](https://github.com/opentdf/platform/commit/771abd6423d15b7dc30ba4742348f0195ea36037)), closes [#845](https://github.com/opentdf/platform/issues/845)
* **core:** bump sdk version in service module ([#892](https://github.com/opentdf/platform/pull/892)) ([d66ce92](https://github.com/opentdf/platform/commit/d66ce9205ec6482aec315961fe2ceff57b2357be))

## [0.4.3](https://github.com/opentdf/platform/compare/service/v0.4.2...service/v0.4.3) (2024-05-22)


### Features

* **authz:** Allow un-scoped GetEntitlements calls ([#833](https://github.com/opentdf/platform/issues/833)) ([9146947](https://github.com/opentdf/platform/commit/9146947a8df6f91dc733e957ba9b663223cd4fc4))
* **authz:** Handle jwts as entity chains in decision requests ([#759](https://github.com/opentdf/platform/issues/759)) ([65612e0](https://github.com/opentdf/platform/commit/65612e08b418eb17c9576903c002685daed21ec1))
* **ci:** Add e2e roundtrip tests for different attribute combinations ([#790](https://github.com/opentdf/platform/issues/790)) ([1b0ec23](https://github.com/opentdf/platform/commit/1b0ec2347b1dc43c90fae600aebe9707351ea9c0))
* **core:** Adds opentdf.hsm build constraint ([#830](https://github.com/opentdf/platform/issues/830)) ([e13e52a](https://github.com/opentdf/platform/commit/e13e52a5fb860213b195a14a5d2be087ffb49cb3))
* **core:** audit logging ([#774](https://github.com/opentdf/platform/issues/774)) ([ea58b3c](https://github.com/opentdf/platform/commit/ea58b3c359d3a68c6436b0472c90bfd5ad4cb06c))


### Bug Fixes

* **authz:** Populate fqn field in attribute values returned from GetAttributeValuesByFqns ([#816](https://github.com/opentdf/platform/issues/816)) ([0ac8390](https://github.com/opentdf/platform/commit/0ac83904836f1c0b42416d137f4a929a7804467d))
* **authz:** Typo in client secret config ([#835](https://github.com/opentdf/platform/issues/835)) ([7cad1f1](https://github.com/opentdf/platform/commit/7cad1f11cc16d81e3b37a5b17dc6f1298f423496))
* bump internal versions ([#840](https://github.com/opentdf/platform/issues/840)) ([8f45f18](https://github.com/opentdf/platform/commit/8f45f184eaa2512fd0633c4afaf9f148d415cb74))
* **core:** bump sdk deps to 0.2.3 ([#848](https://github.com/opentdf/platform/issues/848)) ([ca8b9f7](https://github.com/opentdf/platform/commit/ca8b9f71102dbdbfcb7b6a327567d7a078e4e4f7))
* **policy:** fix policy fqn-reindex command schema suffix ([#818](https://github.com/opentdf/platform/issues/818)) ([aff9850](https://github.com/opentdf/platform/commit/aff985092e83b5d1c14ef48f9c92df66b726e8d2)), closes [#817](https://github.com/opentdf/platform/issues/817)
* **policy:** GetAttributeValuesByFqns and MatchSubjectMappings should not return deactivated policy objects ([#813](https://github.com/opentdf/platform/issues/813)) ([41ca82d](https://github.com/opentdf/platform/commit/41ca82d692209d120bfa52800fa0988bf373b0b5)), closes [#494](https://github.com/opentdf/platform/issues/494)
* **policy:** make resource-mappings update patch instead of put in RESTful gateway ([#824](https://github.com/opentdf/platform/issues/824)) ([1878bb5](https://github.com/opentdf/platform/commit/1878bb55fb17419487e6c8add6d363469e364923)), closes [#313](https://github.com/opentdf/platform/issues/313)

## [0.4.2](https://github.com/opentdf/platform/compare/service/v0.4.1...service/v0.4.2) (2024-05-15)


### Features

* **docs:** improve serviceregistry doc annotations ([#799](https://github.com/opentdf/platform/issues/799)) ([df8a504](https://github.com/opentdf/platform/commit/df8a504753690bf2b0814416999512eed0557291))


### Bug Fixes

* **authz:** Adds jwt to context when verified ([#764](https://github.com/opentdf/platform/issues/764)) ([7bf6513](https://github.com/opentdf/platform/commit/7bf65135779e95094acfdf140e7ff73f581d09cf))
* **ci:** Use the correct schema with the provision fixture command ([#794](https://github.com/opentdf/platform/issues/794)) ([459e82a](https://github.com/opentdf/platform/commit/459e82aa3c1d278f5ac5f4835f94d9f3fe90727e))
* **core:** Bump dep on sdk; reduce go to 1.21 ([#815](https://github.com/opentdf/platform/issues/815)) ([fe4a5ca](https://github.com/opentdf/platform/commit/fe4a5ca4321dd3c30022e9590b0c8a58719e03ea))
* **core:** rollup readiness checks to central health service ([#755](https://github.com/opentdf/platform/issues/755)) ([8a65161](https://github.com/opentdf/platform/commit/8a65161729d634cc10a5d48d23030866b50e6b01)), closes [#726](https://github.com/opentdf/platform/issues/726)
* **core:** Updates logs statements to log errors ([#796](https://github.com/opentdf/platform/issues/796)) ([7a3379b](https://github.com/opentdf/platform/commit/7a3379b6878562e4958e61516335e912716588b7))
* **core:** wrong AuthorizationService provided with missing logger ([#791](https://github.com/opentdf/platform/issues/791)) ([b13be04](https://github.com/opentdf/platform/commit/b13be04889e4bb14cc8ec36484041dc2640d0257))
* **sdk:** Reduces sdk go requirement to 1.21 ([#795](https://github.com/opentdf/platform/issues/795)) ([6baee80](https://github.com/opentdf/platform/commit/6baee801f7189aac95e6bf0235eeeca57fbc9bd2))
* **service:** cleanup the cryptoprovider config ([#803](https://github.com/opentdf/platform/issues/803)) ([1458d17](https://github.com/opentdf/platform/commit/1458d174cbc2861c4bd0bf9dfeec10fcf3c9dc2f))

## [0.4.1](https://github.com/opentdf/platform/compare/service/v0.4.0...service/v0.4.1) (2024-05-07)


### Features

* **core:** cors config ([#746](https://github.com/opentdf/platform/issues/746)) ([3433b5b](https://github.com/opentdf/platform/commit/3433b5b464ac309c9b8f225d2362d2eb24a56886))
* **core:** Service Level Child Loggers ([#740](https://github.com/opentdf/platform/issues/740)) ([aa0f210](https://github.com/opentdf/platform/commit/aa0f21098a45265b3443e0cbfb7722d9ab107fde))
* **ers:** Create entity resolution service, replace idp plugin ([#660](https://github.com/opentdf/platform/issues/660)) ([ff44112](https://github.com/opentdf/platform/commit/ff441128a4b2ef97c3f739ee3f6f42be273b31dc))
* **sdk:** insecure plaintext and skip verify conn ([#670](https://github.com/opentdf/platform/issues/670)) ([5c94d02](https://github.com/opentdf/platform/commit/5c94d027478314d703bf70885d6a80cdde585542))


### Bug Fixes

* **core:** Fix Lint ([#714](https://github.com/opentdf/platform/issues/714)) ([2b0cb09](https://github.com/opentdf/platform/commit/2b0cb099784110d2f812b050222d07fa5a22eafe)), closes [#701](https://github.com/opentdf/platform/issues/701)
* **core:** Fix several misspellings  ([#738](https://github.com/opentdf/platform/issues/738)) ([8d61db3](https://github.com/opentdf/platform/commit/8d61db343fd68291f80686496fec47b08aaf4746))

## [0.4.0](https://github.com/opentdf/platform/compare/service/v0.3.0...service/v0.4.0) (2024-04-30)


### Features

* **chore:** move db to pkg so types are exported ([#707](https://github.com/opentdf/platform/issues/707)) ([94d3d9d](https://github.com/opentdf/platform/commit/94d3d9d90aa62197bc075e2ebfc919dbd719e063)), closes [#706](https://github.com/opentdf/platform/issues/706)

## [0.3.0](https://github.com/opentdf/platform/compare/service/v0.2.0...service/v0.3.0) (2024-04-29)


### Features

* **core:** add service scoped database clients ([#647](https://github.com/opentdf/platform/issues/647)) ([019a3bf](https://github.com/opentdf/platform/commit/019a3bf37d534359950110f1b077ef4f860f1c60))


### Bug Fixes

* **config:** update docs for enforce dpop config and clean up markdown tables ([#697](https://github.com/opentdf/platform/issues/697)) ([983ce71](https://github.com/opentdf/platform/commit/983ce716055d3217a6e14046b66a94b9254f24fe))
* **policy:** normalize FQN lookup to lower case ([#668](https://github.com/opentdf/platform/issues/668)) ([cd8a875](https://github.com/opentdf/platform/commit/cd8a8750e2a87cb65bc6c8815d8db131dca4f02d)), closes [#669](https://github.com/opentdf/platform/issues/669)

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
