# Changelog

## [0.4.9](https://github.com/opentdf/platform/compare/service/v0.4.8...service/v0.4.9) (2024-07-03)


### Features

* **policy:** add support for key access grants returned ([#1077](https://github.com/opentdf/platform/issues/1077)) ([06050a5](https://github.com/opentdf/platform/commit/06050a5224527c6b248c1c6a840e44fdfbce826c))


### Bug Fixes

* **core:** Autobump service ([#1099](https://github.com/opentdf/platform/issues/1099)) ([d4e1aa2](https://github.com/opentdf/platform/commit/d4e1aa253bf7abcaaa8cc93463f66f030aace099))
* **policy:** unsafe service attribute update should allow empty names for PATCH-style API ([#1094](https://github.com/opentdf/platform/issues/1094)) ([3c56d0f](https://github.com/opentdf/platform/commit/3c56d0f4ebbda81bf6ca6924176885d93faed48b))

## [0.4.8](https://github.com/opentdf/platform/compare/service/v0.4.7...service/v0.4.8) (2024-07-02)


### Features

* **policy:** add index to fqn column in attribute_fqns table ([#1035](https://github.com/opentdf/platform/issues/1035)) ([1b0cf38](https://github.com/opentdf/platform/commit/1b0cf38542aee3d2b1c8ab9f77e3adab582415ad)), closes [#1053](https://github.com/opentdf/platform/issues/1053)
* **policy:** add unsafe attribute RPC db connectivity  ([#1022](https://github.com/opentdf/platform/issues/1022)) ([fbc02f3](https://github.com/opentdf/platform/commit/fbc02f34f3c3ae663b83944132f7dfd6897f6271))
* **policy:** attribute values unsafe actions db connectivity ([#1030](https://github.com/opentdf/platform/issues/1030)) ([4a30426](https://github.com/opentdf/platform/commit/4a3042625d0d08951bc36053ba053dc44fcffe99))
* **policy:** register unsafe service in platform ([#1066](https://github.com/opentdf/platform/issues/1066)) ([b7796cd](https://github.com/opentdf/platform/commit/b7796cdbe3b16903ac83033c8d99495aa10c8e2c))


### Bug Fixes

* **authz:** Return deny on GetDecision if resource attribute lookup returns not found ([#962](https://github.com/opentdf/platform/issues/962)) ([7dea640](https://github.com/opentdf/platform/commit/7dea6407322b5e625ee2810dfcf407c010d9996f))
* **core:** Autobump service ([#1072](https://github.com/opentdf/platform/issues/1072)) ([409df67](https://github.com/opentdf/platform/commit/409df678b481ce1fc1c542417cbe3ae67b96d565))
* **core:** Autobump service ([#1079](https://github.com/opentdf/platform/issues/1079)) ([10138d2](https://github.com/opentdf/platform/commit/10138d25afa210dc45838d66a888365d4da6960d))
* **core:** Autobump service ([#1084](https://github.com/opentdf/platform/issues/1084)) ([968883e](https://github.com/opentdf/platform/commit/968883ee6413d25476f41eff7a69b3b1201e1fa6))
* **core:** database clients pooling improvements ([#1047](https://github.com/opentdf/platform/issues/1047)) ([8193cec](https://github.com/opentdf/platform/commit/8193cec8c4d1be2b471fa606b6a24cc1644320e7))
* **core:** swap out internal issuer for external issuer endpoint ([#1027](https://github.com/opentdf/platform/issues/1027)) ([c3828d0](https://github.com/opentdf/platform/commit/c3828d088a3483b78079cd257b4237291cf7b6f0))
* **core:** update casbin policy to allow authorization service ([#1041](https://github.com/opentdf/platform/issues/1041)) ([552e970](https://github.com/opentdf/platform/commit/552e9703f99ea0ce8de083f504cbf85959483049))
* **policy:** provide ns and val fqns back on list attributes response ([#1050](https://github.com/opentdf/platform/issues/1050)) ([1be04f6](https://github.com/opentdf/platform/commit/1be04f6355cc753f8bc0ad98b7c6e7e5c3535c79)), closes [#1052](https://github.com/opentdf/platform/issues/1052)
* **policy:** rename unsafe rpcs for aligned casbin action determination ([#1067](https://github.com/opentdf/platform/issues/1067)) ([7861e4a](https://github.com/opentdf/platform/commit/7861e4a5092ee702565b6cd152fd592f3c19435f))
* **policy:** run migrations on db only once for all policy services ([#1040](https://github.com/opentdf/platform/issues/1040)) ([db4f06f](https://github.com/opentdf/platform/commit/db4f06fdb9314747d9a95a5a09f974d86a1f0f29))

## [0.4.7](https://github.com/opentdf/platform/compare/service/v0.4.6...service/v0.4.7) (2024-06-24)


### Features

* add dev_mode flag ([#985](https://github.com/opentdf/platform/issues/985)) ([8da2436](https://github.com/opentdf/platform/commit/8da2436312ceccc002a434752911c6119dae9bae))
* adds new trace log level ([#989](https://github.com/opentdf/platform/issues/989)) ([25f699e](https://github.com/opentdf/platform/commit/25f699e2c7d77ae2c9f83ee8e2c877c06bcf2b13))
* Audit GetDecisions ([#976](https://github.com/opentdf/platform/issues/976)) ([55bdfeb](https://github.com/opentdf/platform/commit/55bdfeb4dd4a846d244febd23825ced38e8e91b1))
* **authz:** Use flattened entity representations in subject mapping evaluation ([#1007](https://github.com/opentdf/platform/issues/1007)) ([b80443f](https://github.com/opentdf/platform/commit/b80443f1828382a12d0a1cdac30f27861e0c19d4))
* **core:** add doublestar for public routes ([#998](https://github.com/opentdf/platform/issues/998)) ([1c70c16](https://github.com/opentdf/platform/commit/1c70c16250485fc41062fd8641ad173c27fa6fc4))
* **core:** New cryptoProvider config ([#939](https://github.com/opentdf/platform/issues/939)) ([8150623](https://github.com/opentdf/platform/commit/81506237e2e640af34df8c745b71c3f20358d5a4))
* **policy:** add unsafe service protos and unsafe service proto Go gencode ([#1003](https://github.com/opentdf/platform/issues/1003)) ([55cc045](https://github.com/opentdf/platform/commit/55cc0459f8e5594765cecf62c3e2a1adff40a565))
* **policy:** policy unsafe namespace RPCs wired up to database ([#1018](https://github.com/opentdf/platform/issues/1018)) ([239d9fa](https://github.com/opentdf/platform/commit/239d9fa025814d0baa9f5c8e7f383604d0574e1d))
* **policy:** service stubs and registration for unsafe service ([#1009](https://github.com/opentdf/platform/issues/1009)) ([9145491](https://github.com/opentdf/platform/commit/9145491450236cb0bb640d0262db7b0605ad4e4c))


### Bug Fixes

* config loaded debug statement logs secrets ([#1010](https://github.com/opentdf/platform/issues/1010)) ([6f6a603](https://github.com/opentdf/platform/commit/6f6a603ae78ea948e6c93b1fba436a862e3f15af))
* **core:** Autobump service ([#1025](https://github.com/opentdf/platform/issues/1025)) ([588827c](https://github.com/opentdf/platform/commit/588827c6b4b7b1c0b8f39002eefd294357b5a206))
* **core:** Fixes issue failing to find keys for kid-free kaos ([#982](https://github.com/opentdf/platform/issues/982)) ([f27d484](https://github.com/opentdf/platform/commit/f27d48426762d684a9b6abe0c54820999b385329))
* **core:** policy resource-mappings fix doc drift in proto comments ([#980](https://github.com/opentdf/platform/issues/980)) ([09ab763](https://github.com/opentdf/platform/commit/09ab763263d092653bbded294895dcc08d03bdb2))
* **core:** Update to lib/fixtures 0.2.7 ([#1017](https://github.com/opentdf/platform/issues/1017)) ([dbae6ff](https://github.com/opentdf/platform/commit/dbae6ff10aadbfc805d9acef8440a7930f3c684e))
* **core:** Updates to protos 0.2.4 ([#1014](https://github.com/opentdf/platform/issues/1014)) ([43e11a3](https://github.com/opentdf/platform/commit/43e11a34c47c76fe2845d0a9d60a686ea394c131))
* **kas:** remove old logs ([#992](https://github.com/opentdf/platform/issues/992)) ([192ff6d](https://github.com/opentdf/platform/commit/192ff6d98b7ab6a59eebe7561def7a43ad049ac5))

## [0.4.6](https://github.com/opentdf/platform/compare/service/v0.4.5...service/v0.4.6) (2024-06-11)


### Features

* **core:** Rewrap and Policy CRUD Audit Events ([#889](https://github.com/opentdf/platform/issues/889)) ([d909a5e](https://github.com/opentdf/platform/commit/d909a5e49c2e87884651c56cd30b9331ed4044c7))


### Bug Fixes

* **core:** Autobump service ([#960](https://github.com/opentdf/platform/issues/960)) ([6b96fee](https://github.com/opentdf/platform/commit/6b96feef714e0e5bdfbdfe3ea9a56a36d4b50289))
* **core:** remove /health from casbin default policy ([#943](https://github.com/opentdf/platform/issues/943)) ([cb3d8df](https://github.com/opentdf/platform/commit/cb3d8df468e62d797e94c474f2900aff527edec0)), closes [#905](https://github.com/opentdf/platform/issues/905)
* **core:** remove public routes from casbin default policy ([#951](https://github.com/opentdf/platform/issues/951)) ([57c2a45](https://github.com/opentdf/platform/commit/57c2a4576060c0dcd87cfc6b170b8dd03c6501c8))
* **core:** Return 404 if public key not found ([#888](https://github.com/opentdf/platform/issues/888)) ([8b110f0](https://github.com/opentdf/platform/commit/8b110f0f608e82ad3a76c9d3bcd586beaaf20b1d))
* **sdk:** convert platform endpoint to grpc dial format ([#941](https://github.com/opentdf/platform/issues/941)) ([3a72a54](https://github.com/opentdf/platform/commit/3a72a54a31d35d31dfcc13ac6e716d68c9c909d1))

## [0.4.5](https://github.com/opentdf/platform/compare/service/v0.4.4...service/v0.4.5) (2024-06-04)


### Features

* **authz:** Subject mapping OPA builtin for condition evaluation and jq selection ([#568](https://github.com/opentdf/platform/issues/568)) ([5379611](https://github.com/opentdf/platform/commit/5379611f4ef498867e86be998e0f6b8d2c590bd3))
* **sdk:** leverage platform wellknown configuration endpoint ([#895](https://github.com/opentdf/platform/issues/895)) ([53b3f42](https://github.com/opentdf/platform/commit/53b3f4231501c6e6ea54ee002c7420436bb44000))
* **sdk:** Support for ECDSA policy binding on both KAS and SDK ([#877](https://github.com/opentdf/platform/issues/877)) ([7baf039](https://github.com/opentdf/platform/commit/7baf03928eb3d29f615359860f9217a69b51c1fe))


### Bug Fixes

* **core:** allow http /kas/v2/rewrap calls in casbin defaultPolicy ([#922](https://github.com/opentdf/platform/issues/922)) ([6414d86](https://github.com/opentdf/platform/commit/6414d868e49cba396e07d57f66838ad87672672b)), closes [#921](https://github.com/opentdf/platform/issues/921)
* **core:** Autobump service ([#920](https://github.com/opentdf/platform/issues/920)) ([a797c16](https://github.com/opentdf/platform/commit/a797c16b4c7398dd7d88f759009ac043d29f4820))
* **core:** Autobump service ([#935](https://github.com/opentdf/platform/issues/935)) ([ded6d60](https://github.com/opentdf/platform/commit/ded6d60e9d7a072ae0ad99efe7e6af3742d3c1c9))
* **core:** bump ocrypto to 0.1.5 ([#913](https://github.com/opentdf/platform/issues/913)) ([4244e06](https://github.com/opentdf/platform/commit/4244e06582f6afa283797172647aeb919bc1889c))
* **core:** Bumps lib/fixtures ([#932](https://github.com/opentdf/platform/issues/932)) ([18586f9](https://github.com/opentdf/platform/commit/18586f9c96421ac63ddc4bb904604cbb8bdbed8c))
* **core:** update default casbin auth policy ([#927](https://github.com/opentdf/platform/issues/927)) ([c354fdb](https://github.com/opentdf/platform/commit/c354fdb118af4e4a222f3c65fcbf5de581d08bee))
* **kas:** misleading hsm error message ([#899](https://github.com/opentdf/platform/issues/899)) ([65fdd4c](https://github.com/opentdf/platform/commit/65fdd4c9a2c91d3f741911da02bb5c14cee42cdc))

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
