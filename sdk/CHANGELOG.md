# Changelog

## [0.3.21](https://github.com/opentdf/platform/compare/sdk/v0.3.20...sdk/v0.3.21) (2024-11-15)


### Features

* **sdk:** add collections for nanotdf  ([#1695](https://github.com/opentdf/platform/issues/1695)) ([6497bf3](https://github.com/opentdf/platform/commit/6497bf3a7cee9b6900569bc6cc2c39b2f647fb52))


### Bug Fixes

* **core:** Autobump sdk ([#1766](https://github.com/opentdf/platform/issues/1766)) ([9ff9f61](https://github.com/opentdf/platform/commit/9ff9f615ff167c165e3150bf1b571d59e1924720))

## [0.3.20](https://github.com/opentdf/platform/compare/sdk/v0.3.19...sdk/v0.3.20) (2024-11-13)


### Features

* backend migration to connect-rpc ([#1733](https://github.com/opentdf/platform/issues/1733)) ([d10ba3c](https://github.com/opentdf/platform/commit/d10ba3cb22175a000ba5d156987c9f201749ae88))


### Bug Fixes

* **core:** Autobump sdk ([#1747](https://github.com/opentdf/platform/issues/1747)) ([fb50a43](https://github.com/opentdf/platform/commit/fb50a431cde8691c670c2bf457c0545c89f278f9))

## [0.3.19](https://github.com/opentdf/platform/compare/sdk/v0.3.18...sdk/v0.3.19) (2024-11-12)


### Bug Fixes

* update GetType to check the first 4 bytes ([#1736](https://github.com/opentdf/platform/issues/1736)) ([d6a1e6d](https://github.com/opentdf/platform/commit/d6a1e6d6bf60e970afe8fc26c483cfe2e340fdd4))

## [0.3.18](https://github.com/opentdf/platform/compare/sdk/v0.3.17...sdk/v0.3.18) (2024-11-06)


### Bug Fixes

* **core:** Autobump sdk ([#1725](https://github.com/opentdf/platform/issues/1725)) ([89e63de](https://github.com/opentdf/platform/commit/89e63dee36ff01c4ebb74f653f3c63b923464454))
* NanoTDF secure key from debug logging and iv conflict risk ([#1714](https://github.com/opentdf/platform/issues/1714)) ([7ba2e12](https://github.com/opentdf/platform/commit/7ba2e12d4ece7fb298f58adc38181e62cc2fc2ee))
* **sdk:** Error message improvements ([#1176](https://github.com/opentdf/platform/issues/1176)) ([0ef65d4](https://github.com/opentdf/platform/commit/0ef65d410a8e1bc8b82f52b6a4f0f469a2f7f4fe))
* **sdk:** Fix handling of kas rewrap errors ([#1696](https://github.com/opentdf/platform/issues/1696)) ([ce10f3f](https://github.com/opentdf/platform/commit/ce10f3f8a8d3cfc3abf4950c044da18a42e4107a))
* **sdk:** reset reader after checking if IsNanoTDF ([#1718](https://github.com/opentdf/platform/issues/1718)) ([f9d6f26](https://github.com/opentdf/platform/commit/f9d6f26f1a674366da3d1adfe414ed66480e710f)), closes [#1717](https://github.com/opentdf/platform/issues/1717)

## [0.3.17](https://github.com/opentdf/platform/compare/sdk/v0.3.16...sdk/v0.3.17) (2024-10-28)


### Bug Fixes

* **sdk:** option to disable assertion verification ([#1689](https://github.com/opentdf/platform/issues/1689)) ([5c08c47](https://github.com/opentdf/platform/commit/5c08c47d616e98a0dcd2eec4e30a6c04ae71526d))
* **sdk:** Stops including binding in assertion hashes ([#1681](https://github.com/opentdf/platform/issues/1681)) ([a4583b0](https://github.com/opentdf/platform/commit/a4583b07a15f73027a1a63c619338bf1bdbebe49))

## [0.3.16](https://github.com/opentdf/platform/compare/sdk/v0.3.15...sdk/v0.3.16) (2024-10-15)


### Features

* **sdk:** Expose error types for signature, assertion, and kas failures ([#1613](https://github.com/opentdf/platform/issues/1613)) ([2aab506](https://github.com/opentdf/platform/commit/2aab5062a7aef3a9c95f0bb2c9c031a08501f76d))

## [0.3.15](https://github.com/opentdf/platform/compare/sdk/v0.3.14...sdk/v0.3.15) (2024-10-15)


### Bug Fixes

* **core:** Autobump sdk ([#1637](https://github.com/opentdf/platform/issues/1637)) ([f42d5af](https://github.com/opentdf/platform/commit/f42d5af65738bff3497c16d63455457f6aab2728))

## [0.3.14](https://github.com/opentdf/platform/compare/sdk/v0.3.13...sdk/v0.3.14) (2024-10-08)


### Features

* **sdk:** Improve KAS key lookup and caching ([#1556](https://github.com/opentdf/platform/issues/1556)) ([fb6c47a](https://github.com/opentdf/platform/commit/fb6c47a95f2e91748436a76aeef46a81273bb10d))


### Bug Fixes

* **core:** Autobump sdk ([#1609](https://github.com/opentdf/platform/issues/1609)) ([d5e4292](https://github.com/opentdf/platform/commit/d5e4292a026cda0e0bfc667f267492f4024b0335))

## [0.3.13](https://github.com/opentdf/platform/compare/sdk/v0.3.12...sdk/v0.3.13) (2024-10-01)


### Features

* **sdk:** Add namesapce grants to key splitting ([#1512](https://github.com/opentdf/platform/issues/1512)) ([d9a07f8](https://github.com/opentdf/platform/commit/d9a07f84ab5686fe13af82435af3201042dd7228))


### Bug Fixes

* **ci:** Fix negative assertion test case false positive ([#1550](https://github.com/opentdf/platform/issues/1550)) ([ef40bdb](https://github.com/opentdf/platform/commit/ef40bdbc575638e29a6dfbe2890620ea252ee481))
* **core:** Add NanoTDF KID padding removal and update logging level ([#1466](https://github.com/opentdf/platform/issues/1466)) ([54de8f4](https://github.com/opentdf/platform/commit/54de8f4e0497e8c587eac06fb5418e9dc3b33e19)), closes [#1467](https://github.com/opentdf/platform/issues/1467)
* **core:** Autobump sdk ([#1513](https://github.com/opentdf/platform/issues/1513)) ([03fba13](https://github.com/opentdf/platform/commit/03fba13f3457584e910caf11eacf421fcafff355))
* **core:** Autobump sdk ([#1577](https://github.com/opentdf/platform/issues/1577)) ([df7466b](https://github.com/opentdf/platform/commit/df7466b2484a836c7e91ca9af59c678d28c38b56))
* **core:** only strip nano kids to the right ([#1475](https://github.com/opentdf/platform/issues/1475)) ([ae8d8a2](https://github.com/opentdf/platform/commit/ae8d8a27354e81b91b77ed5ab3d1710813c1f024))
* **core:** Store attribute specific grants to key cache ([#1507](https://github.com/opentdf/platform/issues/1507)) ([8bc0a98](https://github.com/opentdf/platform/commit/8bc0a982481e64d1ec44c13de0c1d1264a61ac70))
* **sdk:** DoS protection through TDF segment sizes ([#1536](https://github.com/opentdf/platform/issues/1536)) ([d506734](https://github.com/opentdf/platform/commit/d506734985eedd72532a280b7c83bc2d746488b3))
* **sdk:** Fix nanotdf ECC mode bitfield ([#1551](https://github.com/opentdf/platform/issues/1551)) ([58a76ad](https://github.com/opentdf/platform/commit/58a76ad5a4736f99df3b9e1dcbf4e06c6b830da1))
* **sdk:** Fix possible panic for `AttributeValueFQN.Prefix()` ([#1472](https://github.com/opentdf/platform/issues/1472)) ([144aeda](https://github.com/opentdf/platform/commit/144aeda9141123cbfad44271844df49d632744f2))
* **sdk:** Granter offline mode with namespaces and keycache ([#1542](https://github.com/opentdf/platform/issues/1542)) ([ecd41f4](https://github.com/opentdf/platform/commit/ecd41f43461ecce967d193b09f469621a4d6b484))

## [0.3.12](https://github.com/opentdf/platform/compare/sdk/v0.3.11...sdk/v0.3.12) (2024-08-23)


### Features

* **core:** KID in NanoTDF KAS ResourceLocator borrowed from Protocol ([#1222](https://github.com/opentdf/platform/issues/1222)) ([e5ee4ef](https://github.com/opentdf/platform/commit/e5ee4efe91bffd9e0310daccf7217d6a797a7cc9))

## [0.3.11](https://github.com/opentdf/platform/compare/sdk/v0.3.10...sdk/v0.3.11) (2024-08-22)


### Bug Fixes

* **sdk:** set kas key cache ttl to 5 minutes ([#1428](https://github.com/opentdf/platform/issues/1428)) ([a9f63a9](https://github.com/opentdf/platform/commit/a9f63a9d53e1477cb5be315f595806a73f0c084e))
* update to allow for using handling assertiongs ([#1431](https://github.com/opentdf/platform/issues/1431)) ([85d3167](https://github.com/opentdf/platform/commit/85d3167cc136a2d97a0f3f874d170f5cc3bc7369))

## [0.3.10](https://github.com/opentdf/platform/compare/sdk/v0.3.9...sdk/v0.3.10) (2024-08-21)


### Bug Fixes

* **sdk:** 🔒 During read, limits TDF Manifest to 10MB  ([#1385](https://github.com/opentdf/platform/issues/1385)) ([cfeebce](https://github.com/opentdf/platform/commit/cfeebcedcaf1660cc73beb05abee5fa4d1431300))
* **sdk:** let value grants override attr grants ([#1318](https://github.com/opentdf/platform/issues/1318)) ([77f1e11](https://github.com/opentdf/platform/commit/77f1e1140ffc134ce072ba2e79bd74426f8ee5f8))
* **sdk:** well-known warning logs and public client id error ([#1415](https://github.com/opentdf/platform/issues/1415)) ([e6e76bf](https://github.com/opentdf/platform/commit/e6e76bf24a2e587817582ccb113d9e78a92b4060)), closes [#1414](https://github.com/opentdf/platform/issues/1414)

## [0.3.9](https://github.com/opentdf/platform/compare/sdk/v0.3.8...sdk/v0.3.9) (2024-08-20)


### Features

* **sdk:** Load KAS keys from policy service ([#1346](https://github.com/opentdf/platform/issues/1346)) ([fe628a0](https://github.com/opentdf/platform/commit/fe628a013e41fb87585eb53a61988f822b40a71a))
* **sdk:** support oauth2 tokensource with option ([#1394](https://github.com/opentdf/platform/issues/1394)) ([2886c0f](https://github.com/opentdf/platform/commit/2886c0ffa3807bbc6a2d4e9f0da7991a49d227fd)), closes [#1307](https://github.com/opentdf/platform/issues/1307)


### Bug Fixes

* **core:** Autobump sdk ([#1402](https://github.com/opentdf/platform/issues/1402)) ([192e5e5](https://github.com/opentdf/platform/commit/192e5e5a5a2c8d4b5fec74b50a94f15abacc1db7))

## [0.3.8](https://github.com/opentdf/platform/compare/sdk/v0.3.7...sdk/v0.3.8) (2024-08-19)


### Features

* **sdk:** public client and other enhancements to well-known SDK functionality ([#1365](https://github.com/opentdf/platform/issues/1365)) ([3be50a4](https://github.com/opentdf/platform/commit/3be50a4ebf26680fad4ab46620cdfa82340a3da3))

## [0.3.7](https://github.com/opentdf/platform/compare/sdk/v0.3.6...sdk/v0.3.7) (2024-08-16)


### Bug Fixes

* **core:** Autobump sdk ([#1367](https://github.com/opentdf/platform/issues/1367)) ([689e719](https://github.com/opentdf/platform/commit/689e719d357e9626b4eb049fc530673decc163a8))
* **sdk:** align sdk with platform modes ([#1328](https://github.com/opentdf/platform/issues/1328)) ([88ca6f7](https://github.com/opentdf/platform/commit/88ca6f7458930b753756606b670a5c36bddf818c))

## [0.3.6](https://github.com/opentdf/platform/compare/sdk/v0.3.5...sdk/v0.3.6) (2024-08-13)


### Bug Fixes

* **core:** Autobump sdk ([#1336](https://github.com/opentdf/platform/issues/1336)) ([e55ac48](https://github.com/opentdf/platform/commit/e55ac484d64f81cb059268af58ceb3d9850da041))

## [0.3.5](https://github.com/opentdf/platform/compare/sdk/v0.3.4...sdk/v0.3.5) (2024-08-12)


### Features

* Adds IsValidTDF function - needs tests ([#1188](https://github.com/opentdf/platform/issues/1188)) ([4750195](https://github.com/opentdf/platform/commit/4750195f39e7771073d76b1a735bf1ac1bfe0668))
* **sdk:** add assertion to tdf3 ([#575](https://github.com/opentdf/platform/issues/575)) ([5bbce71](https://github.com/opentdf/platform/commit/5bbce7141ba2a6f168f7743f9c6d03a1e23d56e5))
* **sdk:** Allow for payload key retrieval. ([#1230](https://github.com/opentdf/platform/issues/1230)) ([c3423fc](https://github.com/opentdf/platform/commit/c3423fceb39d7a8f7a9a30d1bb817f264180b830))


### Bug Fixes

* **core:** Autobump sdk ([#1313](https://github.com/opentdf/platform/issues/1313)) ([0eda439](https://github.com/opentdf/platform/commit/0eda43951aa0530ddd1d078a6172ddbb15462579))
* **kas:** Regenerate protos and fix tests from info rpc removal ([#1291](https://github.com/opentdf/platform/issues/1291)) ([91a2fe6](https://github.com/opentdf/platform/commit/91a2fe65c63aa5ac6ca2f058dbc0c29ca2a26536))
* **sdk:** Allow hyphens in attr namespaces ([#1250](https://github.com/opentdf/platform/issues/1250)) ([a034bd5](https://github.com/opentdf/platform/commit/a034bd5f605f4aef94533312adcb7ab0fe9bbdd2))

## [0.3.4](https://github.com/opentdf/platform/compare/sdk/v0.3.3...sdk/v0.3.4) (2024-07-23)


### Bug Fixes

* policy binding fix ([#1198](https://github.com/opentdf/platform/issues/1198)) ([6bf8e74](https://github.com/opentdf/platform/commit/6bf8e747885c05ea6a23db707e778b16239abe0a))

## [0.3.3](https://github.com/opentdf/platform/compare/sdk/v0.3.2...sdk/v0.3.3) (2024-07-22)


### Bug Fixes

* fixed policy binding type ([#1184](https://github.com/opentdf/platform/issues/1184)) ([9800a32](https://github.com/opentdf/platform/commit/9800a32c8d9d83458403e2f87720f7882461fc32))
* **sdk:** Allow empty kas info list ([#1161](https://github.com/opentdf/platform/issues/1161)) ([dd6db8e](https://github.com/opentdf/platform/commit/dd6db8e370142be647aba12f00f466ea6d680297))
* **sdk:** Remove case sensitivity of attr values ([#1160](https://github.com/opentdf/platform/issues/1160)) ([21d73f6](https://github.com/opentdf/platform/commit/21d73f6b6af88ecdfeb17c1db3fbfbb88cde89b5))

## [0.3.2](https://github.com/opentdf/platform/compare/sdk/v0.3.1...sdk/v0.3.2) (2024-07-14)


### Bug Fixes

* **core:** Autobump sdk ([#1155](https://github.com/opentdf/platform/issues/1155)) ([9f5608c](https://github.com/opentdf/platform/commit/9f5608cc62938c58078a2916856fa6bf473aea32))

## [0.3.1](https://github.com/opentdf/platform/compare/sdk/v0.3.0...sdk/v0.3.1) (2024-07-12)


### Bug Fixes

* **core:** Fix autoconfigure with no attributes ([#1141](https://github.com/opentdf/platform/issues/1141)) ([76c2a95](https://github.com/opentdf/platform/commit/76c2a95ad7e0c9c57ebde6b101a908fc32fcd539))

## [0.3.0](https://github.com/opentdf/platform/compare/sdk/v0.2.11...sdk/v0.3.0) (2024-07-11)


### ⚠ BREAKING CHANGES

* **sdk:** Autoconfigure with grants ([#1051](https://github.com/opentdf/platform/issues/1051))

### Features

* **sdk:** Autoconfigure with grants ([#1051](https://github.com/opentdf/platform/issues/1051)) ([588b862](https://github.com/opentdf/platform/commit/588b862d9d258ccac2761e41edda04ea77270187))

## [0.2.11](https://github.com/opentdf/platform/compare/sdk/v0.2.10...sdk/v0.2.11) (2024-07-11)


### Features

* **sdk:** Support custom key splits ([#1038](https://github.com/opentdf/platform/issues/1038)) ([685d8b5](https://github.com/opentdf/platform/commit/685d8b5d7b609744eb6623c52efb27cb40fbc36c))


### Bug Fixes

* **core:** Autobump sdk ([#1132](https://github.com/opentdf/platform/issues/1132)) ([da9145c](https://github.com/opentdf/platform/commit/da9145cce0738293281f6fba84d81dc221fc4e6f))

## [0.2.10](https://github.com/opentdf/platform/compare/sdk/v0.2.9...sdk/v0.2.10) (2024-07-09)


### Bug Fixes

* **core:** Autobump sdk ([#1083](https://github.com/opentdf/platform/issues/1083)) ([604fc2b](https://github.com/opentdf/platform/commit/604fc2b769768498bf4187381e14d0bb8e4bafbd))
* **core:** Autobump sdk ([#1098](https://github.com/opentdf/platform/issues/1098)) ([c7cafed](https://github.com/opentdf/platform/commit/c7cafedf89823facb5c7dc096995a457a2829cd2))
* **core:** Autobump sdk ([#1115](https://github.com/opentdf/platform/issues/1115)) ([04ad338](https://github.com/opentdf/platform/commit/04ad3385a4d91af0a7d4b8e31ec4a0e7142c9415))

## [0.2.9](https://github.com/opentdf/platform/compare/sdk/v0.2.8...sdk/v0.2.9) (2024-07-02)


### Features

* **sdk:** support unsafe policy service in SDK ([#1076](https://github.com/opentdf/platform/issues/1076)) ([ca88554](https://github.com/opentdf/platform/commit/ca88554098c6330c3bd5d0c72386b8036fd32434))


### Bug Fixes

* **core:** Autobump sdk ([#1070](https://github.com/opentdf/platform/issues/1070)) ([4ca372c](https://github.com/opentdf/platform/commit/4ca372c71eb2460a0b3d5791119a9a42a91aa1ee))
* Issue [#1008](https://github.com/opentdf/platform/issues/1008) : Use exchange info's TLS Configuration for cert based auth ([#1043](https://github.com/opentdf/platform/issues/1043)) ([93d8f70](https://github.com/opentdf/platform/commit/93d8f70750d181e0818911e5b317c9d85044623b))

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
