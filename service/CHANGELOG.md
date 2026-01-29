# Changelog

## [0.12.0](https://github.com/opentdf/platform/compare/service/v0.11.0...service/v0.12.0) (2026-01-27)


### ⚠ BREAKING CHANGES

* remove nanotdf support ([#3013](https://github.com/opentdf/platform/issues/3013))
* **core:** DSPX-2090 Removes unnamed key mgrs ([#2952](https://github.com/opentdf/platform/issues/2952))

### Features

* **core:** Actually use KeyManager ProviderConfig ([#2837](https://github.com/opentdf/platform/issues/2837)) ([65ba2e0](https://github.com/opentdf/platform/commit/65ba2e002e30ac6624982e15c995dbd228a93541))
* **core:** add additive CORS configuration fields ([#2941](https://github.com/opentdf/platform/issues/2941)) ([d45a34b](https://github.com/opentdf/platform/commit/d45a34b614eceab97a92b615578e92af8a8fc551))
* **core:** add direct entitlement support ([#2630](https://github.com/opentdf/platform/issues/2630)) ([cc8337a](https://github.com/opentdf/platform/commit/cc8337a4d4b6be4cb1f4117711109c2d8d599cb9))
* **deps:** Bump ocrypto to v0.9.0 ([#3024](https://github.com/opentdf/platform/issues/3024)) ([cd79950](https://github.com/opentdf/platform/commit/cd799509b15516f840436e6af20a14eebaa0556d))
* **kas:** add configurable SRT skew tolerance and diagnostics ([#2886](https://github.com/opentdf/platform/issues/2886)) ([1a57227](https://github.com/opentdf/platform/commit/1a57227f6c4d9a02aecf68ca1b1b88bd265e49e0))
* **kas:** Add nano policy binding to rewrap audit. ([#2870](https://github.com/opentdf/platform/issues/2870)) ([a12d1d4](https://github.com/opentdf/platform/commit/a12d1d4a69533cac9ac5581964c3053855584eb9))
* **policy:** add allow_traversal to attribute definitions ([#3014](https://github.com/opentdf/platform/issues/3014)) ([bbbe21b](https://github.com/opentdf/platform/commit/bbbe21bb671f5ffedd116a08ff15779ce7034fcb))
* **policy:** Create/Update scs to use transaction. ([#2882](https://github.com/opentdf/platform/issues/2882)) ([7493941](https://github.com/opentdf/platform/commit/74939411fc6f87aa3314873cfe5b1eb42e6f3d51))
* **policy:** Return definition when attr value is missing ([#3012](https://github.com/opentdf/platform/issues/3012)) ([3967377](https://github.com/opentdf/platform/commit/3967377728cfc9dc8922d9327cf13bab5de2c38b))
* Update Go toolchain version to 1.24.11 across all modules ([#2943](https://github.com/opentdf/platform/issues/2943)) ([a960eca](https://github.com/opentdf/platform/commit/a960eca78ab8870599f0aa2a315dbada355adf20))


### Bug Fixes

* **authz:** deny resources granularly when attribute value FQNs not found ([#2896](https://github.com/opentdf/platform/issues/2896)) ([802db02](https://github.com/opentdf/platform/commit/802db02f7542d7b24d61448a84f3a8b0aa38a09a))
* **authz:** handle individual resource edge cases in decisions ([#2835](https://github.com/opentdf/platform/issues/2835)) ([fad4437](https://github.com/opentdf/platform/commit/fad443714c28f190cde723e5307451f481befd12))
* **authz:** if entity identifier results in multiple representations, treat with AND in resource decision results ([#2860](https://github.com/opentdf/platform/issues/2860)) ([e869b35](https://github.com/opentdf/platform/commit/e869b35024bc2c752dfb89e9e7ad8a82608d8398))
* **authz:** obligations should be logged to audit but not returned when not entitled ([#2847](https://github.com/opentdf/platform/issues/2847)) ([35da5e3](https://github.com/opentdf/platform/commit/35da5e3170780534b09f84308dc59d8af87224f9))
* Connect RPC v1.19.1  ([#3009](https://github.com/opentdf/platform/issues/3009)) ([c354fd3](https://github.com/opentdf/platform/commit/c354fd387f2e17f764feacf302488d9afdbac5f0))
* **core:** add obligations X-Rewrap-Additional-Context to default CORS allowed headers ([#2901](https://github.com/opentdf/platform/issues/2901)) ([d86868d](https://github.com/opentdf/platform/commit/d86868d6edb9d87e7c22c552e07dd218db98bc8d))
* **core:** Add stderr log output option ([#2989](https://github.com/opentdf/platform/issues/2989)) ([7e01b2b](https://github.com/opentdf/platform/commit/7e01b2bae63627e13859cf5ec901561fdbc201b8))
* **core:** DSPX-1944 Fix service negation for extra services ([#2905](https://github.com/opentdf/platform/issues/2905)) ([b07a4fe](https://github.com/opentdf/platform/commit/b07a4fe8de9085b72dc7c9569e71298be849b23e))
* **core:** DSPX-2090 Removes unnamed key mgrs ([#2952](https://github.com/opentdf/platform/issues/2952)) ([ddd98db](https://github.com/opentdf/platform/commit/ddd98dbd6499c949f0a5ae4da42f50137ad5528b))
* **core:** Let default basic keymanager work again ([#2858](https://github.com/opentdf/platform/issues/2858)) ([fb0b99d](https://github.com/opentdf/platform/commit/fb0b99dc6b4fd0cc5c243de474a683672df77b78))
* **core:** remove duplicate root-level trace configuration ([#2944](https://github.com/opentdf/platform/issues/2944)) ([d323e85](https://github.com/opentdf/platform/commit/d323e856ec7cdb83d00fb29070ef105a457c5f1f))
* **core:** Support audit and warn log levels ([#2996](https://github.com/opentdf/platform/issues/2996)) ([e789a64](https://github.com/opentdf/platform/commit/e789a64d52792bead961b8ec918f620e7c7c96ce))
* **core:** Updates audit events when cancelled ([#2954](https://github.com/opentdf/platform/issues/2954)) ([808457e](https://github.com/opentdf/platform/commit/808457e8c8945cfe9d0318a19f7217a97874dfcb))
* **deps:** bump github.com/opentdf/platform/lib/fixtures from 0.3.0 to 0.4.0 in /service ([#2964](https://github.com/opentdf/platform/issues/2964)) ([58512e2](https://github.com/opentdf/platform/commit/58512e23b4d51e1525516ba5c4a1d267b0a34551))
* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.7.0 to 0.8.0 in /service ([#2976](https://github.com/opentdf/platform/issues/2976)) ([be970db](https://github.com/opentdf/platform/commit/be970db2cdd2c1c732e4d9ae3370b22aaf185b0d))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.13.0 to 0.14.0 in /service ([#2965](https://github.com/opentdf/platform/issues/2965)) ([6672550](https://github.com/opentdf/platform/commit/66725508ac9d611f38a68eec4bef2888cedf9437))
* **deps:** bump the external group across 1 directory with 5 updates ([#2950](https://github.com/opentdf/platform/issues/2950)) ([6dc3bca](https://github.com/opentdf/platform/commit/6dc3bca01facc22a51293292c337963feabdf417))
* **deps:** bump toolchain to go1.24.9 for CVEs found by govulncheck ([#2849](https://github.com/opentdf/platform/issues/2849)) ([23f76c0](https://github.com/opentdf/platform/commit/23f76c034cfb4c325d868eb96c95ba616e362db4))
* **ers:** Do not use auth header jwt in MultiStrategy ERS ([#2862](https://github.com/opentdf/platform/issues/2862)) ([dd6256e](https://github.com/opentdf/platform/commit/dd6256ea89ceee83c3da85cda5e258031c43a0ed))
* **kas:** Do not log index object ([#2910](https://github.com/opentdf/platform/issues/2910)) ([4f9b8b9](https://github.com/opentdf/platform/commit/4f9b8b9cff189d59583033e6451ff63557038e67))
* **kas:** document rewrap proto fields used in bulk flow ([#2826](https://github.com/opentdf/platform/issues/2826)) ([32a7e91](https://github.com/opentdf/platform/commit/32a7e919c57fd724f5c4f01148861ebccb1a9989))
* **kas:** Ensure root key is not logged. ([#2918](https://github.com/opentdf/platform/issues/2918)) ([de9a76e](https://github.com/opentdf/platform/commit/de9a76e403377816949365c7ac52e08a1e10ee40))
* **kas:** Fix kas panics on bad requests ([#2916](https://github.com/opentdf/platform/issues/2916)) ([182b463](https://github.com/opentdf/platform/commit/182b4635c6a96881361ad65a9f9aa478c08cfe57))
* **kas:** populate rewrap audit log ([#2861](https://github.com/opentdf/platform/issues/2861)) ([4fe97fd](https://github.com/opentdf/platform/commit/4fe97fd1ca6c05fb488833efb1397ab64ea0cfdf))
* **policy:** ListKeys 404 on missing KAS ([#3001](https://github.com/opentdf/platform/issues/3001)) ([65a228b](https://github.com/opentdf/platform/commit/65a228b9222a812e8d9ab689875ebbb25ccc15d4))
* **policy:** Return the correct total during list responses. ([#2836](https://github.com/opentdf/platform/issues/2836)) ([5c1ec9c](https://github.com/opentdf/platform/commit/5c1ec9c088e714e7a7f6f678cded31e4942b0a83))
* **policy:** wrap SQL optional param type casts in null checks ([#2977](https://github.com/opentdf/platform/issues/2977)) ([4f6825e](https://github.com/opentdf/platform/commit/4f6825e3370f0617f443659ddeec8b1b0f751b15))
* remove lingering kas info endpoint definition ([#2997](https://github.com/opentdf/platform/issues/2997)) ([b7e7a66](https://github.com/opentdf/platform/commit/b7e7a66d8a88847ce5c853685b53b03696b719b8))
* remove nanotdf support ([#3013](https://github.com/opentdf/platform/issues/3013)) ([90ff7ce](https://github.com/opentdf/platform/commit/90ff7ce50754a1f37ba1cc530507c1f6e15930a0))

## [0.11.0](https://github.com/opentdf/platform/compare/service/v0.10.0...service/v0.11.0) (2025-10-22)


### Features

* **authz:** add obligation fulfillment logic to obligation PDP ([#2740](https://github.com/opentdf/platform/issues/2740)) ([2f8d30d](https://github.com/opentdf/platform/commit/2f8d30d2c3de584b3603678fedec2fac9eb34d70))
* **authz:** audit logs should properly handle obligations ([#2824](https://github.com/opentdf/platform/issues/2824)) ([874ec7b](https://github.com/opentdf/platform/commit/874ec7bd0cc6d8336d98d1a18e80ade1c3461db6))
* **authz:** defer to request auth as decision/entitlements entity ([#2789](https://github.com/opentdf/platform/issues/2789)) ([feb34d8](https://github.com/opentdf/platform/commit/feb34d85a3cd9324a95cc7a2fac92a2e658170fe))
* **authz:** obligations protos within auth service ([#2745](https://github.com/opentdf/platform/issues/2745)) ([41ee5a8](https://github.com/opentdf/platform/commit/41ee5a8c0caaa99d5b80d6ebb23696d13053938f))
* **authz:** protovalidate tests for new authz obligations fields ([#2747](https://github.com/opentdf/platform/issues/2747)) ([73e6319](https://github.com/opentdf/platform/commit/73e63197ceceb88b66b9faa9b0ed076b4cc8db53))
* **authz:** service logic to use request auth as entity identifier in PDP decisions/entitlements ([#2790](https://github.com/opentdf/platform/issues/2790)) ([6784e88](https://github.com/opentdf/platform/commit/6784e8813188f1db3af471c21be7ce87a6e86cdb))
* **authz:** wire up obligations enforcement in auth service ([#2756](https://github.com/opentdf/platform/issues/2756)) ([11b3ea9](https://github.com/opentdf/platform/commit/11b3ea9460e1e73824cd421c91d67de26a1bfa57))
* **core:** propagate token clientID on configured claim via interceptor into shared context metadata ([#2760](https://github.com/opentdf/platform/issues/2760)) ([0f77246](https://github.com/opentdf/platform/commit/0f772464dfd9209ef465da3ee3df5521ed660acf))
* **kas:** Add required obligations to kao metadata.: ([#2806](https://github.com/opentdf/platform/issues/2806)) ([16fb26c](https://github.com/opentdf/platform/commit/16fb26c63d27cce8eba34674c5294c400f972546))
* **policy:** add FQNs to obligation defs + vals ([#2749](https://github.com/opentdf/platform/issues/2749)) ([fa2585c](https://github.com/opentdf/platform/commit/fa2585c183c94fe004b5b5d767c2140dd028cf41))
* **policy:** Add obligation support to KAS ([#2786](https://github.com/opentdf/platform/issues/2786)) ([bb1bca0](https://github.com/opentdf/platform/commit/bb1bca0b3dc472161a1322595e869df0e1353ee8))
* **policy:** List obligation triggers rpc ([#2823](https://github.com/opentdf/platform/issues/2823)) ([206abe3](https://github.com/opentdf/platform/commit/206abe3ed266ac9533fcc4de504a5056e5856a56))
* **policy:** namespace root certificates ([#2771](https://github.com/opentdf/platform/issues/2771)) ([beaff21](https://github.com/opentdf/platform/commit/beaff21de6c7fa90d7892fa6cff346f7c697d308))
* **policy:** Proto - root certificates by namespace ([#2800](https://github.com/opentdf/platform/issues/2800)) ([0edb359](https://github.com/opentdf/platform/commit/0edb3591bc0c12b3ffb47b4e43d19b56dae3d016))
* **policy:** Protos List obligation triggers ([#2803](https://github.com/opentdf/platform/issues/2803)) ([b32df81](https://github.com/opentdf/platform/commit/b32df81f6fe35f9db07e58f49ca71b43d7a02a13))
* **policy:** Return built obligations fqns with triggers. ([#2830](https://github.com/opentdf/platform/issues/2830)) ([e843018](https://github.com/opentdf/platform/commit/e8430184089cfb513878dbbadc532117e47d14cf))
* **policy:** Return obligations from GetAttributeValue calls ([#2742](https://github.com/opentdf/platform/issues/2742)) ([aa9b393](https://github.com/opentdf/platform/commit/aa9b393ac27522a3db69131a48409d8f297ebe56))


### Bug Fixes

* **core:** CORS ([#2787](https://github.com/opentdf/platform/issues/2787)) ([a030ac6](https://github.com/opentdf/platform/commit/a030ac6e7a1db1903c2eb32756bd5c476323baff))
* **core:** deprecate policy WithValue selector not utilized by RPC ([#2794](https://github.com/opentdf/platform/issues/2794)) ([c573595](https://github.com/opentdf/platform/commit/c573595aba6c0e5223fc7fd924840c1bf34cd895))
* **core:** deprecated stale protos and add better upgrade comments ([#2793](https://github.com/opentdf/platform/issues/2793)) ([f2678cc](https://github.com/opentdf/platform/commit/f2678cc6929824ae3d73d2c808ce8412086011ee))
* **core:** Don't require known manager names ([#2792](https://github.com/opentdf/platform/issues/2792)) ([8a56a96](https://github.com/opentdf/platform/commit/8a56a965b934b85ba1a7530a249184e96967cde1))
* **core:** Fix mode negation and core mode ([#2779](https://github.com/opentdf/platform/issues/2779)) ([de9807d](https://github.com/opentdf/platform/commit/de9807df7ce9ff4c2efb46cf3486261cff8470ab))
* **core:** resolve environment loading issues ([#2827](https://github.com/opentdf/platform/issues/2827)) ([9af3184](https://github.com/opentdf/platform/commit/9af31842f8a0e36993cada6732d03b3447c62d21))
* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.6.0 to 0.7.0 in /service ([#2812](https://github.com/opentdf/platform/issues/2812)) ([a6d180d](https://github.com/opentdf/platform/commit/a6d180d8999c34954581ae9e360cb3fa84e1789e))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.12.0 to 0.13.0 in /service ([#2814](https://github.com/opentdf/platform/issues/2814)) ([5e9c695](https://github.com/opentdf/platform/commit/5e9c6952a8c9ba453f93293a474e22f17679098d))
* **deps:** bump github.com/opentdf/platform/sdk from 0.7.0 to 0.9.0 in /service ([#2798](https://github.com/opentdf/platform/issues/2798)) ([d6bc9a8](https://github.com/opentdf/platform/commit/d6bc9a81eb450135e5b95629cf509fdbb4e4c641))
* **deps:** bump github.com/opentdf/platform/sdk from 0.9.0 to 0.10.0 in /service ([#2831](https://github.com/opentdf/platform/issues/2831)) ([412dfd1](https://github.com/opentdf/platform/commit/412dfd12b936d12df501b9e71c8beadb5ee9496a))
* ECC key loading (deprecated) ([#2757](https://github.com/opentdf/platform/issues/2757)) ([49990eb](https://github.com/opentdf/platform/commit/49990eb5f7c9c0b35f1be3319f73992429d65a18))
* **policy:** Change to nil ([#2746](https://github.com/opentdf/platform/issues/2746)) ([a449434](https://github.com/opentdf/platform/commit/a44943426e4ffcfb36ee2253c6554689ffa4a76f))

## [0.10.0](https://github.com/opentdf/platform/compare/service/v0.9.0...service/v0.10.0) (2025-09-17)


### ⚠ BREAKING CHANGES

* **policy:** Add manager column to provider configuration for  multi-instance support ([#2601](https://github.com/opentdf/platform/issues/2601))

### Features

* **authz:** add obligation policy decision point ([#2706](https://github.com/opentdf/platform/issues/2706)) ([bb2a4f8](https://github.com/opentdf/platform/commit/bb2a4f89f4cc0c483ac7f60b4e24bf88cac10c7e))
* **core:** add service negation for op mode ([#2680](https://github.com/opentdf/platform/issues/2680)) ([029db8c](https://github.com/opentdf/platform/commit/029db8c10af1cb8f50c2bb925d08ca0f5ddf7916))
* **core:** Bump default write timeout. ([#2671](https://github.com/opentdf/platform/issues/2671)) ([6a233c1](https://github.com/opentdf/platform/commit/6a233c1f16c1a7ea3b059906eb0a489e06544134))
* **core:** Encapsulate&gt;Encrypt ([#2676](https://github.com/opentdf/platform/issues/2676)) ([3c5a614](https://github.com/opentdf/platform/commit/3c5a6145c9bcac47001639bdcf2576a444493dd5))
* **core:** Lets key manager factory take context ([#2715](https://github.com/opentdf/platform/issues/2715)) ([8d70993](https://github.com/opentdf/platform/commit/8d7099361c76d94682a91d86ec5ace7cce816cfa))
* **policy:** add FQN of obligation definitions/values to protos ([#2703](https://github.com/opentdf/platform/issues/2703)) ([45ded0e](https://github.com/opentdf/platform/commit/45ded0e2717cca7ca8465e642c05e02ca4acd6c5))
* **policy:** Add manager column to provider configuration for  multi-instance support ([#2601](https://github.com/opentdf/platform/issues/2601)) ([a5fc994](https://github.com/opentdf/platform/commit/a5fc994acc5491bf8cbf751b675302b459e1f3b0))
* **policy:** Add obligation triggers ([#2675](https://github.com/opentdf/platform/issues/2675)) ([22d0837](https://github.com/opentdf/platform/commit/22d08378c06eef1ec5d59250d3e22f81d230c49d))
* **policy:** add protovalidate for obligation defs + vals ([#2699](https://github.com/opentdf/platform/issues/2699)) ([af5c049](https://github.com/opentdf/platform/commit/af5c049435355646b7b59fd3a4b0191875a4b88d))
* **policy:** Allow creation and update of triggers on Obligation Values ([#2691](https://github.com/opentdf/platform/issues/2691)) ([b1e7ba1](https://github.com/opentdf/platform/commit/b1e7ba14a34c719d711db45cc9401c332c1175a5))
* **policy:** Allow for additional context to be added to obligation triggers ([#2705](https://github.com/opentdf/platform/issues/2705)) ([7025599](https://github.com/opentdf/platform/commit/7025599b30e76bb5b546f5d68f5fee9405f8a0b5))
* **policy:** Include Triggers in GET/LISTable reqs ([#2704](https://github.com/opentdf/platform/issues/2704)) ([b4381d1](https://github.com/opentdf/platform/commit/b4381d1f6f9777ad9041196548d52bc6f769e779))
* **policy:** obligations + values CRUD ([#2545](https://github.com/opentdf/platform/issues/2545)) ([c194e35](https://github.com/opentdf/platform/commit/c194e3522b9dfab74a5a21747d012f88a188f989))
* use public AES protected key from lib/ocrypto ([#2600](https://github.com/opentdf/platform/issues/2600)) ([75d7590](https://github.com/opentdf/platform/commit/75d7590ec062f822045027d4eb0b59a48bdea465))


### Bug Fixes

* **core:** remove extraneous comment ([#2741](https://github.com/opentdf/platform/issues/2741)) ([ada8da6](https://github.com/opentdf/platform/commit/ada8da664012ef82708214108efe9ad722e32faa))
* **core:** return services in the order they were registered ([#2733](https://github.com/opentdf/platform/issues/2733)) ([1d661db](https://github.com/opentdf/platform/commit/1d661dbc15cb14f335c3d1a93b379686da7c700d))
* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.3.0 to 0.6.0 in /service ([#2714](https://github.com/opentdf/platform/issues/2714)) ([00354b3](https://github.com/opentdf/platform/commit/00354b3b37ea181fb007a9df390462989ef44b9c))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.7.0 to 0.9.0 in /service ([#2726](https://github.com/opentdf/platform/issues/2726)) ([9004368](https://github.com/opentdf/platform/commit/900436848bda92b7af735893e192e9ac5b343399))
* **deps:** bump protocol/go to 0.10.0 in service ([#2734](https://github.com/opentdf/platform/issues/2734)) ([11e6201](https://github.com/opentdf/platform/commit/11e62012d1895fd148fe4bfcb2bd2e5132d5be1b))
* **deps:** update protovalidate to v0.14.2 to use new buf validate MessageOneofRule ([#2698](https://github.com/opentdf/platform/issues/2698)) ([1cae18e](https://github.com/opentdf/platform/commit/1cae18e6b6f4a72869b0cdb65d775e108da07872))
* **policy:** Registered Resources should consider actions correctly within Decision Requests ([#2681](https://github.com/opentdf/platform/issues/2681)) ([cf264a2](https://github.com/opentdf/platform/commit/cf264a2701aa529a188548c5288f55ae3c95d338))
* sanitize db schema identifiers ([#2682](https://github.com/opentdf/platform/issues/2682)) ([0d3dd94](https://github.com/opentdf/platform/commit/0d3dd945078fd3b9696a3ab258d8e35c0f272345))

## [0.9.0](https://github.com/opentdf/platform/compare/service/v0.8.0...service/v0.9.0) (2025-08-27)


### Features

* **core:** add multi-strategy ERS to support ldap and sql ([#2596](https://github.com/opentdf/platform/issues/2596)) ([855611d](https://github.com/opentdf/platform/commit/855611d58c36767e04dfa6efabb26e1bd2978fba))
* **policy:** Add legacy keys. ([#2613](https://github.com/opentdf/platform/issues/2613)) ([57370b0](https://github.com/opentdf/platform/commit/57370b0f76605ec2ed375728ec9b60a829072d99))
* **policy:** add values to CreateObligationRequest ([#2614](https://github.com/opentdf/platform/issues/2614)) ([94535cc](https://github.com/opentdf/platform/commit/94535cc0c1622b7499dad8e91a02a93f1eb1531b))
* **policy:** Modify KAS indexer to support legacy keys. ([#2616](https://github.com/opentdf/platform/issues/2616)) ([ba96c18](https://github.com/opentdf/platform/commit/ba96c186330bce0b86cb3a3f275bb2863e532654))


### Bug Fixes

* **deps:** bump github.com/docker/docker from 28.2.2+incompatible to 28.3.3+incompatible in /service ([#2598](https://github.com/opentdf/platform/issues/2598)) ([3c392aa](https://github.com/opentdf/platform/commit/3c392aae4f52ed4f51e68738ee424e56fee23e6b))
* **deps:** bump github.com/go-viper/mapstructure/v2 from 2.3.0 to 2.4.0 in /service ([#2649](https://github.com/opentdf/platform/issues/2649)) ([b838bbc](https://github.com/opentdf/platform/commit/b838bbcf8170c1d69e01617e75d8f08c3c38a339))
* **deps:** bump github.com/opentdf/platform/sdk from 0.5.0 to 0.7.0 in /service ([#2660](https://github.com/opentdf/platform/issues/2660)) ([2c998ac](https://github.com/opentdf/platform/commit/2c998acc00d95ffbf99a016faf4094ad26601ff7))
* **kas:** Allow admin to set registered kas uri ([#2624](https://github.com/opentdf/platform/issues/2624)) ([6203fba](https://github.com/opentdf/platform/commit/6203fbaebcdd57b5b3437679465149f8ff395484))
* updated generated sqlc ([#2609](https://github.com/opentdf/platform/issues/2609)) ([e44a569](https://github.com/opentdf/platform/commit/e44a56937453ebbdac1761f042003aa622e3a239))

## [0.8.0](https://github.com/opentdf/platform/compare/service/v0.7.0...service/v0.8.0) (2025-07-29)


### Features

* **authz:** RR GetDecision improvements ([#2479](https://github.com/opentdf/platform/issues/2479)) ([443cedb](https://github.com/opentdf/platform/commit/443cedba49691e2ef5c2ea6824c0150feff8f056))
* **authz:** sensible request limit upper bounds ([#2526](https://github.com/opentdf/platform/issues/2526)) ([b3093cc](https://github.com/opentdf/platform/commit/b3093cce2ffd1f1cdaec884967dc96a40caa2903))
* **core:** Add the ability to configure the http server settings ([#2522](https://github.com/opentdf/platform/issues/2522)) ([b1472df](https://github.com/opentdf/platform/commit/b1472df8722768f2d00113481458e6eaa4c1247e))
* **policy:** Add list key mappings rpc. ([#2533](https://github.com/opentdf/platform/issues/2533)) ([fbc2724](https://github.com/opentdf/platform/commit/fbc2724a066b5e4121838a958cb926a1ab5bdcde))
* **policy:** add obligation protos ([#2579](https://github.com/opentdf/platform/issues/2579)) ([50882e1](https://github.com/opentdf/platform/commit/50882e10abff64e14548e0c51851a4b671ef8b11))
* **policy:** add obligation tables ([#2532](https://github.com/opentdf/platform/issues/2532)) ([c7d7aa4](https://github.com/opentdf/platform/commit/c7d7aa4fd33397fe0c38abea1e89a21e1603f7e5))
* **policy:** Add validation to delete keys ([#2576](https://github.com/opentdf/platform/issues/2576)) ([cc169d9](https://github.com/opentdf/platform/commit/cc169d969f0e3380a2341033bc53a1a0eece781a))
* **policy:** Allow the deletion of a key. ([#2575](https://github.com/opentdf/platform/issues/2575)) ([82b96f0](https://github.com/opentdf/platform/commit/82b96f023662c0a6c76af6d1196f78ab28a6acf0))
* **policy:** Change return type for delete key proto. ([#2566](https://github.com/opentdf/platform/issues/2566)) ([c1ae924](https://github.com/opentdf/platform/commit/c1ae924d55ec0d13fd79917f960dede66cef7705))
* **policy:** sqlc queries refactor ([#2541](https://github.com/opentdf/platform/issues/2541)) ([e34680e](https://github.com/opentdf/platform/commit/e34680e3d3eeae5534a0ce1624a9e4386b100af1))


### Bug Fixes

* add back grants to listAttributesByDefOrValueFqns ([#2493](https://github.com/opentdf/platform/issues/2493)) ([2b47095](https://github.com/opentdf/platform/commit/2b47095a3f577063d48b67adac50a9fa59b8ace3))
* **authz:** access pdp should use proto getter ([#2530](https://github.com/opentdf/platform/issues/2530)) ([f856212](https://github.com/opentdf/platform/commit/f85621280954f05701dba83a6a4cff729d21b029))
* **core:** Allow 521 curve to be used ([#2485](https://github.com/opentdf/platform/issues/2485)) ([aaf43dc](https://github.com/opentdf/platform/commit/aaf43dc368b4cabbc9affa0a6075abd335aa57e3))
* **core:** resolve 'built-in' typos ([#2548](https://github.com/opentdf/platform/issues/2548)) ([ccdfa96](https://github.com/opentdf/platform/commit/ccdfa9648786027be187f237daf2aa083109789a))
* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.2.0 to 0.3.0 in /service ([#2504](https://github.com/opentdf/platform/issues/2504)) ([a9cc4dd](https://github.com/opentdf/platform/commit/a9cc4dd7db0fbb688d4000468cc2892b260609d2))
* **sdk:** Prefer KID and Algorithm selection from key maps ([#2475](https://github.com/opentdf/platform/issues/2475)) ([98fd392](https://github.com/opentdf/platform/commit/98fd39230a3cc4bfa5ff5ffc1742dd5d15eaeb1c))

## [0.7.0](https://github.com/opentdf/platform/compare/service/v0.6.0...service/v0.7.0) (2025-06-24)


### ⚠ BREAKING CHANGES

* **policy:** disable kas grants in favor of key mappings ([#2220](https://github.com/opentdf/platform/issues/2220))

### Features

* **authz:** Add caching to keycloak ERS ([#2466](https://github.com/opentdf/platform/issues/2466)) ([f5b0a06](https://github.com/opentdf/platform/commit/f5b0a06496ca322dfbf6a8dc613de748fe34d5bb))
* **authz:** auth svc registered resource GetDecision support ([#2392](https://github.com/opentdf/platform/issues/2392)) ([5405674](https://github.com/opentdf/platform/commit/5405674a832baaad7f1f2fc9d479267d8958bc0b))
* **authz:** authz v2 GetBulkDecision ([#2448](https://github.com/opentdf/platform/issues/2448)) ([0da3363](https://github.com/opentdf/platform/commit/0da3363f8cdc39d89892be12eac36b5040e594b9))
* **authz:** cache entitlement policy within authorization service ([#2457](https://github.com/opentdf/platform/issues/2457)) ([c16361c](https://github.com/opentdf/platform/commit/c16361c8048a6685fa7781b6f1f403f13c897792))
* **authz:** ensure logging parity between authz v2 and v1 ([#2443](https://github.com/opentdf/platform/issues/2443)) ([ef68586](https://github.com/opentdf/platform/commit/ef685860e1f01f9d618a8682d16055e5dfa91323))
* **core:** add cache manager ([#2449](https://github.com/opentdf/platform/issues/2449)) ([2b062c5](https://github.com/opentdf/platform/commit/2b062c51d529aaed179258e0af8c86f3e5d53078))
* **core:** consume RPC interceptor request context metadata in logging ([#2442](https://github.com/opentdf/platform/issues/2442)) ([2769c48](https://github.com/opentdf/platform/commit/2769c48a608d8373e24068f808ea27d89a0d5cd6))
* **core:** DSPX-609 - add cli-client to keycloak provisioning ([#2396](https://github.com/opentdf/platform/issues/2396)) ([48e7489](https://github.com/opentdf/platform/commit/48e74899ffc1b68a9e8adb5717e84649125271ec))
* **core:** ERS cache setup, fix cache initialization ([#2458](https://github.com/opentdf/platform/issues/2458)) ([d0c6938](https://github.com/opentdf/platform/commit/d0c6938632e5ba119e56fbb19d477bff1f4d1191))
* inject logger and cache manager to key managers ([#2461](https://github.com/opentdf/platform/issues/2461)) ([9292162](https://github.com/opentdf/platform/commit/9292162f0eefd0718bfff10e3118acda273c2d52))
* **kas:** expose provider config from key details. ([#2459](https://github.com/opentdf/platform/issues/2459)) ([0e7d39a](https://github.com/opentdf/platform/commit/0e7d39a53c1fff0194a26c8bb62a5e2996b5e9fb))
* **main:** Add Close() method to cache manager ([#2465](https://github.com/opentdf/platform/issues/2465)) ([32630d6](https://github.com/opentdf/platform/commit/32630d68a55f2ac03f5ac6c1472258aab09a2f05))
* **policy:** disable kas grants in favor of key mappings ([#2220](https://github.com/opentdf/platform/issues/2220)) ([30f8cf5](https://github.com/opentdf/platform/commit/30f8cf54abbb1a9def43a6d0fa602ba979dd3053))
* **policy:** Restrict deletion of pc with used key. ([#2414](https://github.com/opentdf/platform/issues/2414)) ([3b40a46](https://github.com/opentdf/platform/commit/3b40a46919e4c5b4f2e86dcd63e0f3d8a27d5d27))
* **sdk:** allow Connect-Protocol-Version RPC header for cors ([#2437](https://github.com/opentdf/platform/issues/2437)) ([4bf241e](https://github.com/opentdf/platform/commit/4bf241e15537da406019959b2062133f75171e0a))


### Bug Fixes

* **core:** remove generics on new platform cache manager and client ([#2456](https://github.com/opentdf/platform/issues/2456)) ([98c3c16](https://github.com/opentdf/platform/commit/98c3c166b2a86802c50fe4453ce3fea5974314dc))
* **core:** replace opentdf-public client with cli-client ([#2422](https://github.com/opentdf/platform/issues/2422)) ([fb18525](https://github.com/opentdf/platform/commit/fb18525049405e558f70ae77b075b9e75306d81e))
* **deps:** bump github.com/casbin/casbin/v2 from 2.106.0 to 2.107.0 in /service in the external group ([#2416](https://github.com/opentdf/platform/issues/2416)) ([43afd48](https://github.com/opentdf/platform/commit/43afd48a5338efecc1790f22a533e6d681af510d))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.4.0 to 0.5.0 in /service ([#2470](https://github.com/opentdf/platform/issues/2470)) ([3a73fc9](https://github.com/opentdf/platform/commit/3a73fc9383eadf9078ff2046e7d90eb8beb8ea14))
* **deps:** bump github.com/opentdf/platform/sdk from 0.4.7 to 0.5.0 in /service ([#2473](https://github.com/opentdf/platform/issues/2473)) ([ad37476](https://github.com/opentdf/platform/commit/ad374769f234ba727ed7f8ab61abdd78a450506c))
* **deps:** bump the external group across 1 directory with 2 updates ([#2450](https://github.com/opentdf/platform/issues/2450)) ([9d8d1f1](https://github.com/opentdf/platform/commit/9d8d1f155711fc4704e453e78e74b01ab09a26d6))
* **deps:** bump the external group across 1 directory with 2 updates ([#2472](https://github.com/opentdf/platform/issues/2472)) ([d45b3c8](https://github.com/opentdf/platform/commit/d45b3c8b1e76646f14970f1622809378ccaff26a))
* only request a token when near expiration ([#2370](https://github.com/opentdf/platform/issues/2370)) ([556d95e](https://github.com/opentdf/platform/commit/556d95ea6a7e61f9428754550c181c19e2f91747))
* **policy:** fix casing bug and get provider config on update. ([#2403](https://github.com/opentdf/platform/issues/2403)) ([a52b8f9](https://github.com/opentdf/platform/commit/a52b8f940c8e523d40275310be581e3383411717))
* **policy:** properly formatted pem in test fixtures ([#2409](https://github.com/opentdf/platform/issues/2409)) ([54ffd23](https://github.com/opentdf/platform/commit/54ffd2334b91b38c51a4b56e3b5e124f04bb2478))

## [0.6.0](https://github.com/opentdf/platform/compare/service/v0.5.5...service/v0.6.0) (2025-06-06)


### Features

* **authz:** DSPX-894 auth svc registered resource GetEntitlement support ([#2358](https://github.com/opentdf/platform/issues/2358)) ([a199aa7](https://github.com/opentdf/platform/commit/a199aa74687ecbbe87709a2c4140a8be96f3dcfd))
* **authz:** improve v2 request proto validation ([#2357](https://github.com/opentdf/platform/issues/2357)) ([f927b99](https://github.com/opentdf/platform/commit/f927b994149079947cac1d1386f2bfb9a52139a0))
* **core:** DSPX-608 - Deprecate public_client_id ([#2185](https://github.com/opentdf/platform/issues/2185)) ([0f58efa](https://github.com/opentdf/platform/commit/0f58efab4e99005b73041444d31b1c348b9e2834))
* **policy:** Return Simple Kas Keys from non-Key RPCs ([#2387](https://github.com/opentdf/platform/issues/2387)) ([5113e0e](https://github.com/opentdf/platform/commit/5113e0edbe0260d0937a62932671b40ca5cfcbf4))
* **policy:** Unique name for the key provider. ([#2391](https://github.com/opentdf/platform/issues/2391)) ([bb58b78](https://github.com/opentdf/platform/commit/bb58b7805a5099428efc6bda8441146f78fc02cb))
* **policy:** Update simple kas key ([#2378](https://github.com/opentdf/platform/issues/2378)) ([09d8239](https://github.com/opentdf/platform/commit/09d82390a06e22a8787118cd0ec7d97311e85363))


### Bug Fixes

* **deps:** bump github.com/opentdf/platform/protocol/go from 0.3.6 to 0.4.0 in /service ([#2399](https://github.com/opentdf/platform/issues/2399)) ([1c6fa75](https://github.com/opentdf/platform/commit/1c6fa755ea53c6b48aacd6a460849ce2834560a0))
* **deps:** bump the external group across 1 directory with 21 updates ([#2401](https://github.com/opentdf/platform/issues/2401)) ([3d0d4d1](https://github.com/opentdf/platform/commit/3d0d4d188557608e039e214cbdb52aecbb0bb0ac))
* **policy:** move action sub queries to CTE in sm list and match sql ([#2369](https://github.com/opentdf/platform/issues/2369)) ([0fd6feb](https://github.com/opentdf/platform/commit/0fd6febbfad59cfec1d807e4eec28082c0f5bf48))
* **policy:** protovalidate deprecated action types and removal of gRPC gateway in subject mappings svc ([#2377](https://github.com/opentdf/platform/issues/2377)) ([54a6de0](https://github.com/opentdf/platform/commit/54a6de03d8796b0fe72edc381ce514927bdcd793))
* **policy:** remove gRPC gateway in policy except where needed ([#2382](https://github.com/opentdf/platform/issues/2382)) ([1937acb](https://github.com/opentdf/platform/commit/1937acb3fff5e6216808ac233d3a34b869901b44))
* **policy:** remove support for creation/updation of SubjectMappings with deprecated proto actions ([#2373](https://github.com/opentdf/platform/issues/2373)) ([3660200](https://github.com/opentdf/platform/commit/36602005420e36a5c2bcc39665ded0094db62780))

## [0.5.5](https://github.com/opentdf/platform/compare/service/v0.5.4...service/v0.5.5) (2025-05-30)


### Features

* adds basic config root key manager ([#2303](https://github.com/opentdf/platform/issues/2303)) ([dd0d22f](https://github.com/opentdf/platform/commit/dd0d22fcafea3eb3b58d3836fe4776e4d15791cb))
* **policy:** cache SubjectConditionSet selectors in dedicated column maintained via trigger ([#2320](https://github.com/opentdf/platform/issues/2320)) ([215791f](https://github.com/opentdf/platform/commit/215791f2185d6cacfa4a8ae4a009739ee30bfc66))
* **policy:** map and merge grants and keys ([#2324](https://github.com/opentdf/platform/issues/2324)) ([abf770f](https://github.com/opentdf/platform/commit/abf770f6624f5f3a1ae291c006c76137197a38eb))


### Bug Fixes

* **deps:** bump github.com/opentdf/platform/sdk from 0.4.5 to 0.4.7 in /service in the internal group ([#2334](https://github.com/opentdf/platform/issues/2334)) ([7f5a182](https://github.com/opentdf/platform/commit/7f5a182d4d27876fedd42baf20cafd9f1731dac8))
* **deps:** Updates to major ver of protovalidate ([#2284](https://github.com/opentdf/platform/issues/2284)) ([39ad3c9](https://github.com/opentdf/platform/commit/39ad3c90f3ede1267418b5d4b1bed3d218d94a13))

## [0.5.4](https://github.com/opentdf/platform/compare/service/v0.5.3...service/v0.5.4) (2025-05-29)


### Features

* **authz:** access pdp v2 with actions ([#2264](https://github.com/opentdf/platform/issues/2264)) ([7afefb7](https://github.com/opentdf/platform/commit/7afefb7ac051cc57e8a81dd260f24ac2ae7db246))
* **authz:** logic for authz v2 (actions within ABAC decisioning) ([#2146](https://github.com/opentdf/platform/issues/2146)) ([0fdc259](https://github.com/opentdf/platform/commit/0fdc2599ba2026f35055f30e186006b1ba87a931))
* **policy:** Default Platform Keys ([#2254](https://github.com/opentdf/platform/issues/2254)) ([d7447fe](https://github.com/opentdf/platform/commit/d7447fe2604443b4c75c8e547acf414bf78af988))
* **policy:** Update key status's and UpdateKey rpc. ([#2315](https://github.com/opentdf/platform/issues/2315)) ([7908db9](https://github.com/opentdf/platform/commit/7908db9c2be5adeccd3fb9f177187aee53698ee8))


### Bug Fixes

* **policy:** DSPX-1151 update of registered resource value always clears existing action attribute values ([#2325](https://github.com/opentdf/platform/issues/2325)) ([ca94425](https://github.com/opentdf/platform/commit/ca9442562257c52673c3d22ded75d42b32cc0933))
* **policy:** Ensure non active keys cannot be assigned. ([#2321](https://github.com/opentdf/platform/issues/2321)) ([207d10d](https://github.com/opentdf/platform/commit/207d10d6535b66356cbdf9b4c09626786c7c9f44))

## [0.5.3](https://github.com/opentdf/platform/compare/service/v0.5.2...service/v0.5.3) (2025-05-22)


### Features

* **authz:** authz v2 versioning implementation ([#2173](https://github.com/opentdf/platform/issues/2173)) ([557fc21](https://github.com/opentdf/platform/commit/557fc2148dae9508a8c7f1088bdcf799bd00b794))
* **authz:** authz v2, ers v2 protos and gencode for ABAC with actions & registered resource  ([#2124](https://github.com/opentdf/platform/issues/2124)) ([ea7992a](https://github.com/opentdf/platform/commit/ea7992a6d6739084496ec0afdcb22eb9199d1a85))
* **authz:** export entity id prefix constant from entity instead of authorization service v1 ([#2261](https://github.com/opentdf/platform/issues/2261)) ([94079a9](https://github.com/opentdf/platform/commit/94079a9b90c3256081b2a4f9581986fdb30b3be8))
* **authz:** subject mapping plugin support for ABAC with actions ([#2223](https://github.com/opentdf/platform/issues/2223)) ([d08b939](https://github.com/opentdf/platform/commit/d08b939794bcb2794502c50adc575b58e30643c0))
* bulk keycloak provisioning ([#2205](https://github.com/opentdf/platform/issues/2205)) ([59e4485](https://github.com/opentdf/platform/commit/59e4485bdd0ced85c69604130505553f447918d1))
* **core:** add otel to opentdf services ([#1858](https://github.com/opentdf/platform/issues/1858)) ([53a7aa0](https://github.com/opentdf/platform/commit/53a7aa0fde3322a54d916169fc11fc495dcbaabe))
* **core:** Adds EC withSalt options ([#2126](https://github.com/opentdf/platform/issues/2126)) ([67b6fb8](https://github.com/opentdf/platform/commit/67b6fb8fc1263a4ddfa8ae1c8d451db50be77988))
* **core:** enhance db configuration options ([#2285](https://github.com/opentdf/platform/issues/2285)) ([ed9ff59](https://github.com/opentdf/platform/commit/ed9ff59349aa66f993ca05b3cc425ed344b62908))
* **core:** New Key Index and Manager Plugin SPI ([#2095](https://github.com/opentdf/platform/issues/2095)) ([eb446fc](https://github.com/opentdf/platform/commit/eb446fc555df7226019b891fba309eabb16e18c1))
* **core:** support onConfigUpdate hook when registering services ([#1992](https://github.com/opentdf/platform/issues/1992)) ([366d4dc](https://github.com/opentdf/platform/commit/366d4dcdb0ab167bc9523522e2a5a6bb8d310c1b))
* **core:** v2 ERS with proto updates ([#2210](https://github.com/opentdf/platform/issues/2210)) ([a161ef8](https://github.com/opentdf/platform/commit/a161ef85d12600672ff695cc84b07579a70c5cac))
* **policy:** actions crud service endpoints and proto validation ([#2037](https://github.com/opentdf/platform/issues/2037)) ([e933fa9](https://github.com/opentdf/platform/commit/e933fa99283f364a1078191dc4bdd2b94806a9c8))
* **policy:** actions service RPCs should actually hit storage layer CRUD ([#2063](https://github.com/opentdf/platform/issues/2063)) ([da4faf5](https://github.com/opentdf/platform/commit/da4faf5d8410c37180205ac9bad44436c88207e4))
* **policy:** add enhanced standard/custom actions protos ([#2020](https://github.com/opentdf/platform/issues/2020)) ([bbac53f](https://github.com/opentdf/platform/commit/bbac53fd622defefc6e8831ab041356fe7e23776))
* **policy:** Add platform key indexer. ([#2189](https://github.com/opentdf/platform/issues/2189)) ([861ef8d](https://github.com/opentdf/platform/commit/861ef8d8852a38b1ed809d306177546bb5f0982c))
* **policy:** consume lib/identifier parse function ([#2181](https://github.com/opentdf/platform/issues/2181)) ([1cef22b](https://github.com/opentdf/platform/commit/1cef22b235efd0bc88755bd613f1c87542e453ec))
* **policy:** DSPX-1018 NDR retrieval by FQN support ([#2131](https://github.com/opentdf/platform/issues/2131)) ([0001041](https://github.com/opentdf/platform/commit/00010419d372c358f8885953bcc33a27c2db4607))
* **policy:** DSPX-1057 registered resource action attribute values (DB + Service implementation) ([#2191](https://github.com/opentdf/platform/issues/2191)) ([6bf1b2e](https://github.com/opentdf/platform/commit/6bf1b2ef044312a428a603c80d0fcd3799122efe))
* **policy:** DSPX-1057 registered resource action attribute values (protos only) ([#2217](https://github.com/opentdf/platform/issues/2217)) ([6375596](https://github.com/opentdf/platform/commit/6375596555f09cabb3f1bc16d369fd6d2b94544a))
* **policy:** DSPX-893 NDR define crud protos ([#2056](https://github.com/opentdf/platform/issues/2056)) ([55a5c27](https://github.com/opentdf/platform/commit/55a5c279d0499f684bc62c53838edbcb89bec272))
* **policy:** DSPX-898 NDR database schema ([#2055](https://github.com/opentdf/platform/issues/2055)) ([2a10a6a](https://github.com/opentdf/platform/commit/2a10a6a777559e21fae1e4832529a3533a95ad03))
* **policy:** DSPX-901 NDR database crud ([#2071](https://github.com/opentdf/platform/issues/2071)) ([20e0a5f](https://github.com/opentdf/platform/commit/20e0a5f6254fc58873428c71806c8430d5872a82))
* **policy:** DSPX-902 NDR service crud implementation (2/2) ([#2066](https://github.com/opentdf/platform/issues/2066)) ([030ad33](https://github.com/opentdf/platform/commit/030ad33b5f94767279181d8748f00d3515b88eaf))
* **policy:** DSPX-902 NDR service crud protos only (1/2) ([#2092](https://github.com/opentdf/platform/issues/2092)) ([24b6cb5](https://github.com/opentdf/platform/commit/24b6cb5f876439dd5bb15ed95a20d18a16da3706))
* **policy:** Finish resource mapping groups ([#2224](https://github.com/opentdf/platform/issues/2224)) ([5ff754e](https://github.com/opentdf/platform/commit/5ff754e99189d09ec3698128d1bc51b6f7a90994))
* **policy:** GetMatchedSubjectMappings should provide value FQN ([#2151](https://github.com/opentdf/platform/issues/2151)) ([ad80044](https://github.com/opentdf/platform/commit/ad80044c58f054c8abe60b594a573b9ce46877ee))
* **policy:** key management crud ([#2110](https://github.com/opentdf/platform/issues/2110)) ([4c3d53d](https://github.com/opentdf/platform/commit/4c3d53d5fbb6f4659155ac60d289d92ac20180f1))
* **policy:** Key management proto ([#2115](https://github.com/opentdf/platform/issues/2115)) ([561f853](https://github.com/opentdf/platform/commit/561f85301c73c221cf22695afb66deeac594a3d6))
* **policy:** Modify get request to search for keys by kasid with keyid. ([#2147](https://github.com/opentdf/platform/issues/2147)) ([780d2e4](https://github.com/opentdf/platform/commit/780d2e476f48678c7e384a9ef83df0b8e8b9428a))
* **policy:** Restrict KAS deletion when tied to Key ([#2144](https://github.com/opentdf/platform/issues/2144)) ([4c4ab13](https://github.com/opentdf/platform/commit/4c4ab13f890f080ed087f99a2c50981c97db8b19))
* **policy:** Return KAS Key structure ([#2172](https://github.com/opentdf/platform/issues/2172)) ([7f97b99](https://github.com/opentdf/platform/commit/7f97b99f7f08fbd53cdb3592206f974040c270f3))
* **policy:** rotate keys rpc ([#2180](https://github.com/opentdf/platform/issues/2180)) ([0d00743](https://github.com/opentdf/platform/commit/0d00743d08c3e80fd1b5f9f37adc66d218b8c13b))
* **policy:** stored enhanced actions database migration, CRUD queries, SM updates ([#2040](https://github.com/opentdf/platform/issues/2040)) ([e6b7c79](https://github.com/opentdf/platform/commit/e6b7c79918fdde742692952676b901d0571e73da))
* **sdk:** Add a KAS allowlist ([#2085](https://github.com/opentdf/platform/issues/2085)) ([d7cfdf3](https://github.com/opentdf/platform/commit/d7cfdf376681eab9becc0b5be863379a3182f410))
* **sdk:** add nanotdf plaintext policy ([#2182](https://github.com/opentdf/platform/issues/2182)) ([e5c56db](https://github.com/opentdf/platform/commit/e5c56db5c962d6ff21e7346198f01558489adf3f))
* **sdk:** Use ConnectRPC in the go client ([#2200](https://github.com/opentdf/platform/issues/2200)) ([fc34ee6](https://github.com/opentdf/platform/commit/fc34ee6293dfb9192d48784daaff34d26eaacd1d))


### Bug Fixes

* **core:** access pdp cleanup before actions in ABAC decisioning ([#2123](https://github.com/opentdf/platform/issues/2123)) ([9b38a3c](https://github.com/opentdf/platform/commit/9b38a3ce68d3aea66fe362123de61d4f2b9cb47f))
* **core:** Autobump service ([#2080](https://github.com/opentdf/platform/issues/2080)) ([006c724](https://github.com/opentdf/platform/commit/006c724d8b97d9ce37e63cda886e058a66e77d06))
* **core:** Autobump service ([#2104](https://github.com/opentdf/platform/issues/2104)) ([1f72cc7](https://github.com/opentdf/platform/commit/1f72cc76720ebb751c2e83cd0b07cebdc552f485))
* **core:** Autobump service ([#2108](https://github.com/opentdf/platform/issues/2108)) ([be5b7d7](https://github.com/opentdf/platform/commit/be5b7d754aa3665a7a9b758a8d7dcdd502757b37))
* **core:** bump to go 1.24 and bump service proto module dependencies ([#2064](https://github.com/opentdf/platform/issues/2064)) ([94891a0](https://github.com/opentdf/platform/commit/94891a0c43c105e5a46bda595362705bb6a9feb3))
* **core:** Fix DPoP with grpc-gateway ([#2044](https://github.com/opentdf/platform/issues/2044)) ([4483ef2](https://github.com/opentdf/platform/commit/4483ef20a8d3340d298e21bf7140b8a1b13d1928))
* **core:** fix service go.mod ([#2141](https://github.com/opentdf/platform/issues/2141)) ([3b98f6d](https://github.com/opentdf/platform/commit/3b98f6d5380d19421a6ad17f7f9fddf3c13fa116))
* **core:** Improves errors when under heavy load ([#2132](https://github.com/opentdf/platform/issues/2132)) ([4490a14](https://github.com/opentdf/platform/commit/4490a14db2492629e287445df26312eb3e363b81))
* **core:** Let legacy KAOs use new trust plugins ([#2218](https://github.com/opentdf/platform/issues/2218)) ([5aa6916](https://github.com/opentdf/platform/commit/5aa6916fd646406b023de61cccbd845bd342f0e5))
* **core:** migrate from mitchellh/mapstructure to go-viper/mapstructure ([#2087](https://github.com/opentdf/platform/issues/2087)) ([0a3a82e](https://github.com/opentdf/platform/commit/0a3a82ec71bbc17b02ecc4ed9a0545529be2c412))
* **core:** update viper to 1.20.1 ([#2088](https://github.com/opentdf/platform/issues/2088)) ([09099e9](https://github.com/opentdf/platform/commit/09099e93f068dc50ad17f5f8020c5f89158dd66e))
* **core:** Updates vulnerable dep go/x/net ([#2072](https://github.com/opentdf/platform/issues/2072)) ([11c02cd](https://github.com/opentdf/platform/commit/11c02cd3d20447edb73db2fdc9181541b541343a))
* **deps:** bump github.com/creasty/defaults from 1.7.0 to 1.8.0 in /service ([#2242](https://github.com/opentdf/platform/issues/2242)) ([86a9b46](https://github.com/opentdf/platform/commit/86a9b46f7f8926a3b4ee3cb0dd54662315b36b9e))
* **deps:** bump github.com/jackc/pgx/v5 from 5.5.5 to 5.7.5 in /service ([#2249](https://github.com/opentdf/platform/issues/2249)) ([d8f3b67](https://github.com/opentdf/platform/commit/d8f3b67a77abf18afa7a6188b863bce0a7910c42))
* **deps:** bump the internal group across 1 directory with 2 updates ([#2296](https://github.com/opentdf/platform/issues/2296)) ([7f92c70](https://github.com/opentdf/platform/commit/7f92c70dbe09897980e62eae3f42687e1aa23353))
* **deps:** bump toolchain in /lib/fixtures and /examples to resolve CVE GO-2025-3563 ([#2061](https://github.com/opentdf/platform/issues/2061)) ([9c16843](https://github.com/opentdf/platform/commit/9c168437db3b138613fe629419dd6bd9f837e881))
* handle empty private and public key ctx structs ([#2272](https://github.com/opentdf/platform/issues/2272)) ([f3fc647](https://github.com/opentdf/platform/commit/f3fc6477039c0218bf0a0f8d48a9339d69084cf8))
* **policy:** remove predefined rules in actions protos ([#2069](https://github.com/opentdf/platform/issues/2069)) ([060f059](https://github.com/opentdf/platform/commit/060f05941f9b81b007669f51b6205723af8c1680))
* **policy:** return kas uri on keys for definition, namespace and values ([#2186](https://github.com/opentdf/platform/issues/2186)) ([6c55fb8](https://github.com/opentdf/platform/commit/6c55fb8614903c7fc68151908e25fe4c202f6574))
* update key_mode to provide more context ([#2226](https://github.com/opentdf/platform/issues/2226)) ([44d0805](https://github.com/opentdf/platform/commit/44d0805fb34d87098ada7b5f7c934f65365f77f1))

## [0.5.2](https://github.com/opentdf/platform/compare/service/v0.5.1...service/v0.5.2) (2025-04-01)


### Bug Fixes

* **core:** map IPC reauth routes config  ([#2021](https://github.com/opentdf/platform/issues/2021)) ([b232fc6](https://github.com/opentdf/platform/commit/b232fc60283302174109fc201b2233303444fd7b))

## [0.5.1](https://github.com/opentdf/platform/compare/service/v0.5.0...service/v0.5.1) (2025-03-31)


### Bug Fixes

* **main:** add ipc auth extensibility ([#2014](https://github.com/opentdf/platform/issues/2014)) ([0c701d4](https://github.com/opentdf/platform/commit/0c701d4317faf870d99e009f19f6624d951f2917))

## [0.5.0](https://github.com/opentdf/platform/compare/service/v0.4.40...service/v0.5.0) (2025-03-28)


### ⚠ BREAKING CHANGES

* **core:** update GRPC Gateway to use IPC ([#2005](https://github.com/opentdf/platform/issues/2005))
* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979))

### Features

* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979)) ([164c922](https://github.com/opentdf/platform/commit/164c922af74b1265fe487362c356abb7f1503ada))


### Bug Fixes

* **core:** update GRPC Gateway to use IPC ([#2005](https://github.com/opentdf/platform/issues/2005)) ([ff605f4](https://github.com/opentdf/platform/commit/ff605f40cc1541c35d9492071f47469c4dba1364))

## [0.4.40](https://github.com/opentdf/platform/compare/service/v0.4.39...service/v0.4.40) (2025-03-10)


### Bug Fixes

* **core:** Autobump service ([#1970](https://github.com/opentdf/platform/issues/1970)) ([c0bbb11](https://github.com/opentdf/platform/commit/c0bbb11042b7cae5317e19e8e8333d4eff2008c8))
* **core:** Autobump service ([#1976](https://github.com/opentdf/platform/issues/1976)) ([c79fe0d](https://github.com/opentdf/platform/commit/c79fe0daf4742277e7cd177cf6ca565cbe3c9e47))
* **core:** Fixes merge fail in bulk logic ([#1966](https://github.com/opentdf/platform/issues/1966)) ([c93bf62](https://github.com/opentdf/platform/commit/c93bf62c8fc39bf5c4f64386f37067e689024001))
* **policy:** remove new public keys rpc's ([#1962](https://github.com/opentdf/platform/issues/1962)) ([5049bab](https://github.com/opentdf/platform/commit/5049baba20ddcefa40c280a18e5dd8ef754b7e22))
* Service utilize `httputil.SafeHttpClient` ([#1926](https://github.com/opentdf/platform/issues/1926)) ([af32700](https://github.com/opentdf/platform/commit/af32700d37af4a8b2b354aefad56f05781e4ecd1))

## [0.4.39](https://github.com/opentdf/platform/compare/service/v0.4.38...service/v0.4.39) (2025-02-27)


### Features

* add ability to retrieve policy resources by id or name ([#1901](https://github.com/opentdf/platform/issues/1901)) ([deb4455](https://github.com/opentdf/platform/commit/deb4455773cd71d3436510bbeb599f309106ce1d))
* **core:** EXPERIMENTAL: EC-wrapped key support ([#1902](https://github.com/opentdf/platform/issues/1902)) ([652266f](https://github.com/opentdf/platform/commit/652266f212ba10b2492a84741f68391a1d39e007))
* **policy:** adds new public keys table ([#1836](https://github.com/opentdf/platform/issues/1836)) ([cad5048](https://github.com/opentdf/platform/commit/cad5048d09609d678d5b5ac2972605dd61f33bb5))


### Bug Fixes

* add pagination to list public key mappings response ([#1889](https://github.com/opentdf/platform/issues/1889)) ([9898fbd](https://github.com/opentdf/platform/commit/9898fbda305f4eface291a2aaa98d2df80f0ad05))
* cleanup kas public key create error messages ([#1887](https://github.com/opentdf/platform/issues/1887)) ([59f7d0e](https://github.com/opentdf/platform/commit/59f7d0e0ab45ef47b2df9326c0904b54fba4b3eb))
* **core:** Autobump service ([#1875](https://github.com/opentdf/platform/issues/1875)) ([4b6c335](https://github.com/opentdf/platform/commit/4b6c3353913ad90aeef499beb5f8c52144679a61))
* **core:** Autobump service ([#1895](https://github.com/opentdf/platform/issues/1895)) ([08a2048](https://github.com/opentdf/platform/commit/08a20481a085b4af67fc78e6cfae371f0bccd166))
* **core:** Autobump service ([#1919](https://github.com/opentdf/platform/issues/1919)) ([f902295](https://github.com/opentdf/platform/commit/f90229560e8f09b64b4bf650b271c5fbb428bc7f))
* **core:** Autobump service ([#1945](https://github.com/opentdf/platform/issues/1945)) ([d2e37ca](https://github.com/opentdf/platform/commit/d2e37ca081d04f4588c58b752b0c96ef9b0125cb))
* **core:** Autobump service ([#1950](https://github.com/opentdf/platform/issues/1950)) ([7270080](https://github.com/opentdf/platform/commit/7270080639f19ba9725f1e834970d94d00191994))
* **core:** Autobump service ([#1952](https://github.com/opentdf/platform/issues/1952)) ([b20123e](https://github.com/opentdf/platform/commit/b20123ef768063eb883d9414d86ec1a0e3009884))
* **core:** Fixes for ec-wrapped from js client ([#1923](https://github.com/opentdf/platform/issues/1923)) ([3a66485](https://github.com/opentdf/platform/commit/3a6648528e3d3582ec3c5222e4dfc37d0fb13e74))
* **core:** Fixes protoJSON parse bug on ec rewrap ([#1943](https://github.com/opentdf/platform/issues/1943)) ([9bebfd0](https://github.com/opentdf/platform/commit/9bebfd01f615f5a438e0695c03dbb1a9ad7badf3))
* **core:** improve logging and errors on rewrap ([#1906](https://github.com/opentdf/platform/issues/1906)) ([84339d6](https://github.com/opentdf/platform/commit/84339d620717c7bc5de0d6bb6ece656cce5c07be))
* **core:** Requires unique kids ([#1905](https://github.com/opentdf/platform/issues/1905)) ([c1b380c](https://github.com/opentdf/platform/commit/c1b380cb586a10196a8febc700a57c2c41a51a18))
* filter total count on list public key operations ([#1884](https://github.com/opentdf/platform/issues/1884)) ([8df0adc](https://github.com/opentdf/platform/commit/8df0adc60dd49aa3dcdaf4d60f094338ca5ad2e9))
* **sdk:** Fix compatibility between bulk and non-bulk rewrap ([#1914](https://github.com/opentdf/platform/issues/1914)) ([74abbb6](https://github.com/opentdf/platform/commit/74abbb66cbb39023f56cd502a7cda294580a41c6))

## [0.4.38](https://github.com/opentdf/platform/compare/service/v0.4.37...service/v0.4.38) (2025-01-21)


### Features

* **core:** adds bulk rewrap to sdk and service ([#1835](https://github.com/opentdf/platform/issues/1835)) ([11698ae](https://github.com/opentdf/platform/commit/11698ae18f66282980a7822dd145e3896c2b605c))


### Bug Fixes

* **core:** Autobump service ([#1864](https://github.com/opentdf/platform/issues/1864)) ([f9d149b](https://github.com/opentdf/platform/commit/f9d149b78ff1425d8f376e05ea93793e319d1354))
* **core:** Autobump service ([#1867](https://github.com/opentdf/platform/issues/1867)) ([b8f5101](https://github.com/opentdf/platform/commit/b8f5101efa08087c7e1de534b4aa607811f7df93))
* **core:** reduces GetAttributeValuesByFqns calls in getDecisions ([#1857](https://github.com/opentdf/platform/issues/1857)) ([5379baf](https://github.com/opentdf/platform/commit/5379baf9701d1ae1168e8fc6b51a9c80bc9d2773))

## [0.4.37](https://github.com/opentdf/platform/compare/service/v0.4.36...service/v0.4.37) (2025-01-09)


### Features

* **core:** Expose version info ([#1841](https://github.com/opentdf/platform/issues/1841)) ([92a9f5e](https://github.com/opentdf/platform/commit/92a9f5eab3f2372990b86df6a22ad209eed1a0f9))


### Bug Fixes

* **core:** Correct length of GetDecision response array ([#1839](https://github.com/opentdf/platform/issues/1839)) ([85ce9b6](https://github.com/opentdf/platform/commit/85ce9b60bda1c105f758399de7e209f8ce3c33ac))
* **core:** Return deny decision for empty entity chains ([#1846](https://github.com/opentdf/platform/issues/1846)) ([1e8b6a5](https://github.com/opentdf/platform/commit/1e8b6a5b444bd1aaaabf1de0a64778d3f992ee52))

## [0.4.36](https://github.com/opentdf/platform/compare/service/v0.4.35...service/v0.4.36) (2025-01-03)


### Bug Fixes

* **core:** GetDecisions should handle empty string and non-existent attributes ([#1832](https://github.com/opentdf/platform/issues/1832)) ([dc89678](https://github.com/opentdf/platform/commit/dc8967842a035debce6d2251e13823b183e9c433))
* **core:** reduces GetEntitlements calls in GetDecisions ([#1822](https://github.com/opentdf/platform/issues/1822)) ([8bb5744](https://github.com/opentdf/platform/commit/8bb57440209f50434bcf46551f206dc49b040a03))

## [0.4.35](https://github.com/opentdf/platform/compare/service/v0.4.34...service/v0.4.35) (2024-12-18)


### Features

* **core:** Expose context authn methods ([#1812](https://github.com/opentdf/platform/issues/1812)) ([a9f3fcc](https://github.com/opentdf/platform/commit/a9f3fccb8392609a1ca3e3658ec4fb930367abc9))


### Bug Fixes

* **core:** Update fixtures and flattening in sdk and service ([#1827](https://github.com/opentdf/platform/issues/1827)) ([d6d6a7a](https://github.com/opentdf/platform/commit/d6d6a7a2dffdb96cf7f7f731a4e6e66e06930e59))

## [0.4.34](https://github.com/opentdf/platform/compare/service/v0.4.33...service/v0.4.34) (2024-12-11)


### Bug Fixes

* **core:** properly chain grpc-gateway middleware order ([#1820](https://github.com/opentdf/platform/issues/1820)) ([5b9f054](https://github.com/opentdf/platform/commit/5b9f0541f39c6141ea060d699146482959fb32f7))

## [0.4.33](https://github.com/opentdf/platform/compare/service/v0.4.32...service/v0.4.33) (2024-12-06)


### Bug Fixes

* **core:** Allow more users to rewrap ([#1813](https://github.com/opentdf/platform/issues/1813)) ([4d47475](https://github.com/opentdf/platform/commit/4d474750c20a9a6fe0f00487195851a606e24076))
* **core:** Handle multiple modes including entityresolution mode ([#1816](https://github.com/opentdf/platform/issues/1816)) ([32d6938](https://github.com/opentdf/platform/commit/32d6938549bd9fc7e9e2fc7ec0157537bddafcc9))

## [0.4.32](https://github.com/opentdf/platform/compare/service/v0.4.31...service/v0.4.32) (2024-12-04)


### Features

* **policy:** 1660 transition Policy FQN indexing to a transaction rather than an unmonitored side effect ([#1782](https://github.com/opentdf/platform/issues/1782)) ([7c4c74f](https://github.com/opentdf/platform/commit/7c4c74f0da34da86085b30726d5606542ba10cff))


### Bug Fixes

* **authz:** handle pagination in authz service ([#1797](https://github.com/opentdf/platform/issues/1797)) ([58cb3f6](https://github.com/opentdf/platform/commit/58cb3f672324b715aeae04ac90368a33e8b045fa))
* **core:** expose rest based healthcheck ([#1810](https://github.com/opentdf/platform/issues/1810)) ([859f23b](https://github.com/opentdf/platform/commit/859f23bd399b2a4e8a37c1e06ad1d613087451e2))

## [0.4.31](https://github.com/opentdf/platform/compare/service/v0.4.30...service/v0.4.31) (2024-12-02)


### Features

* **kas:** collect metrics ([#1702](https://github.com/opentdf/platform/issues/1702)) ([def28d1](https://github.com/opentdf/platform/commit/def28d1984b0b111a07330a3eb59c1285206062d))
* **policy:** 1500 Attribute create with Values (one RPC Call) should employ a db transaction ([#1778](https://github.com/opentdf/platform/issues/1778)) ([90edbde](https://github.com/opentdf/platform/commit/90edbde92ea63ad488b9a6de09fcffbc7a4380de))


### Bug Fixes

* **core:** move auth interceptor to top of chain ([#1790](https://github.com/opentdf/platform/issues/1790)) ([f9f5a75](https://github.com/opentdf/platform/commit/f9f5a7545827c5d8cef7f536963e4f794a7f3f6c))
* **policy:** return fqns in list subject mappings ([#1796](https://github.com/opentdf/platform/issues/1796)) ([c0a9dda](https://github.com/opentdf/platform/commit/c0a9dda975a9384cea8efc413d567edce13f753f))

## [0.4.30](https://github.com/opentdf/platform/compare/service/v0.4.29...service/v0.4.30) (2024-11-27)


### Features

* **core:** Introduce ERS mode, ability to connect to remote ERS ([#1735](https://github.com/opentdf/platform/issues/1735)) ([a118316](https://github.com/opentdf/platform/commit/a11831694302114a5d96ac7c6adb4ed55ceff80e))
* **policy:** limit/offset throughout LIST service RPCs/db ([#1669](https://github.com/opentdf/platform/issues/1669)) ([ec46a3a](https://github.com/opentdf/platform/commit/ec46a3a4375d6fe1c948c6f25146bb572717c651)), closes [#55](https://github.com/opentdf/platform/issues/55)


### Bug Fixes

* **core:** Autobump service ([#1789](https://github.com/opentdf/platform/issues/1789)) ([ff7c6f3](https://github.com/opentdf/platform/commit/ff7c6f3ffe420d7c9ee8afe2a4d8614229128bed))
* **core:** Set token endpoint manually if client creds provided in server sdk_config ([#1780](https://github.com/opentdf/platform/issues/1780)) ([07a1dbd](https://github.com/opentdf/platform/commit/07a1dbd28f6e758d36b54b44957ca132fd21793f))
* properly set casbin authz policy ([#1776](https://github.com/opentdf/platform/issues/1776)) ([d4b501c](https://github.com/opentdf/platform/commit/d4b501c66f105a2c90ccc5bfa631b4b063e96f3e))

## [0.4.29](https://github.com/opentdf/platform/compare/service/v0.4.28...service/v0.4.29) (2024-11-18)


### Features

* **core:** programmatic setting of authz policy ([#1769](https://github.com/opentdf/platform/issues/1769)) ([dff34ff](https://github.com/opentdf/platform/commit/dff34ffabf190f21d2f866de23bf9ef955ab7c12))

## [0.4.28](https://github.com/opentdf/platform/compare/service/v0.4.27...service/v0.4.28) (2024-11-15)


### Features

* **sdk:** add collections for nanotdf  ([#1695](https://github.com/opentdf/platform/issues/1695)) ([6497bf3](https://github.com/opentdf/platform/commit/6497bf3a7cee9b6900569bc6cc2c39b2f647fb52))


### Bug Fixes

* **core:** Autobump service ([#1767](https://github.com/opentdf/platform/issues/1767)) ([949087e](https://github.com/opentdf/platform/commit/949087e5e28e2ef082989d0b9622820f6ec57f69))
* **core:** Autobump service ([#1771](https://github.com/opentdf/platform/issues/1771)) ([7a2e709](https://github.com/opentdf/platform/commit/7a2e709acbe0e01df74b0691a93fe54b03754f0c))
* **core:** Updates dpop check for connect ([#1760](https://github.com/opentdf/platform/issues/1760)) ([6d7f24a](https://github.com/opentdf/platform/commit/6d7f24a32222a9eff73c769ac9ec3af91058c7ea))
* grpc-gateway connection with tls enabled ([#1758](https://github.com/opentdf/platform/issues/1758)) ([3120350](https://github.com/opentdf/platform/commit/312035008dfd42c94d3e8135d05deb4cc5bfe21f))

## [0.4.27](https://github.com/opentdf/platform/compare/service/v0.4.26...service/v0.4.27) (2024-11-14)


### Features

* **authz:** JWT ERS that just returns claims ([#1630](https://github.com/opentdf/platform/issues/1630)) ([316b5be](https://github.com/opentdf/platform/commit/316b5be042d9723b19ad5fdbc02f3ffdbc3764c2))
* **authz:** Remove org-admin role, move privileges to admin role ([#1740](https://github.com/opentdf/platform/issues/1740)) ([ae931d0](https://github.com/opentdf/platform/commit/ae931d02f347edea468d4c5d48ab3e07ce7d3abe))
* backend migration to connect-rpc ([#1733](https://github.com/opentdf/platform/issues/1733)) ([d10ba3c](https://github.com/opentdf/platform/commit/d10ba3cb22175a000ba5d156987c9f201749ae88))
* connectrpc realip interceptor ([#1728](https://github.com/opentdf/platform/issues/1728)) ([292fca0](https://github.com/opentdf/platform/commit/292fca06441b1587edb9c64f324eb87dc0b88c5f))
* **docs:** add policy ADR for LIST limit and pagination ([#1557](https://github.com/opentdf/platform/issues/1557)) ([069f939](https://github.com/opentdf/platform/commit/069f939923cb3570c1e62453f68022a0b9c3e544))
* move from fasthttp in-memory listener to memhttp implementation ([#1709](https://github.com/opentdf/platform/issues/1709)) ([70518ff](https://github.com/opentdf/platform/commit/70518ff6da81fda1c61452968ed4c0615e4702b9))
* **policy:** 1603 policy improve upsertattrfqn ([#1679](https://github.com/opentdf/platform/issues/1679)) ([cd17a44](https://github.com/opentdf/platform/commit/cd17a44c3fdb7d510cb9e1fb744a1b12fe1e346e))
* **policy:** 1651 move GetAttributesByValueFqns RPC request validation to protovalidate ([#1657](https://github.com/opentdf/platform/issues/1657)) ([c7d6b15](https://github.com/opentdf/platform/commit/c7d6b1542c10d3e2a35fa00efaf7d415f63c7dca))
* **policy:** 1659 spike on transactions support ([#1678](https://github.com/opentdf/platform/issues/1678)) ([a6fea11](https://github.com/opentdf/platform/commit/a6fea11070f18b7136f47fe87d4fe2020189efb8))
* **policy:** add optional name field to registered KASes in policy ([#1636](https://github.com/opentdf/platform/issues/1636)) ([f1382c1](https://github.com/opentdf/platform/commit/f1382c16893cefd40e930f4112ac7a61c9b05898))
* **policy:** add optional name field to registered KASes in policy ([#1641](https://github.com/opentdf/platform/issues/1641)) ([b277ab4](https://github.com/opentdf/platform/commit/b277ab4cb4fa9aca343fa14d1751f4dff3ea3e23))
* **policy:** limit/offset throughout LIST protos/gencode ([#1668](https://github.com/opentdf/platform/issues/1668)) ([7de6cce](https://github.com/opentdf/platform/commit/7de6cce5c9603228bc0ef5566b5b2d10c4a12ee4))
* **policy:** SPIKE transactions support ([#1663](https://github.com/opentdf/platform/issues/1663)) ([866f4f3](https://github.com/opentdf/platform/commit/866f4f364991c55cad75be79c55adab013a25ead))
* **policy:** subject condition sets prune protos/gencode ([#1687](https://github.com/opentdf/platform/issues/1687)) ([a627e02](https://github.com/opentdf/platform/commit/a627e021e9df2c06e1c86acfc0a4ee83c4bce932))
* **policy:** subject condition sets prune service/db ([#1688](https://github.com/opentdf/platform/issues/1688)) ([3cdd1b2](https://github.com/opentdf/platform/commit/3cdd1b26e81cb004b02af44e914baef3422cdcde)), closes [#1178](https://github.com/opentdf/platform/issues/1178)
* update service registry in preperation for connectrpc migration ([#1715](https://github.com/opentdf/platform/issues/1715)) ([ce289a4](https://github.com/opentdf/platform/commit/ce289a44505e5e3be995e5049f5cbbfb1839f41b))


### Bug Fixes

* cleanup left over status.Error in favor of connect.NewError ([#1751](https://github.com/opentdf/platform/issues/1751)) ([acea8d1](https://github.com/opentdf/platform/commit/acea8d1dbbc037458e6974376a609e064a238931))
* **core:** Autobump service ([#1726](https://github.com/opentdf/platform/issues/1726)) ([39a898d](https://github.com/opentdf/platform/commit/39a898d3d7c45c48187ed54e67519d953d5e3d0c))
* **core:** Autobump service ([#1739](https://github.com/opentdf/platform/issues/1739)) ([46662a7](https://github.com/opentdf/platform/commit/46662a791aa5c26ff6b363e773d74c1e7a89614c))
* **core:** Autobump service ([#1750](https://github.com/opentdf/platform/issues/1750)) ([4b239b1](https://github.com/opentdf/platform/commit/4b239b1f288121ec224038aff7534d4b5329c22d))
* Fixtures CodeQL alert for potentially unsafe quoting ([#1703](https://github.com/opentdf/platform/issues/1703)) ([6f2fa9b](https://github.com/opentdf/platform/commit/6f2fa9b49ae59ca22eedd4b41df02a2bc5fe687d))
* **kas:** Only hit authorization if data attributes not empty ([#1741](https://github.com/opentdf/platform/issues/1741)) ([471f5f1](https://github.com/opentdf/platform/commit/471f5f102e7a4e01abaff6fa2750ad784880274b))
* **policy:** enhance proto validation across policy requests ([#1656](https://github.com/opentdf/platform/issues/1656)) ([df534c4](https://github.com/opentdf/platform/commit/df534c40f3f500190b200923e5157701b438431b))
* **policy:** make MatchSubjectMappings operator agnostic ([#1658](https://github.com/opentdf/platform/issues/1658)) ([cb63819](https://github.com/opentdf/platform/commit/cb63819d107ed65cb5d467a956d713bd55214cdb))
* **policy:** REVERT PR [#1663](https://github.com/opentdf/platform/issues/1663) - SPIKE transactions support ([#1719](https://github.com/opentdf/platform/issues/1719)) ([184a733](https://github.com/opentdf/platform/commit/184a733154943abab7fd2a3715dc25b63dfa622e))
* **policy:** schema markdown links should work ([#1672](https://github.com/opentdf/platform/issues/1672)) ([4122262](https://github.com/opentdf/platform/commit/412226296d579f1d9cb52f149a5e4b629a7f7908))

## [0.4.26](https://github.com/opentdf/platform/compare/service/v0.4.25...service/v0.4.26) (2024-10-17)


### Bug Fixes

* use the right service namespace and update the tests ([#1665](https://github.com/opentdf/platform/issues/1665)) ([72ce62b](https://github.com/opentdf/platform/commit/72ce62b9b79a5b00d9723003789648246dd009b1))

## [0.4.25](https://github.com/opentdf/platform/compare/service/v0.4.24...service/v0.4.25) (2024-10-15)


### Features

* **authz:** Add name to entity id when retrieved from token ([#1616](https://github.com/opentdf/platform/issues/1616)) ([5304204](https://github.com/opentdf/platform/commit/53042041a3c4993cc56db893a69b9e27363e8d1a))
* **core:** Add entity category to audit logs ([#1614](https://github.com/opentdf/platform/issues/1614)) ([871878c](https://github.com/opentdf/platform/commit/871878c922b595cc5354a10300f3e488a841e580))
* **core:** Change log level from Debug to Trace for readiness checks ([#1544](https://github.com/opentdf/platform/issues/1544)) ([0af1269](https://github.com/opentdf/platform/commit/0af12698842b297e9b8f7de5fd009c2e776c5ec1)), closes [#1545](https://github.com/opentdf/platform/issues/1545)
* **policy:** 1004 add audit support for unsafe actions ([#1620](https://github.com/opentdf/platform/issues/1620)) ([4b64e5b](https://github.com/opentdf/platform/commit/4b64e5bc7978201b1f4ba688c292925da227081e))
* **policy:** 1357 policy GetAttributeByFqn db query should employ fewer roundtrips ([#1633](https://github.com/opentdf/platform/issues/1633)) ([0bdb7e5](https://github.com/opentdf/platform/commit/0bdb7e507e5b0303db281e8b967a20b8cbc43ec2)), closes [#1357](https://github.com/opentdf/platform/issues/1357)
* **policy:** 1421 tech debt migrate Resource Mappings object queries to sqlc ([#1422](https://github.com/opentdf/platform/issues/1422)) ([cd74bcf](https://github.com/opentdf/platform/commit/cd74bcf00d1c19c9a609f1dba6ad406a0454b07c))
* **policy:** 1426 tech debt migrate Namespace object queries to sqlc - PART 2 ([#1617](https://github.com/opentdf/platform/issues/1617)) ([b914350](https://github.com/opentdf/platform/commit/b9143502c737a526f71a41d31ad6778e392255e0))
* **policy:** 1434 tech debt migrate attribute value object queries to sqlc ([#1444](https://github.com/opentdf/platform/issues/1444)) ([0a7998e](https://github.com/opentdf/platform/commit/0a7998ec44c98eab5e084766e759fb2596e6e184)), closes [#1434](https://github.com/opentdf/platform/issues/1434)
* **policy:** 1435 tech debt migrate attribute definition object queries to sqlc ([#1450](https://github.com/opentdf/platform/issues/1450)) ([c36624c](https://github.com/opentdf/platform/commit/c36624cbefd8643cad6f01603046fa060ae06724))
* **policy:** 1436 tech debt migrate subject mapping and condition set object queries to sqlc ([#1606](https://github.com/opentdf/platform/issues/1606)) ([ec60c9f](https://github.com/opentdf/platform/commit/ec60c9fcb6d2ad7c7638dab39145341ab6f5d213))
* **policy:** 1438 tech debt migrate attribute fqn indexing queries to sqlc ([#1445](https://github.com/opentdf/platform/issues/1445)) ([617aa91](https://github.com/opentdf/platform/commit/617aa913a1e79f0332c90e2882878c88ba3c3ff7)), closes [#1438](https://github.com/opentdf/platform/issues/1438)
* **policy:** 1580 Resource Mappings GET/LIST should provide attribute value FQNs in response ([#1622](https://github.com/opentdf/platform/issues/1622)) ([e33bcc0](https://github.com/opentdf/platform/commit/e33bcc0aa04794049a5f920e1d4014a86e65a97b)), closes [#1580](https://github.com/opentdf/platform/issues/1580)
* **policy:** 1618 update KAS CRUD to align with ADR decisions ([#1619](https://github.com/opentdf/platform/issues/1619)) ([379f980](https://github.com/opentdf/platform/commit/379f980bc8166fcf856e75e6ba5bac75adff92d6)), closes [#1618](https://github.com/opentdf/platform/issues/1618)
* **policy:** DSP-51 - deprecate PublicKey local field ([#1590](https://github.com/opentdf/platform/issues/1590)) ([e3ed0b5](https://github.com/opentdf/platform/commit/e3ed0b5ce6039000c9e3c574d3d6ce2931781235))
* **sdk:** Improve KAS key lookup and caching ([#1556](https://github.com/opentdf/platform/issues/1556)) ([fb6c47a](https://github.com/opentdf/platform/commit/fb6c47a95f2e91748436a76aeef46a81273bb10d))


### Bug Fixes

* allow standard users to get authorization decisions ([#1634](https://github.com/opentdf/platform/issues/1634)) ([718f5e3](https://github.com/opentdf/platform/commit/718f5e3aeb98795ec2edd1da5bd41dce24991969))
* **authz:** Move logs containing subject mappings to trace level ([#1635](https://github.com/opentdf/platform/issues/1635)) ([80c117c](https://github.com/opentdf/platform/commit/80c117cbf21dc6ed54acaf5eacb180e1c9bd5540)), closes [#1503](https://github.com/opentdf/platform/issues/1503)
* **core:** Autobump service ([#1611](https://github.com/opentdf/platform/issues/1611)) ([2567052](https://github.com/opentdf/platform/commit/256705261e0c61e9624adf5cc7b9d2ac08581858))
* **core:** Autobump service ([#1624](https://github.com/opentdf/platform/issues/1624)) ([9468479](https://github.com/opentdf/platform/commit/94684795da135f330abdee3d86a17a72e909e5f5))
* **core:** Autobump service ([#1639](https://github.com/opentdf/platform/issues/1639)) ([0551247](https://github.com/opentdf/platform/commit/05512477604d894b9eba3dca137d9960608abf40))
* **core:** Autobump service ([#1654](https://github.com/opentdf/platform/issues/1654)) ([ecf41e9](https://github.com/opentdf/platform/commit/ecf41e9cd0f7d02cfded03053e91fc23884ba452))
* **core:** log audit object as json ([#1612](https://github.com/opentdf/platform/issues/1612)) ([c519ffb](https://github.com/opentdf/platform/commit/c519ffb7a87a2fd21e0e162c1898667815cc7c28))
* Simplify request ID extraction from context for AUDIT ([#1626](https://github.com/opentdf/platform/issues/1626)) ([2f7518c](https://github.com/opentdf/platform/commit/2f7518c3447211106c19ae376f9f700a31ef8f0a))

## [0.4.24](https://github.com/opentdf/platform/compare/service/v0.4.23...service/v0.4.24) (2024-10-01)


### Features

* **ci:** run otdfctl e2e tests within platform ([#1526](https://github.com/opentdf/platform/issues/1526)) ([8240645](https://github.com/opentdf/platform/commit/8240645270e1cd25001c6f40d4276093c6e3cb23)), closes [#1528](https://github.com/opentdf/platform/issues/1528)
* **core:** Ability to add namespace level loggers ([#1537](https://github.com/opentdf/platform/issues/1537)) ([bd57070](https://github.com/opentdf/platform/commit/bd570702952092f05f84f2312a211aa753f3205e))
* **policy:** 1370 add audit support for Resource Mapping Groups ([#1418](https://github.com/opentdf/platform/issues/1418)) ([57dc217](https://github.com/opentdf/platform/commit/57dc21788557f726362ce0fd0351cf6ea12fee2c)), closes [#1370](https://github.com/opentdf/platform/issues/1370)
* **policy:** 1398 add metadata support to Resource Mapping Groups ([#1412](https://github.com/opentdf/platform/issues/1412)) ([87b7b2f](https://github.com/opentdf/platform/commit/87b7b2ff6f7b39d34823ba926758fba25489c0a6))
* **policy:** 1426 tech debt migrate Namespace object queries to sqlc ([#1432](https://github.com/opentdf/platform/issues/1432)) ([6bde0ab](https://github.com/opentdf/platform/commit/6bde0abae4997af4ce9a3556d65d28fa322423e3)), closes [#1426](https://github.com/opentdf/platform/issues/1426)
* **policy:** 1509 add readme on arch decisions of policy service ([#1508](https://github.com/opentdf/platform/issues/1508)) ([71b49ec](https://github.com/opentdf/platform/commit/71b49eca6e84185f85c97b7c490e8f9e89176764)), closes [#1509](https://github.com/opentdf/platform/issues/1509)
* **policy:** 1552 implement recommended changes to audit process ([#1588](https://github.com/opentdf/platform/issues/1588)) ([aabc5cb](https://github.com/opentdf/platform/commit/aabc5cb58979e736657c0c6fd48ae7077e0def5f))
* **policy:** generate policy ERD ([#1525](https://github.com/opentdf/platform/issues/1525)) ([8eb322b](https://github.com/opentdf/platform/commit/8eb322bddccd4eedcea87bfadb9cfd194e0d028f))


### Bug Fixes

* **core:** Add NanoTDF KID padding removal and update logging level ([#1466](https://github.com/opentdf/platform/issues/1466)) ([54de8f4](https://github.com/opentdf/platform/commit/54de8f4e0497e8c587eac06fb5418e9dc3b33e19)), closes [#1467](https://github.com/opentdf/platform/issues/1467)
* **core:** Autobump service ([#1514](https://github.com/opentdf/platform/issues/1514)) ([2b9aa6d](https://github.com/opentdf/platform/commit/2b9aa6d7213ce8c940481bfc3578f672a8b2776b))
* **core:** Autobump service ([#1599](https://github.com/opentdf/platform/issues/1599)) ([93646d7](https://github.com/opentdf/platform/commit/93646d7d2c4f4f09561501aa0013a46688da48f6))
* **core:** Fix parsing /v1/authorization ([#1554](https://github.com/opentdf/platform/issues/1554)) ([b7d694d](https://github.com/opentdf/platform/commit/b7d694d5df3867f278007660c32acb72c868735e)), closes [#1553](https://github.com/opentdf/platform/issues/1553)
* **core:** Fix POST /v1/entitlements body parsing ([#1574](https://github.com/opentdf/platform/issues/1574)) ([fcae7ef](https://github.com/opentdf/platform/commit/fcae7ef0eba2c43ab93f5a2815e7b3e1dec69364))
* **core:** let service start fail if port not free ([#1504](https://github.com/opentdf/platform/issues/1504)) ([708d15d](https://github.com/opentdf/platform/commit/708d15d8d10fc7b253dd22f151ed765222737175))
* **policy:** ensure LIST namespace grants excludes fqns for defs/vals ([#1478](https://github.com/opentdf/platform/issues/1478)) ([243c51c](https://github.com/opentdf/platform/commit/243c51c49b3ca323cabe1cbc07ac33272be38dfd))

## [0.4.23](https://github.com/opentdf/platform/compare/service/v0.4.22...service/v0.4.23) (2024-08-27)


### Bug Fixes

* **core:** Fix flake in nano rewrap ([#1457](https://github.com/opentdf/platform/issues/1457)) ([45b0f90](https://github.com/opentdf/platform/commit/45b0f9000c56d2e76ae35f060eaa6b21ded5deca))
* **main:** Fix deadlock when registering config with duplicate namespace ([#1462](https://github.com/opentdf/platform/issues/1462)) ([6266998](https://github.com/opentdf/platform/commit/6266998b9c17ba64e3396a3379f0d18548593215)), closes [#1461](https://github.com/opentdf/platform/issues/1461)

## [0.4.22](https://github.com/opentdf/platform/compare/service/v0.4.21...service/v0.4.22) (2024-08-26)


### Bug Fixes

* **core:** Don't double encode key fixture ([#1453](https://github.com/opentdf/platform/issues/1453)) ([75f9bb4](https://github.com/opentdf/platform/commit/75f9bb4481eb93fc61954be118d0c16a69be5b94)), closes [#1454](https://github.com/opentdf/platform/issues/1454)
* remove access token log even on failure ([#1452](https://github.com/opentdf/platform/issues/1452)) ([2add657](https://github.com/opentdf/platform/commit/2add657071a679335be8b41440c782883f28fa52))
* stopped logging policy binding ([#1451](https://github.com/opentdf/platform/issues/1451)) ([309dafe](https://github.com/opentdf/platform/commit/309dafe0164a2f4d8125d3def0fbb2267d625d2d))

## [0.4.21](https://github.com/opentdf/platform/compare/service/v0.4.20...service/v0.4.21) (2024-08-23)


### Features

* **core:** KID in NanoTDF KAS ResourceLocator borrowed from Protocol ([#1222](https://github.com/opentdf/platform/issues/1222)) ([e5ee4ef](https://github.com/opentdf/platform/commit/e5ee4efe91bffd9e0310daccf7217d6a797a7cc9))


### Bug Fixes

* **authz:** entitlements fqn casing ([#1446](https://github.com/opentdf/platform/issues/1446)) ([2ffc66b](https://github.com/opentdf/platform/commit/2ffc66b1810e095fbd4779f3e311d40d37b6f83b)), closes [#1359](https://github.com/opentdf/platform/issues/1359)
* **core:** Autobump service ([#1417](https://github.com/opentdf/platform/issues/1417)) ([e6db378](https://github.com/opentdf/platform/commit/e6db378970657e0992199284a199e6099a6e4bf1))
* **core:** Autobump service ([#1441](https://github.com/opentdf/platform/issues/1441)) ([e17deab](https://github.com/opentdf/platform/commit/e17deab15b5177145610ad1cd2048898bfc67c63))
* **core:** Autobump service ([#1449](https://github.com/opentdf/platform/issues/1449)) ([7e443da](https://github.com/opentdf/platform/commit/7e443da08b424dfb239e9afadcbc4be4e4f32ac1))
* **core:** case sensitivity in AccessPDP ([#1439](https://github.com/opentdf/platform/issues/1439)) ([aed7633](https://github.com/opentdf/platform/commit/aed7633190a3c120a0e67c0dc668abf25bc2a0f8)), closes [#1359](https://github.com/opentdf/platform/issues/1359)
* **core:** policy db should use pool connection hook to set search_path ([#1443](https://github.com/opentdf/platform/issues/1443)) ([8501ff5](https://github.com/opentdf/platform/commit/8501ff5488a893d1aad3d24e73994a1556698b63))

## [0.4.20](https://github.com/opentdf/platform/compare/service/v0.4.19...service/v0.4.20) (2024-08-22)


### Bug Fixes

* migration missing conditional ([#1424](https://github.com/opentdf/platform/issues/1424)) ([87efe8d](https://github.com/opentdf/platform/commit/87efe8da2b44d43f1f9ce1a4ea00097911de2e45)), closes [#1423](https://github.com/opentdf/platform/issues/1423)

## [0.4.19](https://github.com/opentdf/platform/compare/service/v0.4.18...service/v0.4.19) (2024-08-20)


### Features

* **core:** add RPCs to namespaces service to handle assignment/removal of KAS grants ([#1344](https://github.com/opentdf/platform/issues/1344)) ([ee47d6c](https://github.com/opentdf/platform/commit/ee47d6cb4576108f0a85a325f41cd43182a2bc73))
* **core:** Adds key ids to kas registry ([#1347](https://github.com/opentdf/platform/issues/1347)) ([e6c76ee](https://github.com/opentdf/platform/commit/e6c76ee415e08ec8681ae4ff8fb9d5d04ea7d2bb))
* **core:** further support in policy for namespace grants ([#1334](https://github.com/opentdf/platform/issues/1334)) ([d56231e](https://github.com/opentdf/platform/commit/d56231ea632c6072613c18cf1fcb9770cedf49e3))
* **core:** support grants to namespaces, definitions, and values in GetAttributeByValueFqns ([#1353](https://github.com/opentdf/platform/issues/1353)) ([42a3d74](https://github.com/opentdf/platform/commit/42a3d747f7271b3861ee210b621a5502b8f07174))
* **core:** validate kas uri ([#1351](https://github.com/opentdf/platform/issues/1351)) ([2b70931](https://github.com/opentdf/platform/commit/2b7093136f6af1b6a86e613c095cefe403c9a06c))
* **policy:** 1277 protos and service methods for Resource Mapping Groups operations ([#1343](https://github.com/opentdf/platform/issues/1343)) ([570f402](https://github.com/opentdf/platform/commit/570f4023183898212dcd007e5b42135ccf1d285a))
* **sdk:** Load KAS keys from policy service ([#1346](https://github.com/opentdf/platform/issues/1346)) ([fe628a0](https://github.com/opentdf/platform/commit/fe628a013e41fb87585eb53a61988f822b40a71a))
* **sdk:** public client and other enhancements to well-known SDK functionality ([#1365](https://github.com/opentdf/platform/issues/1365)) ([3be50a4](https://github.com/opentdf/platform/commit/3be50a4ebf26680fad4ab46620cdfa82340a3da3))


### Bug Fixes

* **authz:** Add http routes for authorization to casbin policy ([#1355](https://github.com/opentdf/platform/issues/1355)) ([3fbaf59](https://github.com/opentdf/platform/commit/3fbaf5968d795ccfb44bd59178a25df4df5eb798))
* **core:** align keycloak provisioning in one command ([#1381](https://github.com/opentdf/platform/issues/1381)) ([c3611d2](https://github.com/opentdf/platform/commit/c3611d2bb3ebd3791de9eecdb97efb36ac43f19d)), closes [#1380](https://github.com/opentdf/platform/issues/1380)
* **core:** align policy kas grant assignments http gateway methods with actions ([#1299](https://github.com/opentdf/platform/issues/1299)) ([031c6ca](https://github.com/opentdf/platform/commit/031c6ca87b8e252a4254f10bfcc78b45e5111ed9))
* **core:** Autobump service ([#1340](https://github.com/opentdf/platform/issues/1340)) ([3414670](https://github.com/opentdf/platform/commit/341467051fc70fe84c627d5cea07f7b111ca0d08))
* **core:** Autobump service ([#1369](https://github.com/opentdf/platform/issues/1369)) ([2ac2378](https://github.com/opentdf/platform/commit/2ac2378f5934066ff9ff22e782adf02baa68f797))
* **core:** Autobump service ([#1403](https://github.com/opentdf/platform/issues/1403)) ([8084e3e](https://github.com/opentdf/platform/commit/8084e3e3b242f36617a5eba2839ab8aee1631287))
* **core:** Autobump service ([#1405](https://github.com/opentdf/platform/issues/1405)) ([74a7f0c](https://github.com/opentdf/platform/commit/74a7f0c2daa988c3a505c9c027575cc00b6ac35a))
* **core:** bump go version to 1.22 ([#1407](https://github.com/opentdf/platform/issues/1407)) ([c696cd1](https://github.com/opentdf/platform/commit/c696cd1144309f28226547ebe26a76259a8e88d3))
* **core:** cleanup sensitive info being logged from configuration ([#1366](https://github.com/opentdf/platform/issues/1366)) ([2b6cf62](https://github.com/opentdf/platform/commit/2b6cf62941075eab30ab9ba71f17be09b05821b6))
* **core:** policy kas grants list (filter params and namespace grants) ([#1342](https://github.com/opentdf/platform/issues/1342)) ([f18ba68](https://github.com/opentdf/platform/commit/f18ba683007a6fa9f3527238596d426931d81d85))
* **core:** policy migrations timestamps merge order ([#1325](https://github.com/opentdf/platform/issues/1325)) ([2bf4290](https://github.com/opentdf/platform/commit/2bf4290b310097c4faf9556064e8a9666e084964))
* **sdk:** align sdk with platform modes ([#1328](https://github.com/opentdf/platform/issues/1328)) ([88ca6f7](https://github.com/opentdf/platform/commit/88ca6f7458930b753756606b670a5c36bddf818c))

## [0.4.18](https://github.com/opentdf/platform/compare/service/v0.4.17...service/v0.4.18) (2024-08-12)


### Features

* **authz:** Remove external ers configuration from authorization ([#1265](https://github.com/opentdf/platform/issues/1265)) ([aa925a8](https://github.com/opentdf/platform/commit/aa925a8ca1cb8cf3c971f2b0463f48444796b7b4))
* **authz:** Typed Entities ([#1249](https://github.com/opentdf/platform/issues/1249)) ([cfab3ad](https://github.com/opentdf/platform/commit/cfab3ad8a72f3a2f1a28ccca988459ddcdcbd7f6))
* **core:** ability to run a set of isolated services ([#1245](https://github.com/opentdf/platform/issues/1245)) ([aa5636a](https://github.com/opentdf/platform/commit/aa5636aff4b842215af4a02d2fea9b7b9397080f))
* **core:** improve entitlements performance  ([#1271](https://github.com/opentdf/platform/issues/1271)) ([f6a1b26](https://github.com/opentdf/platform/commit/f6a1b2673695d2578bd497f223eebf190172da5e))
* **core:** policy support for LIST of kas grants (protos/db) ([#1317](https://github.com/opentdf/platform/issues/1317)) ([599fc56](https://github.com/opentdf/platform/commit/599fc56dbcc3ae8ff2f46584c9bae7c1619a590d))
* **core:** Simplifies support for kidless clients ([#1272](https://github.com/opentdf/platform/issues/1272)) ([dedeb32](https://github.com/opentdf/platform/commit/dedeb3253421870c11300345a1fb6ce8d00fcf6f))
* **policy:** 1256 resource mapping groups db support ([#1270](https://github.com/opentdf/platform/issues/1270)) ([c020e9b](https://github.com/opentdf/platform/commit/c020e9bba2d0fa930d9e4d368e2956116ed356c6))
* **policy:** 1277 add Resource Mapping Group to objects proto ([#1309](https://github.com/opentdf/platform/issues/1309)) ([514f1b8](https://github.com/opentdf/platform/commit/514f1b8e2d6c56056a8258e144380974b1f84d1b)), closes [#1277](https://github.com/opentdf/platform/issues/1277)


### Bug Fixes

* **core:** Autobump service ([#1322](https://github.com/opentdf/platform/issues/1322)) ([9460fb5](https://github.com/opentdf/platform/commit/9460fb56058dadf7941aa316e2e6e89caab6e8af))
* **core:** casbin policy should support assign/remove/deactivate rpc naming ([#1298](https://github.com/opentdf/platform/issues/1298)) ([288921b](https://github.com/opentdf/platform/commit/288921b2c852537ebb9134b95e67964dbc4ee2ad)), closes [#1303](https://github.com/opentdf/platform/issues/1303)
* **core:** put back proto breaking change detection in CI ([#1292](https://github.com/opentdf/platform/issues/1292)) ([9921962](https://github.com/opentdf/platform/commit/9921962ca56954afe5e47bbc68f0461bc1dc28bf)), closes [#1293](https://github.com/opentdf/platform/issues/1293)
* **core:** Update casbin policy for rewrap with unknown role ([#1305](https://github.com/opentdf/platform/issues/1305)) ([de5be3c](https://github.com/opentdf/platform/commit/de5be3cab6c18c8816677cbbed35913bb7090c51))
* **policy:** deprecates and reserves value members from value object in protos ([#1151](https://github.com/opentdf/platform/issues/1151)) ([07fcc9e](https://github.com/opentdf/platform/commit/07fcc9ec93f00beeb863e67d0ca1465c783c2a54))

## [0.4.17](https://github.com/opentdf/platform/compare/service/v0.4.16...service/v0.4.17) (2024-08-06)


### Features

* **authz:** Move ERS call out of rego and include all entities in requests ([#1228](https://github.com/opentdf/platform/issues/1228)) ([cdcca79](https://github.com/opentdf/platform/commit/cdcca79484da1be58687d7ce6bae930a3eae7b21))
* **core:** MIC-934 Moves logger out of internal folder ([#1219](https://github.com/opentdf/platform/issues/1219)) ([0576813](https://github.com/opentdf/platform/commit/05768134db300a06ea2d687f8cec583ef7598fb6))
* **policy:** add support for sqlc within policy db queries ([#1185](https://github.com/opentdf/platform/issues/1185)) ([5aef245](https://github.com/opentdf/platform/commit/5aef245720cb417a51622ffd1276f57163319c6d)), closes [#561](https://github.com/opentdf/platform/issues/561)


### Bug Fixes

* **core:** Autobump service ([#1202](https://github.com/opentdf/platform/issues/1202)) ([98d6d8b](https://github.com/opentdf/platform/commit/98d6d8b84bc72a2d92e7b93dca9f6fa395aaac2e))
* **core:** bump github.com/docker/docker from 25.0.5+incompatible to 26.1.4+incompatible in /service ([#1223](https://github.com/opentdf/platform/issues/1223)) ([937c967](https://github.com/opentdf/platform/commit/937c9675daa7da848223577adf939f721e5a773e))
* **core:** drop unused/deprecated resources table & add comments to policy DB ([#1258](https://github.com/opentdf/platform/issues/1258)) ([bb084aa](https://github.com/opentdf/platform/commit/bb084aad4ac5da071afbe5467b571c2b28227773))
* **core:** improve casbin ExtendDefaultPolicy and add test ([#1234](https://github.com/opentdf/platform/issues/1234)) ([cc15f25](https://github.com/opentdf/platform/commit/cc15f25af2c3e839d7ad45283b7bd298a80e8728))
* **core:** policy subject mapping integration test addition for 'contains' operator ([#1244](https://github.com/opentdf/platform/issues/1244)) ([f8becb8](https://github.com/opentdf/platform/commit/f8becb8911a0d4e9726245ebc51d902cf11e0dd0))

## [0.4.16](https://github.com/opentdf/platform/compare/service/v0.4.15...service/v0.4.16) (2024-07-25)


### Bug Fixes

* log request body on debug ([#1211](https://github.com/opentdf/platform/issues/1211)) ([d2906f0](https://github.com/opentdf/platform/commit/d2906f0e911bb161164a01fbefd8a43db903148a))

## [0.4.15](https://github.com/opentdf/platform/compare/service/v0.4.14...service/v0.4.15) (2024-07-24)


### Bug Fixes

* **core:** set more reasonable message sizes via config ([#1207](https://github.com/opentdf/platform/issues/1207)) ([3e08cba](https://github.com/opentdf/platform/commit/3e08cba232ad5485ff38ad8c095ce2deec55980b))

## [0.4.14](https://github.com/opentdf/platform/compare/service/v0.4.13...service/v0.4.14) (2024-07-24)


### Bug Fixes

* **core:** increase internal grpc message size limit ([#1205](https://github.com/opentdf/platform/issues/1205)) ([1442b59](https://github.com/opentdf/platform/commit/1442b592be8616649451ba64427f045c82ba6668))

## [0.4.13](https://github.com/opentdf/platform/compare/service/v0.4.12...service/v0.4.13) (2024-07-22)


### Features

* **core:** Adds authn time skew config ([#1175](https://github.com/opentdf/platform/issues/1175)) ([adde7c4](https://github.com/opentdf/platform/commit/adde7c48645575cbe57e76b0deb50e6c9b11d192))


### Bug Fixes

* **core:** Autobump service ([#1192](https://github.com/opentdf/platform/issues/1192)) ([dbae4ff](https://github.com/opentdf/platform/commit/dbae4ff4cd4ff53841d123d5086b7fded79efd95))
* fixed policy binding type ([#1184](https://github.com/opentdf/platform/issues/1184)) ([9800a32](https://github.com/opentdf/platform/commit/9800a32c8d9d83458403e2f87720f7882461fc32))

## [0.4.12](https://github.com/opentdf/platform/compare/service/v0.4.11...service/v0.4.12) (2024-07-14)


### Bug Fixes

* **core:** Autobump service ([#1148](https://github.com/opentdf/platform/issues/1148)) ([efd8d30](https://github.com/opentdf/platform/commit/efd8d30975140ecee1e08e031d0a4dc00f4d57ec))
* **core:** Autobump service ([#1156](https://github.com/opentdf/platform/issues/1156)) ([00c05b4](https://github.com/opentdf/platform/commit/00c05b49a7f4b7257f7ac66924936a14be5efd13))
* **core:** Autobump service ([#1159](https://github.com/opentdf/platform/issues/1159)) ([943c7dd](https://github.com/opentdf/platform/commit/943c7ddaf3e0cbb3b9a086df07f292bf636abf57))
* **core:** Fix autoconfigure with no attributes ([#1141](https://github.com/opentdf/platform/issues/1141)) ([76c2a95](https://github.com/opentdf/platform/commit/76c2a95ad7e0c9c57ebde6b101a908fc32fcd539))
* **core:** Reduce casbin logs verbosity ([#1144](https://github.com/opentdf/platform/issues/1144)) ([3e77441](https://github.com/opentdf/platform/commit/3e77441b594b6022cb2fb3c8962f8595566baefe))
* **policy:** mark value members as deprecated within protos ([#1152](https://github.com/opentdf/platform/issues/1152)) ([d18c889](https://github.com/opentdf/platform/commit/d18c8893cdd73344021de638e2d92859a320eed4))
* **policy:** move policy sql logs to trace level to reduce noise ([#1150](https://github.com/opentdf/platform/issues/1150)) ([b0e6ed3](https://github.com/opentdf/platform/commit/b0e6ed395c9c08790b0ecb9d665f5fbb5d976e7f))

## [0.4.11](https://github.com/opentdf/platform/compare/service/v0.4.10...service/v0.4.11) (2024-07-11)


### Features

* **authz:** Keycloak ERS ability to handle clients, users, and emails that dont exist ([#1113](https://github.com/opentdf/platform/issues/1113)) ([4a17f18](https://github.com/opentdf/platform/commit/4a17f18171ee8c557b85118d56a2428482bc6a56))
* **core:** GetEntitlements with_comprehensive_hierarchy ([#1121](https://github.com/opentdf/platform/issues/1121)) ([ac85bf7](https://github.com/opentdf/platform/commit/ac85bf7aef6c9a00bfa0900f6ff3533059ab4bc8)), closes [#1054](https://github.com/opentdf/platform/issues/1054)
* **sdk:** Support custom key splits ([#1038](https://github.com/opentdf/platform/issues/1038)) ([685d8b5](https://github.com/opentdf/platform/commit/685d8b5d7b609744eb6623c52efb27cb40fbc36c))


### Bug Fixes

* **core:** Autobump service ([#1133](https://github.com/opentdf/platform/issues/1133)) ([1a1a64f](https://github.com/opentdf/platform/commit/1a1a64f9511a38ccbc516ad0d6710cccaf9cf741))
* **core:** Autobump service ([#1136](https://github.com/opentdf/platform/issues/1136)) ([baaee4d](https://github.com/opentdf/platform/commit/baaee4df1c8b0b06e0a456267e0dc6ec657b0980))
* **core:** Autobump service ([#1139](https://github.com/opentdf/platform/issues/1139)) ([7da3cb9](https://github.com/opentdf/platform/commit/7da3cb9e3061a560aa254d557109969024d32bdb))
* **kas:** remove unused hostname check ([#1123](https://github.com/opentdf/platform/issues/1123)) ([2909700](https://github.com/opentdf/platform/commit/2909700a67c191bf6d3008219e79a4339a8d592d))

## [0.4.10](https://github.com/opentdf/platform/compare/service/v0.4.9...service/v0.4.10) (2024-07-09)


### Features

* **core:** CONTAINS SubjectMapping Operator ([#1109](https://github.com/opentdf/platform/issues/1109)) ([65cd4af](https://github.com/opentdf/platform/commit/65cd4af366d2d6d17ad72157d5d4d31f6620cc1f))
* **core:** extend authz policy ([#1105](https://github.com/opentdf/platform/issues/1105)) ([b6bf259](https://github.com/opentdf/platform/commit/b6bf259dd20ee02d4f365722f83194d174869e3f)), closes [#1104](https://github.com/opentdf/platform/issues/1104)


### Bug Fixes

* **authz:** move opa out of startup call ([#1048](https://github.com/opentdf/platform/issues/1048)) ([3a0e71a](https://github.com/opentdf/platform/commit/3a0e71a903da5de38b1b5aa95b471cc638814c2e))
* **core:** Autobump service ([#1119](https://github.com/opentdf/platform/issues/1119)) ([bce17e0](https://github.com/opentdf/platform/commit/bce17e0bcd734c52d1cda5c8aca9d842d870dabd))
* **policy:** ensure get requests of attributes and values contain any KAS grants ([#1101](https://github.com/opentdf/platform/issues/1101)) ([87172c9](https://github.com/opentdf/platform/commit/87172c9e4198448b74a310025070848e771bf425))

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
