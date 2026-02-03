# Changelog

## [0.12.0](https://github.com/opentdf/platform/compare/sdk/v0.11.0...sdk/v0.12.0) (2026-01-27)


### ⚠ BREAKING CHANGES

* remove nanotdf support ([#3013](https://github.com/opentdf/platform/issues/3013))

### Features

* **deps:** Bump ocrypto to v0.9.0 ([#3024](https://github.com/opentdf/platform/issues/3024)) ([cd79950](https://github.com/opentdf/platform/commit/cd799509b15516f840436e6af20a14eebaa0556d))
* **sdk:** expose base key API ([#3000](https://github.com/opentdf/platform/issues/3000)) ([67de794](https://github.com/opentdf/platform/commit/67de794721ccb7e5f93454043409dff1619fe42c))


### Bug Fixes

* remove nanotdf support ([#3013](https://github.com/opentdf/platform/issues/3013)) ([90ff7ce](https://github.com/opentdf/platform/commit/90ff7ce50754a1f37ba1cc530507c1f6e15930a0))

## [0.11.0](https://github.com/opentdf/platform/compare/sdk/v0.10.0...sdk/v0.11.0) (2026-01-06)


### Features

* crypto.Signer in assertion signing ([#2956](https://github.com/opentdf/platform/issues/2956)) ([ab36c3a](https://github.com/opentdf/platform/commit/ab36c3a4f4f556dc504320e51216c0d90b848f0f))
* **sdk:** adds configurable max manifest sizes  ([#2906](https://github.com/opentdf/platform/issues/2906)) ([e418a4b](https://github.com/opentdf/platform/commit/e418a4b675f34c0cc3aafbe5ca4c8c9ba93187b5))
* **sdk:** Expose policy binding hash from Nano. ([#2857](https://github.com/opentdf/platform/issues/2857)) ([5221cf4](https://github.com/opentdf/platform/commit/5221cf41079fc43a3966e17c6f3e0d3cf8a16730))
* **sdk:** JWK-based signature verification for assertions ([#2985](https://github.com/opentdf/platform/issues/2985)) ([ef4b5b5](https://github.com/opentdf/platform/commit/ef4b5b5f4dabfe46e126359dc82e6a346d012965))
* Update Go toolchain version to 1.24.11 across all modules ([#2943](https://github.com/opentdf/platform/issues/2943)) ([a960eca](https://github.com/opentdf/platform/commit/a960eca78ab8870599f0aa2a315dbada355adf20))


### Bug Fixes

* **deps:** bump github.com/opentdf/platform/lib/fixtures from 0.3.0 to 0.4.0 in /sdk ([#2962](https://github.com/opentdf/platform/issues/2962)) ([fbb5985](https://github.com/opentdf/platform/commit/fbb598552764438fae94481d3fa653d244a17f41))
* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.7.0 to 0.8.0 in /sdk ([#2975](https://github.com/opentdf/platform/issues/2975)) ([6fc9b46](https://github.com/opentdf/platform/commit/6fc9b468bed1c3632232e5654410957abc68b221))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.13.0 to 0.14.0 in /sdk ([#2963](https://github.com/opentdf/platform/issues/2963)) ([3606421](https://github.com/opentdf/platform/commit/36064212ec7e74962b638e6e675973ad2c75b765))
* **deps:** bump the external group across 1 directory with 5 updates ([#2950](https://github.com/opentdf/platform/issues/2950)) ([6dc3bca](https://github.com/opentdf/platform/commit/6dc3bca01facc22a51293292c337963feabdf417))
* **deps:** bump toolchain to go1.24.9 for CVEs found by govulncheck ([#2849](https://github.com/opentdf/platform/issues/2849)) ([23f76c0](https://github.com/opentdf/platform/commit/23f76c034cfb4c325d868eb96c95ba616e362db4))
* **sdk:** more efficient encryption in experiment TDF Writer ([#2904](https://github.com/opentdf/platform/issues/2904)) ([3ec0518](https://github.com/opentdf/platform/commit/3ec05180ab567e78def51be90b10dd137f3a1f61))
* **sdk:** uses kas sessions key ([#2940](https://github.com/opentdf/platform/issues/2940)) ([736f250](https://github.com/opentdf/platform/commit/736f250bee9ced322aa0e96191d1659db7d1fe79))

## [0.10.0](https://github.com/opentdf/platform/compare/sdk/v0.9.0...sdk/v0.10.0) (2025-10-21)


### Features

* **policy:** Proto - root certificates by namespace ([#2800](https://github.com/opentdf/platform/issues/2800)) ([0edb359](https://github.com/opentdf/platform/commit/0edb3591bc0c12b3ffb47b4e43d19b56dae3d016))
* **policy:** Protos List obligation triggers ([#2803](https://github.com/opentdf/platform/issues/2803)) ([b32df81](https://github.com/opentdf/platform/commit/b32df81f6fe35f9db07e58f49ca71b43d7a02a13))
* **sdk:** Add obligations support. ([#2759](https://github.com/opentdf/platform/issues/2759)) ([3cccfd2](https://github.com/opentdf/platform/commit/3cccfd2929858c394b2a46369e0c2d35cd1cb039))
* **sdk:** Call init if obligations are empty. ([#2825](https://github.com/opentdf/platform/issues/2825)) ([14191e4](https://github.com/opentdf/platform/commit/14191e499d68f669f41f913937c57cbc0e4be42e))


### Bug Fixes

* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.6.0 to 0.7.0 in /sdk ([#2810](https://github.com/opentdf/platform/issues/2810)) ([1c5cf5f](https://github.com/opentdf/platform/commit/1c5cf5f7b4804ed6411992668d45e4c7ba8146c0))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.12.0 to 0.13.0 in /sdk ([#2813](https://github.com/opentdf/platform/issues/2813)) ([1643ed2](https://github.com/opentdf/platform/commit/1643ed238565fb8359d05d96750525ee8557932e))
* **sdk:** Fix the bug in ResourceLocator serialization logic ([#2791](https://github.com/opentdf/platform/issues/2791)) ([01329d6](https://github.com/opentdf/platform/commit/01329d606e6add0905604ed3bdc522c25d303062))

## [0.9.0](https://github.com/opentdf/platform/compare/sdk/v0.8.0...sdk/v0.9.0) (2025-10-09)


### Features

* **sdk:** DSPX-1465 refactor TDF architecture with streaming support and segment-based writing ([#2785](https://github.com/opentdf/platform/issues/2785)) ([ea9b278](https://github.com/opentdf/platform/commit/ea9b278e34e52958990446924e110175ed9a3d6f))
* **sdk:** Experimental zipstream lib, add segment-based streaming ZIP writer, ZIP64 modes ([#2782](https://github.com/opentdf/platform/issues/2782)) ([b381179](https://github.com/opentdf/platform/commit/b381179119bca67ef19a935771b5a2efb5f6823a))
* **sdk:** sdk should optionally take in a logger ([#2754](https://github.com/opentdf/platform/issues/2754)) ([f40d05f](https://github.com/opentdf/platform/commit/f40d05ff24aa7ff4270f206c4e3efc13125ec284))


### Bug Fixes

* **core:** deprecate policy WithValue selector not utilized by RPC ([#2794](https://github.com/opentdf/platform/issues/2794)) ([c573595](https://github.com/opentdf/platform/commit/c573595aba6c0e5223fc7fd924840c1bf34cd895))

## [0.8.0](https://github.com/opentdf/platform/compare/sdk/v0.7.0...sdk/v0.8.0) (2025-09-19)


### Features

* **policy:** obligations + values CRUD ([#2545](https://github.com/opentdf/platform/issues/2545)) ([c194e35](https://github.com/opentdf/platform/commit/c194e3522b9dfab74a5a21747d012f88a188f989))


### Bug Fixes

* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.3.0 to 0.5.0 in /sdk ([#2693](https://github.com/opentdf/platform/issues/2693)) ([b511048](https://github.com/opentdf/platform/commit/b5110481d28e05c0e1fd3b2bf6074d7f096a0356))
* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.5.0 to 0.6.0 in /sdk ([#2712](https://github.com/opentdf/platform/issues/2712)) ([74956bf](https://github.com/opentdf/platform/commit/74956bf58822eba432e746374a60b51fdc43cded))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.7.0 to 0.8.0 in /sdk ([#2692](https://github.com/opentdf/platform/issues/2692)) ([fac2ef2](https://github.com/opentdf/platform/commit/fac2ef2a1dcbb4ee1e4ca5a2638febebf9f343f5))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.8.0 to 0.9.0 in /sdk ([#2724](https://github.com/opentdf/platform/issues/2724)) ([e07cc91](https://github.com/opentdf/platform/commit/e07cc916460daa24db24969cef8ecd36bec4d6a4))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.9.0 to 0.10.0 in /sdk ([#2737](https://github.com/opentdf/platform/issues/2737)) ([f4a8d1d](https://github.com/opentdf/platform/commit/f4a8d1df1ddf1869cac750de344ae14710f70b1d))
* **sdk:** newGranter nil check ([#2729](https://github.com/opentdf/platform/issues/2729)) ([a1bebc5](https://github.com/opentdf/platform/commit/a1bebc509083d27cd6e920e7305606ae2d8bf12b))

## [0.7.0](https://github.com/opentdf/platform/compare/sdk/v0.6.1...sdk/v0.7.0) (2025-08-25)


### ⚠ BREAKING CHANGES

* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979))

### Features

* add system metadata assertions to TDFConfig ([#2446](https://github.com/opentdf/platform/issues/2446)) ([4eb9fff](https://github.com/opentdf/platform/commit/4eb9fff910ff5b3dd267b9017a1f2ca12133a264))
* **authz:** authz v2 versioning implementation ([#2173](https://github.com/opentdf/platform/issues/2173)) ([557fc21](https://github.com/opentdf/platform/commit/557fc2148dae9508a8c7f1088bdcf799bd00b794))
* **core:** adds bulk rewrap to sdk and service ([#1835](https://github.com/opentdf/platform/issues/1835)) ([11698ae](https://github.com/opentdf/platform/commit/11698ae18f66282980a7822dd145e3896c2b605c))
* **core:** Adds EC withSalt options ([#2126](https://github.com/opentdf/platform/issues/2126)) ([67b6fb8](https://github.com/opentdf/platform/commit/67b6fb8fc1263a4ddfa8ae1c8d451db50be77988))
* **core:** Adds ErrInvalidPerSchema ([#1860](https://github.com/opentdf/platform/issues/1860)) ([456639e](https://github.com/opentdf/platform/commit/456639e0bfbffc93b08ec1cea9dfb7d6feb3529d))
* **core:** DSPX-608 - Deprecate public_client_id ([#2185](https://github.com/opentdf/platform/issues/2185)) ([0f58efa](https://github.com/opentdf/platform/commit/0f58efab4e99005b73041444d31b1c348b9e2834))
* **core:** EXPERIMENTAL: EC-wrapped key support ([#1902](https://github.com/opentdf/platform/issues/1902)) ([652266f](https://github.com/opentdf/platform/commit/652266f212ba10b2492a84741f68391a1d39e007))
* **core:** Expose version info ([#1841](https://github.com/opentdf/platform/issues/1841)) ([92a9f5e](https://github.com/opentdf/platform/commit/92a9f5eab3f2372990b86df6a22ad209eed1a0f9))
* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979)) ([164c922](https://github.com/opentdf/platform/commit/164c922af74b1265fe487362c356abb7f1503ada))
* **core:** v2 ERS with proto updates ([#2210](https://github.com/opentdf/platform/issues/2210)) ([a161ef8](https://github.com/opentdf/platform/commit/a161ef85d12600672ff695cc84b07579a70c5cac))
* **policy:** actions service RPCs should actually hit storage layer CRUD ([#2063](https://github.com/opentdf/platform/issues/2063)) ([da4faf5](https://github.com/opentdf/platform/commit/da4faf5d8410c37180205ac9bad44436c88207e4))
* **policy:** Add list key mappings rpc. ([#2533](https://github.com/opentdf/platform/issues/2533)) ([fbc2724](https://github.com/opentdf/platform/commit/fbc2724a066b5e4121838a958cb926a1ab5bdcde))
* **policy:** adds new public keys table ([#1836](https://github.com/opentdf/platform/issues/1836)) ([cad5048](https://github.com/opentdf/platform/commit/cad5048d09609d678d5b5ac2972605dd61f33bb5))
* **policy:** Allow the deletion of a key. ([#2575](https://github.com/opentdf/platform/issues/2575)) ([82b96f0](https://github.com/opentdf/platform/commit/82b96f023662c0a6c76af6d1196f78ab28a6acf0))
* **policy:** Default Platform Keys ([#2254](https://github.com/opentdf/platform/issues/2254)) ([d7447fe](https://github.com/opentdf/platform/commit/d7447fe2604443b4c75c8e547acf414bf78af988))
* **policy:** DSPX-902 NDR service crud implementation (2/2) ([#2066](https://github.com/opentdf/platform/issues/2066)) ([030ad33](https://github.com/opentdf/platform/commit/030ad33b5f94767279181d8748f00d3515b88eaf))
* **policy:** key management crud ([#2110](https://github.com/opentdf/platform/issues/2110)) ([4c3d53d](https://github.com/opentdf/platform/commit/4c3d53d5fbb6f4659155ac60d289d92ac20180f1))
* **sdk:** Add a KAS allowlist ([#2085](https://github.com/opentdf/platform/issues/2085)) ([d7cfdf3](https://github.com/opentdf/platform/commit/d7cfdf376681eab9becc0b5be863379a3182f410))
* **sdk:** add nanotdf plaintext policy ([#2182](https://github.com/opentdf/platform/issues/2182)) ([e5c56db](https://github.com/opentdf/platform/commit/e5c56db5c962d6ff21e7346198f01558489adf3f))
* **sdk:** adds seeker interface to TDF Reader ([#2385](https://github.com/opentdf/platform/issues/2385)) ([63ccd9a](https://github.com/opentdf/platform/commit/63ccd9aa89060209ca0bb3911bc092af9467e986))
* **sdk:** Allow key splits with same algo ([#2454](https://github.com/opentdf/platform/issues/2454)) ([7422b15](https://github.com/opentdf/platform/commit/7422b15d529bd9a32cccbb67c47d7a25a41b9bde))
* **sdk:** Allow schema validation during TDF decrypt ([#1870](https://github.com/opentdf/platform/issues/1870)) ([b7e6fb2](https://github.com/opentdf/platform/commit/b7e6fb24631b4898561b1a64c24c85b32c452a1c))
* **sdk:** autoconfig kaos with kids ([#2438](https://github.com/opentdf/platform/issues/2438)) ([c272016](https://github.com/opentdf/platform/commit/c2720163957dbbc4ddb79222fb8ed6883e830e69))
* **sdk:** bump protocol/go v0.6.0 ([#2536](https://github.com/opentdf/platform/issues/2536)) ([23e4c2b](https://github.com/opentdf/platform/commit/23e4c2b0b41db368482f52cbc39331b05fe23462))
* **sdk:** CreateTDF option to run with specific target schema version ([#2045](https://github.com/opentdf/platform/issues/2045)) ([0976b15](https://github.com/opentdf/platform/commit/0976b15f9a78509350ecc49a514e2d5028059117))
* **sdk:** Enable base key support. ([#2425](https://github.com/opentdf/platform/issues/2425)) ([9ff3806](https://github.com/opentdf/platform/commit/9ff38064abf4c62f929c53bbed7acf3ad1d751fe))
* **sdk:** Expose connectrpc wrapper codegen for re-use ([#2322](https://github.com/opentdf/platform/issues/2322)) ([8b29392](https://github.com/opentdf/platform/commit/8b2939288395cd4eea2e7b2aa7e9c02ecaac3ccd))
* **sdk:** MIC-1436: User can decrypt TDF files created with FileWatcher2.0.8 and older. ([#1833](https://github.com/opentdf/platform/issues/1833)) ([f77d110](https://github.com/opentdf/platform/commit/f77d110fcc7f332ceec5a3294b144973eced37c1))
* **sdk:** remove hex encoding for segment hash ([#1805](https://github.com/opentdf/platform/issues/1805)) ([d7179c2](https://github.com/opentdf/platform/commit/d7179c2a91b508c26fbe6499fe5c1ac8334e5505))
* **sdk:** sdk.New should validate platform connectivity and provide precise error ([#1937](https://github.com/opentdf/platform/issues/1937)) ([aa3696d](https://github.com/opentdf/platform/commit/aa3696d848a23ac79029bd64f1b61a15567204d7))
* **sdk:** Use ConnectRPC in the go client ([#2200](https://github.com/opentdf/platform/issues/2200)) ([fc34ee6](https://github.com/opentdf/platform/commit/fc34ee6293dfb9192d48784daaff34d26eaacd1d))


### Bug Fixes

* Allow parsing IPs as hostnames ([#1999](https://github.com/opentdf/platform/issues/1999)) ([d54b550](https://github.com/opentdf/platform/commit/d54b550a889a55fe19cc79988cb2fc030860514a))
* **ci:** Fix intermittent failures from auth tests ([#2345](https://github.com/opentdf/platform/issues/2345)) ([395988a](https://github.com/opentdf/platform/commit/395988acf615d722638efd2ceb234c38aec03821))
* **ci:** Update expired ca and certs in oauth unit tests ([#2113](https://github.com/opentdf/platform/issues/2113)) ([5440fcc](https://github.com/opentdf/platform/commit/5440fccf100c5eea14927f8dbe4589ab6c3311f0))
* **core:** Autobump sdk ([#1863](https://github.com/opentdf/platform/issues/1863)) ([855cb2b](https://github.com/opentdf/platform/commit/855cb2b779b04d927ebdf8bfe8af589c186f95eb))
* **core:** Autobump sdk ([#1873](https://github.com/opentdf/platform/issues/1873)) ([085ac7a](https://github.com/opentdf/platform/commit/085ac7af550d2c9d3fd0b0b2deb389939e7cde8e))
* **core:** Autobump sdk ([#1894](https://github.com/opentdf/platform/issues/1894)) ([201244e](https://github.com/opentdf/platform/commit/201244e4473115f07fc997dc49c695cc05d9a6ba))
* **core:** Autobump sdk ([#1917](https://github.com/opentdf/platform/issues/1917)) ([edeeb74](https://github.com/opentdf/platform/commit/edeeb74e9c38b2e6eef7fefa29768912371ec949))
* **core:** Autobump sdk ([#1941](https://github.com/opentdf/platform/issues/1941)) ([0a5a948](https://github.com/opentdf/platform/commit/0a5a94893836482990586302bfb9838e54c5b6ba))
* **core:** Autobump sdk ([#1948](https://github.com/opentdf/platform/issues/1948)) ([4dfb457](https://github.com/opentdf/platform/commit/4dfb45780ef5a42d95405a8ad09421a21c9cd149))
* **core:** Autobump sdk ([#1968](https://github.com/opentdf/platform/issues/1968)) ([7084061](https://github.com/opentdf/platform/commit/7084061da604c7c1a37cc91b50141436ff7d2595))
* **core:** Autobump sdk ([#1972](https://github.com/opentdf/platform/issues/1972)) ([7258f5d](https://github.com/opentdf/platform/commit/7258f5d4b45c37ef035ec7659747d6615ea8d54f))
* **core:** Autobump sdk ([#2102](https://github.com/opentdf/platform/issues/2102)) ([0315635](https://github.com/opentdf/platform/commit/03156357f4cadabaf169be7cb5df07737b0af818))
* **core:** Fixes protoJSON parse bug on ec rewrap ([#1943](https://github.com/opentdf/platform/issues/1943)) ([9bebfd0](https://github.com/opentdf/platform/commit/9bebfd01f615f5a438e0695c03dbb1a9ad7badf3))
* **core:** Improves errors when under heavy load ([#2132](https://github.com/opentdf/platform/issues/2132)) ([4490a14](https://github.com/opentdf/platform/commit/4490a14db2492629e287445df26312eb3e363b81))
* **core:** Update fixtures and flattening in sdk and service ([#1827](https://github.com/opentdf/platform/issues/1827)) ([d6d6a7a](https://github.com/opentdf/platform/commit/d6d6a7a2dffdb96cf7f7f731a4e6e66e06930e59))
* **core:** Updates ec-wrapped to newer salt ([#1961](https://github.com/opentdf/platform/issues/1961)) ([0e17968](https://github.com/opentdf/platform/commit/0e17968e4bd4e69ddf7f676733327d6f0e0e36f0))
* **deps:** bump github.com/docker/docker from 28.2.2+incompatible to 28.3.3+incompatible in /sdk ([#2597](https://github.com/opentdf/platform/issues/2597)) ([a68d00d](https://github.com/opentdf/platform/commit/a68d00dca7dd8e506b2d0fe640aaf67c3e86996d))
* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.2.0 to 0.3.0 in /sdk ([#2502](https://github.com/opentdf/platform/issues/2502)) ([3ec8b35](https://github.com/opentdf/platform/commit/3ec8b3577982796c9ce6e02deaa7cf91358641d2))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.3.6 to 0.4.0 in /sdk ([#2397](https://github.com/opentdf/platform/issues/2397)) ([99e3aa4](https://github.com/opentdf/platform/commit/99e3aa4600ae503142ed81c9a483b1b75d950713))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.4.0 to 0.5.0 in /sdk ([#2471](https://github.com/opentdf/platform/issues/2471)) ([e8f97e0](https://github.com/opentdf/platform/commit/e8f97e083fdd08c6cea24e6cf0c2b4f32309b6bf))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.5.0 to 0.5.1 in /sdk ([#2505](https://github.com/opentdf/platform/issues/2505)) ([4edab72](https://github.com/opentdf/platform/commit/4edab72fa06c182c987d2b85fba3f5efea251ce4))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.6.0 to 0.6.2 in /sdk ([#2586](https://github.com/opentdf/platform/issues/2586)) ([4ed9856](https://github.com/opentdf/platform/commit/4ed98561d503646c83c7dbc9fbdd0ab847e1c58e))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.6.2 to 0.7.0 in /sdk ([#2627](https://github.com/opentdf/platform/issues/2627)) ([e775e14](https://github.com/opentdf/platform/commit/e775e143eec3f31f32c2b11e2346cea5be83dbb3))
* **deps:** bump golang.org/x/oauth2 from 0.26.0 to 0.30.0 in /sdk ([#2252](https://github.com/opentdf/platform/issues/2252)) ([9b775a2](https://github.com/opentdf/platform/commit/9b775a23488861a8ab0ada848e59e53552f12e7f))
* **deps:** bump google.golang.org/grpc from 1.71.0 to 1.72.1 in /sdk ([#2244](https://github.com/opentdf/platform/issues/2244)) ([49484e0](https://github.com/opentdf/platform/commit/49484e0b009db511fbc53fbebb8d45ca173f96ec))
* **deps:** bump the external group across 1 directory with 5 updates ([#2400](https://github.com/opentdf/platform/issues/2400)) ([0b7ea79](https://github.com/opentdf/platform/commit/0b7ea79516352923f291047074ec27bcae74381d))
* **deps:** bump toolchain in /lib/fixtures and /examples to resolve CVE GO-2025-3563 ([#2061](https://github.com/opentdf/platform/issues/2061)) ([9c16843](https://github.com/opentdf/platform/commit/9c168437db3b138613fe629419dd6bd9f837e881))
* Improve http.Client usage for security and performance ([#1910](https://github.com/opentdf/platform/issues/1910)) ([e6a53a3](https://github.com/opentdf/platform/commit/e6a53a370b13c3ed63752789aa886be660354e1a))
* **sdk:** adds connection options to getPlatformConfiguration ([#2286](https://github.com/opentdf/platform/issues/2286)) ([a3af31e](https://github.com/opentdf/platform/commit/a3af31e52daf795a733bb02397e2e618bb5dbddd))
* **sdk:** Allow reuse of session key ([#2016](https://github.com/opentdf/platform/issues/2016)) ([d48c11e](https://github.com/opentdf/platform/commit/d48c11e6e429638662e03dcc2c4ae37bedd0521c))
* **sdk:** bump lib/ocrypto to 0.1.8 ([#1938](https://github.com/opentdf/platform/issues/1938)) ([53fa8ab](https://github.com/opentdf/platform/commit/53fa8ab90236d5bd29541552782b60b96f625405))
* **sdk:** bump protocol/go module dependencies ([#2078](https://github.com/opentdf/platform/issues/2078)) ([e027f43](https://github.com/opentdf/platform/commit/e027f431aaf989f76bb46ded8d0243dfad46b048))
* **sdk:** Display proper error on kas rewrap failure ([#2081](https://github.com/opentdf/platform/issues/2081)) ([508cbcd](https://github.com/opentdf/platform/commit/508cbcde80310c2a35b8fe69b110600a7078301c))
* **sdk:** everything is `mixedSplits` now ([#1861](https://github.com/opentdf/platform/issues/1861)) ([ba78f14](https://github.com/opentdf/platform/commit/ba78f142e94330ed66d45a9b43640fbcf2c98d22))
* **sdk:** Fix compatibility between bulk and non-bulk rewrap ([#1914](https://github.com/opentdf/platform/issues/1914)) ([74abbb6](https://github.com/opentdf/platform/commit/74abbb66cbb39023f56cd502a7cda294580a41c6))
* **sdk:** Fixed token expiration time ([#1854](https://github.com/opentdf/platform/issues/1854)) ([c3cda1b](https://github.com/opentdf/platform/commit/c3cda1b877ed588ac52dca09c74775a5d9fd63ca))
* **sdk:** perfsprint lint issues ([#2208](https://github.com/opentdf/platform/issues/2208)) ([d36a078](https://github.com/opentdf/platform/commit/d36a078433a384418eee51b5bceb511cc9f6619e))
* **sdk:** Prefer KID and Algorithm selection from key maps ([#2475](https://github.com/opentdf/platform/issues/2475)) ([98fd392](https://github.com/opentdf/platform/commit/98fd39230a3cc4bfa5ff5ffc1742dd5d15eaeb1c))
* **sdk:** Removes unnecessary down-cast of `int` ([#1869](https://github.com/opentdf/platform/issues/1869)) ([66f0c14](https://github.com/opentdf/platform/commit/66f0c14a1ef7490a207c0cef8c98ab4af3f128b1))
* **sdk:** Version config fix ([#1847](https://github.com/opentdf/platform/issues/1847)) ([be5d817](https://github.com/opentdf/platform/commit/be5d81777c08264d7fec80064b86a02bc4532229))
* Service utilize `httputil.SafeHttpClient` ([#1926](https://github.com/opentdf/platform/issues/1926)) ([af32700](https://github.com/opentdf/platform/commit/af32700d37af4a8b2b354aefad56f05781e4ecd1))
* set consistent system metadata id and schema ([#2451](https://github.com/opentdf/platform/issues/2451)) ([5db3cf2](https://github.com/opentdf/platform/commit/5db3cf2c8ba3ef187e64740c183a8d5ec3c2397b))

## [0.6.1](https://github.com/opentdf/platform/compare/sdk/v0.6.0...sdk/v0.6.1) (2025-07-28)

### Bug Fixes

* **deps:** bump github.com/opentdf/platform/protocol/go from 0.6.0 to 0.6.2 in /sdk [backport to release/sdk/v0.6] ([#2588](https://github.com/opentdf/platform/issues/2588)) ([b42c254](https://github.com/opentdf/platform/commit/b42c2541bb9e8519c31549a9e151bdea042d210f))

## [0.6.0](https://github.com/opentdf/platform/compare/sdk/v0.5.0...sdk/v0.6.0) (2025-07-09)

### Features

* **policy:** Add list key mappings rpc. ([#2533](https://github.com/opentdf/platform/issues/2533)) ([fbc2724](https://github.com/opentdf/platform/commit/fbc2724a066b5e4121838a958cb926a1ab5bdcde))
* **sdk:** bump protocol/go v0.6.0 ([#2536](https://github.com/opentdf/platform/issues/2536)) ([23e4c2b](https://github.com/opentdf/platform/commit/23e4c2b0b41db368482f52cbc39331b05fe23462))

### Bug Fixes

* **deps:** bump github.com/opentdf/platform/lib/ocrypto from 0.2.0 to 0.3.0 in /sdk ([#2502](https://github.com/opentdf/platform/issues/2502)) ([3ec8b35](https://github.com/opentdf/platform/commit/3ec8b3577982796c9ce6e02deaa7cf91358641d2))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.5.0 to 0.5.1 in /sdk ([#2505](https://github.com/opentdf/platform/issues/2505)) ([4edab72](https://github.com/opentdf/platform/commit/4edab72fa06c182c987d2b85fba3f5efea251ce4))
* **sdk:** Prefer KID and Algorithm selection from key maps ([#2475](https://github.com/opentdf/platform/issues/2475)) ([98fd392](https://github.com/opentdf/platform/commit/98fd39230a3cc4bfa5ff5ffc1742dd5d15eaeb1c))

## [0.5.0](https://github.com/opentdf/platform/compare/sdk/v0.4.7...sdk/v0.5.0) (2025-06-23)

### Features

* add system metadata assertions to TDFConfig ([#2446](https://github.com/opentdf/platform/issues/2446)) ([4eb9fff](https://github.com/opentdf/platform/commit/4eb9fff910ff5b3dd267b9017a1f2ca12133a264))
* **core:** DSPX-608 - Deprecate public_client_id ([#2185](https://github.com/opentdf/platform/issues/2185)) ([0f58efa](https://github.com/opentdf/platform/commit/0f58efab4e99005b73041444d31b1c348b9e2834))
* **sdk:** adds seeker interface to TDF Reader ([#2385](https://github.com/opentdf/platform/issues/2385)) ([63ccd9a](https://github.com/opentdf/platform/commit/63ccd9aa89060209ca0bb3911bc092af9467e986))
* **sdk:** Allow key splits with same algo ([#2454](https://github.com/opentdf/platform/issues/2454)) ([7422b15](https://github.com/opentdf/platform/commit/7422b15d529bd9a32cccbb67c47d7a25a41b9bde))
* **sdk:** autoconfig kaos with kids ([#2438](https://github.com/opentdf/platform/issues/2438)) ([c272016](https://github.com/opentdf/platform/commit/c2720163957dbbc4ddb79222fb8ed6883e830e69))
* **sdk:** Enable base key support. ([#2425](https://github.com/opentdf/platform/issues/2425)) ([9ff3806](https://github.com/opentdf/platform/commit/9ff38064abf4c62f929c53bbed7acf3ad1d751fe))

### Bug Fixes

* **ci:** Fix intermittent failures from auth tests ([#2345](https://github.com/opentdf/platform/issues/2345)) ([395988a](https://github.com/opentdf/platform/commit/395988acf615d722638efd2ceb234c38aec03821))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.3.6 to 0.4.0 in /sdk ([#2397](https://github.com/opentdf/platform/issues/2397)) ([99e3aa4](https://github.com/opentdf/platform/commit/99e3aa4600ae503142ed81c9a483b1b75d950713))
* **deps:** bump github.com/opentdf/platform/protocol/go from 0.4.0 to 0.5.0 in /sdk ([#2471](https://github.com/opentdf/platform/issues/2471)) ([e8f97e0](https://github.com/opentdf/platform/commit/e8f97e083fdd08c6cea24e6cf0c2b4f32309b6bf))
* **deps:** bump the external group across 1 directory with 5 updates ([#2400](https://github.com/opentdf/platform/issues/2400)) ([0b7ea79](https://github.com/opentdf/platform/commit/0b7ea79516352923f291047074ec27bcae74381d))
* set consistent system metadata id and schema ([#2451](https://github.com/opentdf/platform/issues/2451)) ([5db3cf2](https://github.com/opentdf/platform/commit/5db3cf2c8ba3ef187e64740c183a8d5ec3c2397b))

## [0.4.7](https://github.com/opentdf/platform/compare/sdk/v0.4.6...sdk/v0.4.7) (2025-05-29)

### Features

* **sdk:** Expose connectrpc wrapper codegen for re-use ([#2322](https://github.com/opentdf/platform/issues/2322)) ([8b29392](https://github.com/opentdf/platform/commit/8b2939288395cd4eea2e7b2aa7e9c02ecaac3ccd))

## [0.4.6](https://github.com/opentdf/platform/compare/sdk/v0.4.5...sdk/v0.4.6) (2025-05-28)

### Features

* **policy:** Default Platform Keys ([#2254](https://github.com/opentdf/platform/issues/2254)) ([d7447fe](https://github.com/opentdf/platform/commit/d7447fe2604443b4c75c8e547acf414bf78af988))

## [0.4.5](https://github.com/opentdf/platform/compare/sdk/v0.4.4...sdk/v0.4.5) (2025-05-22)

### Features

* **authz:** authz v2 versioning implementation ([#2173](https://github.com/opentdf/platform/issues/2173)) ([557fc21](https://github.com/opentdf/platform/commit/557fc2148dae9508a8c7f1088bdcf799bd00b794))
* **core:** Adds EC withSalt options ([#2126](https://github.com/opentdf/platform/issues/2126)) ([67b6fb8](https://github.com/opentdf/platform/commit/67b6fb8fc1263a4ddfa8ae1c8d451db50be77988))
* **core:** v2 ERS with proto updates ([#2210](https://github.com/opentdf/platform/issues/2210)) ([a161ef8](https://github.com/opentdf/platform/commit/a161ef85d12600672ff695cc84b07579a70c5cac))
* **policy:** key management crud ([#2110](https://github.com/opentdf/platform/issues/2110)) ([4c3d53d](https://github.com/opentdf/platform/commit/4c3d53d5fbb6f4659155ac60d289d92ac20180f1))
* **sdk:** add nanotdf plaintext policy ([#2182](https://github.com/opentdf/platform/issues/2182)) ([e5c56db](https://github.com/opentdf/platform/commit/e5c56db5c962d6ff21e7346198f01558489adf3f))
* **sdk:** Use ConnectRPC in the go client ([#2200](https://github.com/opentdf/platform/issues/2200)) ([fc34ee6](https://github.com/opentdf/platform/commit/fc34ee6293dfb9192d48784daaff34d26eaacd1d))

### Bug Fixes

* **core:** Improves errors when under heavy load ([#2132](https://github.com/opentdf/platform/issues/2132)) ([4490a14](https://github.com/opentdf/platform/commit/4490a14db2492629e287445df26312eb3e363b81))
* **deps:** bump golang.org/x/oauth2 from 0.26.0 to 0.30.0 in /sdk ([#2252](https://github.com/opentdf/platform/issues/2252)) ([9b775a2](https://github.com/opentdf/platform/commit/9b775a23488861a8ab0ada848e59e53552f12e7f))
* **deps:** bump google.golang.org/grpc from 1.71.0 to 1.72.1 in /sdk ([#2244](https://github.com/opentdf/platform/issues/2244)) ([49484e0](https://github.com/opentdf/platform/commit/49484e0b009db511fbc53fbebb8d45ca173f96ec))
* **sdk:** adds connection options to getPlatformConfiguration ([#2286](https://github.com/opentdf/platform/issues/2286)) ([a3af31e](https://github.com/opentdf/platform/commit/a3af31e52daf795a733bb02397e2e618bb5dbddd))
* **sdk:** perfsprint lint issues ([#2208](https://github.com/opentdf/platform/issues/2208)) ([d36a078](https://github.com/opentdf/platform/commit/d36a078433a384418eee51b5bceb511cc9f6619e))

## [0.4.4](https://github.com/opentdf/platform/compare/sdk/v0.4.3...sdk/v0.4.4) (2025-04-28)

### Features

* **sdk:** Add a KAS allowlist ([#2085](https://github.com/opentdf/platform/issues/2085)) ([d7cfdf3](https://github.com/opentdf/platform/commit/d7cfdf376681eab9becc0b5be863379a3182f410))

### Bug Fixes

* **ci:** Update expired ca and certs in oauth unit tests ([#2113](https://github.com/opentdf/platform/issues/2113)) ([5440fcc](https://github.com/opentdf/platform/commit/5440fccf100c5eea14927f8dbe4589ab6c3311f0))

## [0.4.3](https://github.com/opentdf/platform/compare/sdk/v0.4.2...sdk/v0.4.3) (2025-04-23)

### Features

* **policy:** actions service RPCs should actually hit storage layer CRUD ([#2063](https://github.com/opentdf/platform/issues/2063)) ([da4faf5](https://github.com/opentdf/platform/commit/da4faf5d8410c37180205ac9bad44436c88207e4))
* **policy:** DSPX-902 NDR service crud implementation (2/2) ([#2066](https://github.com/opentdf/platform/issues/2066)) ([030ad33](https://github.com/opentdf/platform/commit/030ad33b5f94767279181d8748f00d3515b88eaf))

### Bug Fixes

* **core:** Autobump sdk ([#2102](https://github.com/opentdf/platform/issues/2102)) ([0315635](https://github.com/opentdf/platform/commit/03156357f4cadabaf169be7cb5df07737b0af818))
* **sdk:** Display proper error on kas rewrap failure ([#2081](https://github.com/opentdf/platform/issues/2081)) ([508cbcd](https://github.com/opentdf/platform/commit/508cbcde80310c2a35b8fe69b110600a7078301c))

## [0.4.2](https://github.com/opentdf/platform/compare/sdk/v0.4.1...sdk/v0.4.2) (2025-04-17)

### Bug Fixes

* **deps:** bump toolchain in /lib/fixtures and /examples to resolve CVE GO-2025-3563 ([#2061](https://github.com/opentdf/platform/issues/2061)) ([9c16843](https://github.com/opentdf/platform/commit/9c168437db3b138613fe629419dd6bd9f837e881))
* **sdk:** bump protocol/go module dependencies ([#2078](https://github.com/opentdf/platform/issues/2078)) ([e027f43](https://github.com/opentdf/platform/commit/e027f431aaf989f76bb46ded8d0243dfad46b048))

## [0.4.1](https://github.com/opentdf/platform/compare/sdk/v0.4.0...sdk/v0.4.1) (2025-04-07)

### Features

* **sdk:** CreateTDF option to run with specific target schema version ([#2045](https://github.com/opentdf/platform/issues/2045)) ([0976b15](https://github.com/opentdf/platform/commit/0976b15f9a78509350ecc49a514e2d5028059117))

## [0.4.0](https://github.com/opentdf/platform/compare/sdk/v0.3.29...sdk/v0.4.0) (2025-04-01)

### ⚠ BREAKING CHANGES

* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979))

### Features

* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979)) ([164c922](https://github.com/opentdf/platform/commit/164c922af74b1265fe487362c356abb7f1503ada))

### Bug Fixes

* Allow parsing IPs as hostnames ([#1999](https://github.com/opentdf/platform/issues/1999)) ([d54b550](https://github.com/opentdf/platform/commit/d54b550a889a55fe19cc79988cb2fc030860514a))
* **sdk:** Allow reuse of session key ([#2016](https://github.com/opentdf/platform/issues/2016)) ([d48c11e](https://github.com/opentdf/platform/commit/d48c11e6e429638662e03dcc2c4ae37bedd0521c))

## [0.3.29](https://github.com/opentdf/platform/compare/sdk/v0.3.28...sdk/v0.3.29) (2025-03-08)

### Bug Fixes

* **core:** Autobump sdk ([#1968](https://github.com/opentdf/platform/issues/1968)) ([7084061](https://github.com/opentdf/platform/commit/7084061da604c7c1a37cc91b50141436ff7d2595))
* **core:** Autobump sdk ([#1972](https://github.com/opentdf/platform/issues/1972)) ([7258f5d](https://github.com/opentdf/platform/commit/7258f5d4b45c37ef035ec7659747d6615ea8d54f))
* **core:** Updates ec-wrapped to newer salt ([#1961](https://github.com/opentdf/platform/issues/1961)) ([0e17968](https://github.com/opentdf/platform/commit/0e17968e4bd4e69ddf7f676733327d6f0e0e36f0))
* Service utilize `httputil.SafeHttpClient` ([#1926](https://github.com/opentdf/platform/issues/1926)) ([af32700](https://github.com/opentdf/platform/commit/af32700d37af4a8b2b354aefad56f05781e4ecd1))

## [0.3.28](https://github.com/opentdf/platform/compare/sdk/v0.3.27...sdk/v0.3.28) (2025-02-26)

### Bug Fixes

* **core:** Autobump sdk ([#1948](https://github.com/opentdf/platform/issues/1948)) ([4dfb457](https://github.com/opentdf/platform/commit/4dfb45780ef5a42d95405a8ad09421a21c9cd149))
* **core:** Fixes protoJSON parse bug on ec rewrap ([#1943](https://github.com/opentdf/platform/issues/1943)) ([9bebfd0](https://github.com/opentdf/platform/commit/9bebfd01f615f5a438e0695c03dbb1a9ad7badf3))

## [0.3.27](https://github.com/opentdf/platform/compare/sdk/v0.3.26...sdk/v0.3.27) (2025-02-25)

### Features

* **core:** EXPERIMENTAL: EC-wrapped key support ([#1902](https://github.com/opentdf/platform/issues/1902)) ([652266f](https://github.com/opentdf/platform/commit/652266f212ba10b2492a84741f68391a1d39e007))
* **policy:** adds new public keys table ([#1836](https://github.com/opentdf/platform/issues/1836)) ([cad5048](https://github.com/opentdf/platform/commit/cad5048d09609d678d5b5ac2972605dd61f33bb5))
* **sdk:** Allow schema validation during TDF decrypt ([#1870](https://github.com/opentdf/platform/issues/1870)) ([b7e6fb2](https://github.com/opentdf/platform/commit/b7e6fb24631b4898561b1a64c24c85b32c452a1c))
* **sdk:** MIC-1436: User can decrypt TDF files created with FileWatcher2.0.8 and older. ([#1833](https://github.com/opentdf/platform/issues/1833)) ([f77d110](https://github.com/opentdf/platform/commit/f77d110fcc7f332ceec5a3294b144973eced37c1))
* **sdk:** remove hex encoding for segment hash ([#1805](https://github.com/opentdf/platform/issues/1805)) ([d7179c2](https://github.com/opentdf/platform/commit/d7179c2a91b508c26fbe6499fe5c1ac8334e5505))
* **sdk:** sdk.New should validate platform connectivity and provide precise error ([#1937](https://github.com/opentdf/platform/issues/1937)) ([aa3696d](https://github.com/opentdf/platform/commit/aa3696d848a23ac79029bd64f1b61a15567204d7))

### Bug Fixes

* **core:** Autobump sdk ([#1873](https://github.com/opentdf/platform/issues/1873)) ([085ac7a](https://github.com/opentdf/platform/commit/085ac7af550d2c9d3fd0b0b2deb389939e7cde8e))
* **core:** Autobump sdk ([#1894](https://github.com/opentdf/platform/issues/1894)) ([201244e](https://github.com/opentdf/platform/commit/201244e4473115f07fc997dc49c695cc05d9a6ba))
* **core:** Autobump sdk ([#1917](https://github.com/opentdf/platform/issues/1917)) ([edeeb74](https://github.com/opentdf/platform/commit/edeeb74e9c38b2e6eef7fefa29768912371ec949))
* **core:** Autobump sdk ([#1941](https://github.com/opentdf/platform/issues/1941)) ([0a5a948](https://github.com/opentdf/platform/commit/0a5a94893836482990586302bfb9838e54c5b6ba))
* Improve http.Client usage for security and performance ([#1910](https://github.com/opentdf/platform/issues/1910)) ([e6a53a3](https://github.com/opentdf/platform/commit/e6a53a370b13c3ed63752789aa886be660354e1a))
* **sdk:** bump lib/ocrypto to 0.1.8 ([#1938](https://github.com/opentdf/platform/issues/1938)) ([53fa8ab](https://github.com/opentdf/platform/commit/53fa8ab90236d5bd29541552782b60b96f625405))
* **sdk:** Fix compatibility between bulk and non-bulk rewrap ([#1914](https://github.com/opentdf/platform/issues/1914)) ([74abbb6](https://github.com/opentdf/platform/commit/74abbb66cbb39023f56cd502a7cda294580a41c6))
* **sdk:** Removes unnecessary down-cast of `int` ([#1869](https://github.com/opentdf/platform/issues/1869)) ([66f0c14](https://github.com/opentdf/platform/commit/66f0c14a1ef7490a207c0cef8c98ab4af3f128b1))

## [0.3.26](https://github.com/opentdf/platform/compare/sdk/v0.3.25...sdk/v0.3.26) (2025-01-21)

### Features

* **core:** adds bulk rewrap to sdk and service ([#1835](https://github.com/opentdf/platform/issues/1835)) ([11698ae](https://github.com/opentdf/platform/commit/11698ae18f66282980a7822dd145e3896c2b605c))
* **core:** Adds ErrInvalidPerSchema ([#1860](https://github.com/opentdf/platform/issues/1860)) ([456639e](https://github.com/opentdf/platform/commit/456639e0bfbffc93b08ec1cea9dfb7d6feb3529d))

### Bug Fixes

* **core:** Autobump sdk ([#1863](https://github.com/opentdf/platform/issues/1863)) ([855cb2b](https://github.com/opentdf/platform/commit/855cb2b779b04d927ebdf8bfe8af589c186f95eb))
* **sdk:** everything is `mixedSplits` now ([#1861](https://github.com/opentdf/platform/issues/1861)) ([ba78f14](https://github.com/opentdf/platform/commit/ba78f142e94330ed66d45a9b43640fbcf2c98d22))
* **sdk:** Fixed token expiration time ([#1854](https://github.com/opentdf/platform/issues/1854)) ([c3cda1b](https://github.com/opentdf/platform/commit/c3cda1b877ed588ac52dca09c74775a5d9fd63ca))

## [0.3.25](https://github.com/opentdf/platform/compare/sdk/v0.3.24...sdk/v0.3.25) (2025-01-08)

### Bug Fixes

* **sdk:** Version config fix ([#1847](https://github.com/opentdf/platform/issues/1847)) ([be5d817](https://github.com/opentdf/platform/commit/be5d81777c08264d7fec80064b86a02bc4532229))

## [0.3.24](https://github.com/opentdf/platform/compare/sdk/v0.3.23...sdk/v0.3.24) (2025-01-08)

### Features

* **core:** Expose version info ([#1841](https://github.com/opentdf/platform/issues/1841)) ([92a9f5e](https://github.com/opentdf/platform/commit/92a9f5eab3f2372990b86df6a22ad209eed1a0f9))
* **kas:** collect metrics ([#1702](https://github.com/opentdf/platform/issues/1702)) ([def28d1](https://github.com/opentdf/platform/commit/def28d1984b0b111a07330a3eb59c1285206062d))

### Bug Fixes

* **core:** Update fixtures and flattening in sdk and service ([#1827](https://github.com/opentdf/platform/issues/1827)) ([d6d6a7a](https://github.com/opentdf/platform/commit/d6d6a7a2dffdb96cf7f7f731a4e6e66e06930e59))

## [0.3.23](https://github.com/opentdf/platform/compare/sdk/v0.3.22...sdk/v0.3.23) (2024-11-26)

### Features

* **core:** Introduce ERS mode, ability to connect to remote ERS ([#1735](https://github.com/opentdf/platform/issues/1735)) ([a118316](https://github.com/opentdf/platform/commit/a11831694302114a5d96ac7c6adb4ed55ceff80e))

## [0.3.22](https://github.com/opentdf/platform/compare/sdk/v0.3.21...sdk/v0.3.22) (2024-11-25)

### Bug Fixes

* **sdk:** Dont require mimetype in manifest schema ([#1777](https://github.com/opentdf/platform/issues/1777)) ([98c5899](https://github.com/opentdf/platform/commit/98c5899de25e5766cea8132e57eb95ed6ae629ee))
* **sdk:** Expose oauth package ([#1779](https://github.com/opentdf/platform/issues/1779)) ([55c1a10](https://github.com/opentdf/platform/commit/55c1a10a1f187fdacd25dd684f64eebb79f09976))

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
