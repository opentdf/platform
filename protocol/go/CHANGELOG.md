# Changelog

## [0.7.0](https://github.com/opentdf/platform/compare/protocol/go/v0.6.2...protocol/go/v0.7.0) (2025-08-08)


### ⚠ BREAKING CHANGES

* **policy:** disable kas grants in favor of key mappings ([#2220](https://github.com/opentdf/platform/issues/2220))
* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979))

### Features

* add ability to retrieve policy resources by id or name ([#1901](https://github.com/opentdf/platform/issues/1901)) ([deb4455](https://github.com/opentdf/platform/commit/deb4455773cd71d3436510bbeb599f309106ce1d))
* **authz:** authz v2, ers v2 protos and gencode for ABAC with actions & registered resource  ([#2124](https://github.com/opentdf/platform/issues/2124)) ([ea7992a](https://github.com/opentdf/platform/commit/ea7992a6d6739084496ec0afdcb22eb9199d1a85))
* **authz:** improve v2 request proto validation ([#2357](https://github.com/opentdf/platform/issues/2357)) ([f927b99](https://github.com/opentdf/platform/commit/f927b994149079947cac1d1386f2bfb9a52139a0))
* **authz:** sensible request limit upper bounds ([#2526](https://github.com/opentdf/platform/issues/2526)) ([b3093cc](https://github.com/opentdf/platform/commit/b3093cce2ffd1f1cdaec884967dc96a40caa2903))
* **core:** adds bulk rewrap to sdk and service ([#1835](https://github.com/opentdf/platform/issues/1835)) ([11698ae](https://github.com/opentdf/platform/commit/11698ae18f66282980a7822dd145e3896c2b605c))
* **core:** EXPERIMENTAL: EC-wrapped key support ([#1902](https://github.com/opentdf/platform/issues/1902)) ([652266f](https://github.com/opentdf/platform/commit/652266f212ba10b2492a84741f68391a1d39e007))
* **core:** Require go 1.23+ ([#1979](https://github.com/opentdf/platform/issues/1979)) ([164c922](https://github.com/opentdf/platform/commit/164c922af74b1265fe487362c356abb7f1503ada))
* **core:** v2 ERS with proto updates ([#2210](https://github.com/opentdf/platform/issues/2210)) ([a161ef8](https://github.com/opentdf/platform/commit/a161ef85d12600672ff695cc84b07579a70c5cac))
* **policy:** add enhanced standard/custom actions protos ([#2020](https://github.com/opentdf/platform/issues/2020)) ([bbac53f](https://github.com/opentdf/platform/commit/bbac53fd622defefc6e8831ab041356fe7e23776))
* **policy:** Add legacy keys. ([#2613](https://github.com/opentdf/platform/issues/2613)) ([57370b0](https://github.com/opentdf/platform/commit/57370b0f76605ec2ed375728ec9b60a829072d99))
* **policy:** Add list key mappings rpc. ([#2533](https://github.com/opentdf/platform/issues/2533)) ([fbc2724](https://github.com/opentdf/platform/commit/fbc2724a066b5e4121838a958cb926a1ab5bdcde))
* **policy:** add obligation protos ([#2579](https://github.com/opentdf/platform/issues/2579)) ([50882e1](https://github.com/opentdf/platform/commit/50882e10abff64e14548e0c51851a4b671ef8b11))
* **policy:** Add validation to delete keys ([#2576](https://github.com/opentdf/platform/issues/2576)) ([cc169d9](https://github.com/opentdf/platform/commit/cc169d969f0e3380a2341033bc53a1a0eece781a))
* **policy:** add values to CreateObligationRequest ([#2614](https://github.com/opentdf/platform/issues/2614)) ([94535cc](https://github.com/opentdf/platform/commit/94535cc0c1622b7499dad8e91a02a93f1eb1531b))
* **policy:** adds new public keys table ([#1836](https://github.com/opentdf/platform/issues/1836)) ([cad5048](https://github.com/opentdf/platform/commit/cad5048d09609d678d5b5ac2972605dd61f33bb5))
* **policy:** Allow the deletion of a key. ([#2575](https://github.com/opentdf/platform/issues/2575)) ([82b96f0](https://github.com/opentdf/platform/commit/82b96f023662c0a6c76af6d1196f78ab28a6acf0))
* **policy:** cache SubjectConditionSet selectors in dedicated column maintained via trigger ([#2320](https://github.com/opentdf/platform/issues/2320)) ([215791f](https://github.com/opentdf/platform/commit/215791f2185d6cacfa4a8ae4a009739ee30bfc66))
* **policy:** Change return type for delete key proto. ([#2566](https://github.com/opentdf/platform/issues/2566)) ([c1ae924](https://github.com/opentdf/platform/commit/c1ae924d55ec0d13fd79917f960dede66cef7705))
* **policy:** Default Platform Keys ([#2254](https://github.com/opentdf/platform/issues/2254)) ([d7447fe](https://github.com/opentdf/platform/commit/d7447fe2604443b4c75c8e547acf414bf78af988))
* **policy:** disable kas grants in favor of key mappings ([#2220](https://github.com/opentdf/platform/issues/2220)) ([30f8cf5](https://github.com/opentdf/platform/commit/30f8cf54abbb1a9def43a6d0fa602ba979dd3053))
* **policy:** DSPX-1018 NDR retrieval by FQN support ([#2131](https://github.com/opentdf/platform/issues/2131)) ([0001041](https://github.com/opentdf/platform/commit/00010419d372c358f8885953bcc33a27c2db4607))
* **policy:** DSPX-1057 registered resource action attribute values (protos only) ([#2217](https://github.com/opentdf/platform/issues/2217)) ([6375596](https://github.com/opentdf/platform/commit/6375596555f09cabb3f1bc16d369fd6d2b94544a))
* **policy:** DSPX-893 NDR define crud protos ([#2056](https://github.com/opentdf/platform/issues/2056)) ([55a5c27](https://github.com/opentdf/platform/commit/55a5c279d0499f684bc62c53838edbcb89bec272))
* **policy:** DSPX-902 NDR service crud protos only (1/2) ([#2092](https://github.com/opentdf/platform/issues/2092)) ([24b6cb5](https://github.com/opentdf/platform/commit/24b6cb5f876439dd5bb15ed95a20d18a16da3706))
* **policy:** Finish resource mapping groups ([#2224](https://github.com/opentdf/platform/issues/2224)) ([5ff754e](https://github.com/opentdf/platform/commit/5ff754e99189d09ec3698128d1bc51b6f7a90994))
* **policy:** key management crud ([#2110](https://github.com/opentdf/platform/issues/2110)) ([4c3d53d](https://github.com/opentdf/platform/commit/4c3d53d5fbb6f4659155ac60d289d92ac20180f1))
* **policy:** Key management proto ([#2115](https://github.com/opentdf/platform/issues/2115)) ([561f853](https://github.com/opentdf/platform/commit/561f85301c73c221cf22695afb66deeac594a3d6))
* **policy:** Modify get request to search for keys by kasid with keyid. ([#2147](https://github.com/opentdf/platform/issues/2147)) ([780d2e4](https://github.com/opentdf/platform/commit/780d2e476f48678c7e384a9ef83df0b8e8b9428a))
* **policy:** Return KAS Key structure ([#2172](https://github.com/opentdf/platform/issues/2172)) ([7f97b99](https://github.com/opentdf/platform/commit/7f97b99f7f08fbd53cdb3592206f974040c270f3))
* **policy:** Return Simple Kas Keys from non-Key RPCs ([#2387](https://github.com/opentdf/platform/issues/2387)) ([5113e0e](https://github.com/opentdf/platform/commit/5113e0edbe0260d0937a62932671b40ca5cfcbf4))
* **policy:** rotate keys rpc ([#2180](https://github.com/opentdf/platform/issues/2180)) ([0d00743](https://github.com/opentdf/platform/commit/0d00743d08c3e80fd1b5f9f37adc66d218b8c13b))
* **policy:** Update key status's and UpdateKey rpc. ([#2315](https://github.com/opentdf/platform/issues/2315)) ([7908db9](https://github.com/opentdf/platform/commit/7908db9c2be5adeccd3fb9f177187aee53698ee8))
* **policy:** Update simple kas key ([#2378](https://github.com/opentdf/platform/issues/2378)) ([09d8239](https://github.com/opentdf/platform/commit/09d82390a06e22a8787118cd0ec7d97311e85363))


### Bug Fixes

* add pagination to list public key mappings response ([#1889](https://github.com/opentdf/platform/issues/1889)) ([9898fbd](https://github.com/opentdf/platform/commit/9898fbda305f4eface291a2aaa98d2df80f0ad05))
* **core:** Allow 521 curve to be used ([#2485](https://github.com/opentdf/platform/issues/2485)) ([aaf43dc](https://github.com/opentdf/platform/commit/aaf43dc368b4cabbc9affa0a6075abd335aa57e3))
* **core:** Fixes protoJSON parse bug on ec rewrap ([#1943](https://github.com/opentdf/platform/issues/1943)) ([9bebfd0](https://github.com/opentdf/platform/commit/9bebfd01f615f5a438e0695c03dbb1a9ad7badf3))
* **core:** Update fixtures and flattening in sdk and service ([#1827](https://github.com/opentdf/platform/issues/1827)) ([d6d6a7a](https://github.com/opentdf/platform/commit/d6d6a7a2dffdb96cf7f7f731a4e6e66e06930e59))
* **deps:** bump toolchain in /lib/fixtures and /examples to resolve CVE GO-2025-3563 ([#2061](https://github.com/opentdf/platform/issues/2061)) ([9c16843](https://github.com/opentdf/platform/commit/9c168437db3b138613fe629419dd6bd9f837e881))
* **policy:** protovalidate deprecated action types and removal of gRPC gateway in subject mappings svc ([#2377](https://github.com/opentdf/platform/issues/2377)) ([54a6de0](https://github.com/opentdf/platform/commit/54a6de03d8796b0fe72edc381ce514927bdcd793))
* **policy:** remove gRPC gateway in policy except where needed ([#2382](https://github.com/opentdf/platform/issues/2382)) ([1937acb](https://github.com/opentdf/platform/commit/1937acb3fff5e6216808ac233d3a34b869901b44))
* **policy:** remove new public keys rpc's ([#1962](https://github.com/opentdf/platform/issues/1962)) ([5049bab](https://github.com/opentdf/platform/commit/5049baba20ddcefa40c280a18e5dd8ef754b7e22))
* **policy:** remove predefined rules in actions protos ([#2069](https://github.com/opentdf/platform/issues/2069)) ([060f059](https://github.com/opentdf/platform/commit/060f05941f9b81b007669f51b6205723af8c1680))
* **policy:** return kas uri on keys for definition, namespace and values ([#2186](https://github.com/opentdf/platform/issues/2186)) ([6c55fb8](https://github.com/opentdf/platform/commit/6c55fb8614903c7fc68151908e25fe4c202f6574))
* **sdk:** Fix compatibility between bulk and non-bulk rewrap ([#1914](https://github.com/opentdf/platform/issues/1914)) ([74abbb6](https://github.com/opentdf/platform/commit/74abbb66cbb39023f56cd502a7cda294580a41c6))
* update key_mode to provide more context ([#2226](https://github.com/opentdf/platform/issues/2226)) ([44d0805](https://github.com/opentdf/platform/commit/44d0805fb34d87098ada7b5f7c934f65365f77f1))

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
