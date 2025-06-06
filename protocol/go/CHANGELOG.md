# Changelog

## [0.4.0](https://github.com/opentdf/platform/compare/protocol/go/v0.3.6...protocol/go/v0.4.0) (2025-06-05)


### Features

* **authz:** improve v2 request proto validation ([#2357](https://github.com/opentdf/platform/issues/2357)) ([f927b99](https://github.com/opentdf/platform/commit/f927b994149079947cac1d1386f2bfb9a52139a0))
* **policy:** cache SubjectConditionSet selectors in dedicated column maintained via trigger ([#2320](https://github.com/opentdf/platform/issues/2320)) ([215791f](https://github.com/opentdf/platform/commit/215791f2185d6cacfa4a8ae4a009739ee30bfc66))
* **policy:** Return Simple Kas Keys from non-Key RPCs ([#2387](https://github.com/opentdf/platform/issues/2387)) ([5113e0e](https://github.com/opentdf/platform/commit/5113e0edbe0260d0937a62932671b40ca5cfcbf4))
* **policy:** Update simple kas key ([#2378](https://github.com/opentdf/platform/issues/2378)) ([09d8239](https://github.com/opentdf/platform/commit/09d82390a06e22a8787118cd0ec7d97311e85363))


### Bug Fixes

* **policy:** protovalidate deprecated action types and removal of gRPC gateway in subject mappings svc ([#2377](https://github.com/opentdf/platform/issues/2377)) ([54a6de0](https://github.com/opentdf/platform/commit/54a6de03d8796b0fe72edc381ce514927bdcd793))
* **policy:** remove gRPC gateway in policy except where needed ([#2382](https://github.com/opentdf/platform/issues/2382)) ([1937acb](https://github.com/opentdf/platform/commit/1937acb3fff5e6216808ac233d3a34b869901b44))

## [0.3.6](https://github.com/opentdf/platform/compare/protocol/go/v0.3.5...protocol/go/v0.3.6) (2025-05-27)


### Features

* **policy:** Update key status's and UpdateKey rpc. ([#2315](https://github.com/opentdf/platform/issues/2315)) ([7908db9](https://github.com/opentdf/platform/commit/7908db9c2be5adeccd3fb9f177187aee53698ee8))
* **policy** Rename key context structures. ([#2318](https://github.com/opentdf/platform/pull/2318))
   ([4cb28a9](https://github.com/opentdf/platform/commit/4cb28a9216a208493086fc5d44d38270a9d6f3cc))

## [0.3.5](https://github.com/opentdf/platform/compare/protocol/go/v0.3.4...protocol/go/v0.3.5) (2025-05-23)


### Features

* **policy:** Default Platform Keys ([#2254](https://github.com/opentdf/platform/issues/2254)) ([d7447fe](https://github.com/opentdf/platform/commit/d7447fe2604443b4c75c8e547acf414bf78af988))

## [0.3.4](https://github.com/opentdf/platform/compare/protocol/go/v0.3.3...protocol/go/v0.3.4) (2025-05-20)


### Features

* **core:** v2 ERS with proto updates ([#2210](https://github.com/opentdf/platform/issues/2210)) ([a161ef8](https://github.com/opentdf/platform/commit/a161ef85d12600672ff695cc84b07579a70c5cac))
* **policy:** Finish resource mapping groups ([#2224](https://github.com/opentdf/platform/issues/2224)) ([5ff754e](https://github.com/opentdf/platform/commit/5ff754e99189d09ec3698128d1bc51b6f7a90994))


### Bug Fixes

* update key_mode to provide more context ([#2226](https://github.com/opentdf/platform/issues/2226)) ([44d0805](https://github.com/opentdf/platform/commit/44d0805fb34d87098ada7b5f7c934f65365f77f1))
