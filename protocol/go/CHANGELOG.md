# Changelog

## [0.2.11](https://github.com/opentdf/platform/compare/protocol/go/v0.2.10...protocol/go/v0.2.11) (2024-08-12)


### Features

* **authz:** Typed Entities ([#1249](https://github.com/opentdf/platform/issues/1249)) ([cfab3ad](https://github.com/opentdf/platform/commit/cfab3ad8a72f3a2f1a28ccca988459ddcdcbd7f6))
* **policy:** 1277 add Resource Mapping Group to objects proto ([#1309](https://github.com/opentdf/platform/issues/1309)) ([514f1b8](https://github.com/opentdf/platform/commit/514f1b8e2d6c56056a8258e144380974b1f84d1b)), closes [#1277](https://github.com/opentdf/platform/issues/1277)


### Bug Fixes

* **core:** bump golang.org/x/net from 0.22.0 to 0.23.0 in /protocol/go ([#627](https://github.com/opentdf/platform/issues/627)) ([6008320](https://github.com/opentdf/platform/commit/60083203f34ad75a6618e4aeaee05caddd6b0fe6))
* **kas:** Regenerate protos and fix tests from info rpc removal ([#1291](https://github.com/opentdf/platform/issues/1291)) ([91a2fe6](https://github.com/opentdf/platform/commit/91a2fe65c63aa5ac6ca2f058dbc0c29ca2a26536))
* **policy:** deprecates and reserves value members from value object in protos ([#1151](https://github.com/opentdf/platform/issues/1151)) ([07fcc9e](https://github.com/opentdf/platform/commit/07fcc9ec93f00beeb863e67d0ca1465c783c2a54))

## [0.2.10](https://github.com/opentdf/platform/compare/protocol/go/v0.2.9...protocol/go/v0.2.10) (2024-07-14)


### Bug Fixes

* **policy:** mark value members as deprecated within protos ([#1152](https://github.com/opentdf/platform/issues/1152)) ([d18c889](https://github.com/opentdf/platform/commit/d18c8893cdd73344021de638e2d92859a320eed4))

## [0.2.9](https://github.com/opentdf/platform/compare/protocol/go/v0.2.8...protocol/go/v0.2.9) (2024-07-11)


### Features

* **core:** GetEntitlements with_comprehensive_hierarchy ([#1121](https://github.com/opentdf/platform/issues/1121)) ([ac85bf7](https://github.com/opentdf/platform/commit/ac85bf7aef6c9a00bfa0900f6ff3533059ab4bc8)), closes [#1054](https://github.com/opentdf/platform/issues/1054)

## [0.2.8](https://github.com/opentdf/platform/compare/protocol/go/v0.2.7...protocol/go/v0.2.8) (2024-07-09)


### Features

* **core:** CONTAINS SubjectMapping Operator ([#1109](https://github.com/opentdf/platform/issues/1109)) ([65cd4af](https://github.com/opentdf/platform/commit/65cd4af366d2d6d17ad72157d5d4d31f6620cc1f))

## [0.2.7](https://github.com/opentdf/platform/compare/protocol/go/v0.2.6...protocol/go/v0.2.7) (2024-07-03)


### Bug Fixes

* **policy:** unsafe service attribute update should allow empty names for PATCH-style API ([#1094](https://github.com/opentdf/platform/issues/1094)) ([3c56d0f](https://github.com/opentdf/platform/commit/3c56d0f4ebbda81bf6ca6924176885d93faed48b))

## [0.2.6](https://github.com/opentdf/platform/compare/protocol/go/v0.2.5...protocol/go/v0.2.6) (2024-07-02)


### Features

* **policy:** register unsafe service in platform ([#1066](https://github.com/opentdf/platform/issues/1066)) ([b7796cd](https://github.com/opentdf/platform/commit/b7796cdbe3b16903ac83033c8d99495aa10c8e2c))

## [0.2.5](https://github.com/opentdf/platform/compare/protocol/go/v0.2.4...protocol/go/v0.2.5) (2024-07-02)


### Features

* **policy:** add unsafe attribute RPC db connectivity  ([#1022](https://github.com/opentdf/platform/issues/1022)) ([fbc02f3](https://github.com/opentdf/platform/commit/fbc02f34f3c3ae663b83944132f7dfd6897f6271))


### Bug Fixes

* **policy:** rename unsafe rpcs for aligned casbin action determination ([#1067](https://github.com/opentdf/platform/issues/1067)) ([7861e4a](https://github.com/opentdf/platform/commit/7861e4a5092ee702565b6cd152fd592f3c19435f))

## [0.2.4](https://github.com/opentdf/platform/compare/protocol/go/v0.2.3...protocol/go/v0.2.4) (2024-06-18)


### Features

* **core:** New cryptoProvider config ([#939](https://github.com/opentdf/platform/issues/939)) ([8150623](https://github.com/opentdf/platform/commit/81506237e2e640af34df8c745b71c3f20358d5a4))
* **policy:** add unsafe service protos and unsafe service proto Go gencode ([#1003](https://github.com/opentdf/platform/issues/1003)) ([55cc045](https://github.com/opentdf/platform/commit/55cc0459f8e5594765cecf62c3e2a1adff40a565))


### Bug Fixes

* **core:** policy resource-mappings fix doc drift in proto comments ([#980](https://github.com/opentdf/platform/issues/980)) ([09ab763](https://github.com/opentdf/platform/commit/09ab763263d092653bbded294895dcc08d03bdb2))

## [0.2.3](https://github.com/opentdf/platform/compare/protocol/go/v0.2.2...protocol/go/v0.2.3) (2024-05-17)


### Features

* **authz:** Handle jwts as entity chains in decision requests ([#759](https://github.com/opentdf/platform/issues/759)) ([65612e0](https://github.com/opentdf/platform/commit/65612e08b418eb17c9576903c002685daed21ec1))


### Bug Fixes

* **policy:** make resource-mappings update patch instead of put in RESTful gateway ([#824](https://github.com/opentdf/platform/issues/824)) ([1878bb5](https://github.com/opentdf/platform/commit/1878bb55fb17419487e6c8add6d363469e364923)), closes [#313](https://github.com/opentdf/platform/issues/313)

## [0.2.2](https://github.com/opentdf/platform/compare/protocol/go/v0.2.1...protocol/go/v0.2.2) (2024-05-13)


### Bug Fixes

* **core:** Bump libs patch version ([#779](https://github.com/opentdf/platform/issues/779)) ([3b68dea](https://github.com/opentdf/platform/commit/3b68dea867609071047554a6a7697becaaee2805))

## [0.2.1](https://github.com/opentdf/platform/compare/protocol/go/v0.2.0...protocol/go/v0.2.1) (2024-05-07)


### Features

* **ers:** Create entity resolution service, replace idp plugin ([#660](https://github.com/opentdf/platform/issues/660)) ([ff44112](https://github.com/opentdf/platform/commit/ff441128a4b2ef97c3f739ee3f6f42be273b31dc))


### Bug Fixes

* **policy:** normalize FQN lookup to lower case ([#668](https://github.com/opentdf/platform/issues/668)) ([cd8a875](https://github.com/opentdf/platform/commit/cd8a8750e2a87cb65bc6c8815d8db131dca4f02d)), closes [#669](https://github.com/opentdf/platform/issues/669)

## [0.2.0](https://github.com/opentdf/platform/compare/protocol/go/v0.1.0...protocol/go/v0.2.0) (2024-04-25)


### Features

* **policy:** move key access server registry under policy ([#655](https://github.com/opentdf/platform/issues/655)) ([7b63394](https://github.com/opentdf/platform/commit/7b633942cc5b929122b9f765a5f35cb7b4dd391f))

## [0.1.0](https://github.com/opentdf/platform/compare/protocol/go-v0.1.0...protocol/go/v0.1.0) (2024-04-22)


### Features

* **attr value lookup by fqn:** adds GetAttributesByFqns rpc in attributes service [#243](https://github.com/opentdf/platform/issues/243) ([#250](https://github.com/opentdf/platform/issues/250)) ([b810d33](https://github.com/opentdf/platform/commit/b810d33ad514967d7963310fc7dd60fb6b21cc78))
* **auth:** add authorization via casbin ([#417](https://github.com/opentdf/platform/issues/417)) ([292f2bd](https://github.com/opentdf/platform/commit/292f2bd46a856aaac3b4c996b481f6b4872613cb))
* **authorization service:** Gets the attributes from the in-memory service connection inside the GetDecisions request ([#273](https://github.com/opentdf/platform/issues/273)) ([ce57117](https://github.com/opentdf/platform/commit/ce57117faad274bc63776b41198dc47fee5bb677))
* **authorization:** entitlements ([#247](https://github.com/opentdf/platform/issues/247)) ([42c4f27](https://github.com/opentdf/platform/commit/42c4f27fd03d9802b402d723fcb16e71a61a3048))
* **core:** exposes new well-known configuration endpoint ([#299](https://github.com/opentdf/platform/issues/299)) ([d52cd21](https://github.com/opentdf/platform/commit/d52cd216e3345cd6ef2dbe4f99b78d0f214f7f5d))
* **idp-add-on:** PLAT-3005 Add keycloak idp add on and idp add on protos ([#233](https://github.com/opentdf/platform/issues/233)) ([2365e61](https://github.com/opentdf/platform/commit/2365e6185cf43a93fa9369e960c5cfd28ef59778))
* **kas:** authorization decisions ([#431](https://github.com/opentdf/platform/issues/431)) ([82e8895](https://github.com/opentdf/platform/commit/82e88953beedd503bb161b9c728e31fdcb195624))
* **PLAT-2950:** Update buf generated interface code for java ([#240](https://github.com/opentdf/platform/issues/240)) ([d7e2642](https://github.com/opentdf/platform/commit/d7e26425528ca80545738ece554510f82fb189fb))
* **policy object selectors:** adds initial selector protos, moves policy object type messages to top-level to avoid circular imports, and provides subject mappings in response to GetAttributeValuesByFqns ([#372](https://github.com/opentdf/platform/issues/372)) ([e9d9241](https://github.com/opentdf/platform/commit/e9d9241c022ddbd425120a54e8f73ffdab4e2ae0))
* **policy subject mappings condition sets / migrations:** adds DB schema, fixes migrate down command, adds migrate up command, bumps goose ([#286](https://github.com/opentdf/platform/issues/286)) ([4d7a032](https://github.com/opentdf/platform/commit/4d7a0327b1a71ff666ef5ffecefe13adac721aab))
* **policy:** adds support for match subject request to get entitlements without FQN scopes ([#347](https://github.com/opentdf/platform/issues/347)) ([63c34a5](https://github.com/opentdf/platform/commit/63c34a5b58e748ee0691f03522c19d9b34ad96fb))
* **policy:** enhance and expand metadata and normalize API ([#314](https://github.com/opentdf/platform/issues/314)) ([9389f3b](https://github.com/opentdf/platform/commit/9389f3b724076ba5a47ea1de44e3a58080b50905))
* **policy:** enhance subject mappings with subject condition sets ([#321](https://github.com/opentdf/platform/issues/321)) ([df692eb](https://github.com/opentdf/platform/commit/df692eb6bce2b0aa70692ede2cb718f69c8a7a09))
* **policy:** list attrs by namespace ([#479](https://github.com/opentdf/platform/issues/479)) ([92d8f8c](https://github.com/opentdf/platform/commit/92d8f8cfed2c27a1d893fd22581d66e7e41d9516))
* **policy:** list attrs by namespace name ([#487](https://github.com/opentdf/platform/issues/487)) ([04e723f](https://github.com/opentdf/platform/commit/04e723faf6e90e75e05e625b51428da9579e3fb7))
* **policy:** rework attribute value members ([#398](https://github.com/opentdf/platform/issues/398)) ([1cb7d0c](https://github.com/opentdf/platform/commit/1cb7d0c981a5cdcdb3dd070f887aedf609274a57))
* **policy:** support attribute value creation ([#454](https://github.com/opentdf/platform/issues/454)) ([432ee6b](https://github.com/opentdf/platform/commit/432ee6b277059827f28c4bf7b24f59273632a5b1))
* **policy:** update fixtures, proto comments, and proto field names to reflect use of jq selector syntax within Conditions of Subject Sets ([#523](https://github.com/opentdf/platform/issues/523)) ([16f40f7](https://github.com/opentdf/platform/commit/16f40f7727f7c695f9b5d9f5aac26c348dbee4a2))


### Bug Fixes

* **authorization:** remove access pdp internal AttributeInstance type and use policy proto generated struct types instead ([#485](https://github.com/opentdf/platform/issues/485)) ([8435f59](https://github.com/opentdf/platform/commit/8435f59d60e654098caa002505cedf364811840b))
* **policy:** Adds policy package infix ([#280](https://github.com/opentdf/platform/issues/280)) ([57e8ef9](https://github.com/opentdf/platform/commit/57e8ef9b1fcb9dbbc317e62fd6ea9e24f10b356f))
* **protos:** authorization service's ResourceAttribute message should map to updated platform policy schema ([#238](https://github.com/opentdf/platform/issues/238)) ([bf381dc](https://github.com/opentdf/platform/commit/bf381dc9618d505f3aa5e0a27f79faf373a866c7))
