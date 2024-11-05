# Changelog

## [0.2.19](https://github.com/opentdf/platform/compare/protocol/go/v0.2.18...protocol/go/v0.2.19) (2024-11-05)


### Features

* **policy:** 1651 move GetAttributesByValueFqns RPC request validation to protovalidate ([#1657](https://github.com/opentdf/platform/issues/1657)) ([c7d6b15](https://github.com/opentdf/platform/commit/c7d6b1542c10d3e2a35fa00efaf7d415f63c7dca))
* **policy:** add optional name field to registered KASes in policy ([#1636](https://github.com/opentdf/platform/issues/1636)) ([f1382c1](https://github.com/opentdf/platform/commit/f1382c16893cefd40e930f4112ac7a61c9b05898))
* **policy:** limit/offset throughout LIST protos/gencode ([#1668](https://github.com/opentdf/platform/issues/1668)) ([7de6cce](https://github.com/opentdf/platform/commit/7de6cce5c9603228bc0ef5566b5b2d10c4a12ee4))
* **policy:** subject condition sets prune protos/gencode ([#1687](https://github.com/opentdf/platform/issues/1687)) ([a627e02](https://github.com/opentdf/platform/commit/a627e021e9df2c06e1c86acfc0a4ee83c4bce932))


### Bug Fixes

* **policy:** enhance proto validation across policy requests ([#1656](https://github.com/opentdf/platform/issues/1656)) ([df534c4](https://github.com/opentdf/platform/commit/df534c40f3f500190b200923e5157701b438431b))
* **policy:** make MatchSubjectMappings operator agnostic ([#1658](https://github.com/opentdf/platform/issues/1658)) ([cb63819](https://github.com/opentdf/platform/commit/cb63819d107ed65cb5d467a956d713bd55214cdb))

## [0.2.18](https://github.com/opentdf/platform/compare/protocol/go/v0.2.17...protocol/go/v0.2.18) (2024-10-11)


### Features

* **policy:** DSP-51 - deprecate PublicKey local field ([#1590](https://github.com/opentdf/platform/issues/1590)) ([e3ed0b5](https://github.com/opentdf/platform/commit/e3ed0b5ce6039000c9e3c574d3d6ce2931781235))

## [0.2.17](https://github.com/opentdf/platform/compare/protocol/go/v0.2.16...protocol/go/v0.2.17) (2024-09-25)


### Bug Fixes

* **core:** Fix POST /v1/entitlements body parsing ([#1574](https://github.com/opentdf/platform/issues/1574)) ([fcae7ef](https://github.com/opentdf/platform/commit/fcae7ef0eba2c43ab93f5a2815e7b3e1dec69364))

## [0.2.16](https://github.com/opentdf/platform/compare/protocol/go/v0.2.15...protocol/go/v0.2.16) (2024-09-19)


### Bug Fixes

* **core:** Fix parsing /v1/authorization ([#1554](https://github.com/opentdf/platform/issues/1554)) ([b7d694d](https://github.com/opentdf/platform/commit/b7d694d5df3867f278007660c32acb72c868735e)), closes [#1553](https://github.com/opentdf/platform/issues/1553)

## [0.2.15](https://github.com/opentdf/platform/compare/protocol/go/v0.2.14...protocol/go/v0.2.15) (2024-09-04)


### Features

* **policy:** 1398 add metadata support to Resource Mapping Groups ([#1412](https://github.com/opentdf/platform/issues/1412)) ([87b7b2f](https://github.com/opentdf/platform/commit/87b7b2ff6f7b39d34823ba926758fba25489c0a6))

## [0.2.14](https://github.com/opentdf/platform/compare/protocol/go/v0.2.13...protocol/go/v0.2.14) (2024-08-20)


### Features

* **policy:** 1277 protos and service methods for Resource Mapping Groups operations ([#1343](https://github.com/opentdf/platform/issues/1343)) ([570f402](https://github.com/opentdf/platform/commit/570f4023183898212dcd007e5b42135ccf1d285a))
* **sdk:** Load KAS keys from policy service ([#1346](https://github.com/opentdf/platform/issues/1346)) ([fe628a0](https://github.com/opentdf/platform/commit/fe628a013e41fb87585eb53a61988f822b40a71a))

## [0.2.13](https://github.com/opentdf/platform/compare/protocol/go/v0.2.12...protocol/go/v0.2.13) (2024-08-16)


### Features

* **core:** Adds key ids to kas registry ([#1347](https://github.com/opentdf/platform/issues/1347)) ([e6c76ee](https://github.com/opentdf/platform/commit/e6c76ee415e08ec8681ae4ff8fb9d5d04ea7d2bb))
* **core:** validate kas uri ([#1351](https://github.com/opentdf/platform/issues/1351)) ([2b70931](https://github.com/opentdf/platform/commit/2b7093136f6af1b6a86e613c095cefe403c9a06c))


### Bug Fixes

* **core:** align policy kas grant assignments http gateway methods with actions ([#1299](https://github.com/opentdf/platform/issues/1299)) ([031c6ca](https://github.com/opentdf/platform/commit/031c6ca87b8e252a4254f10bfcc78b45e5111ed9))

## [0.2.12](https://github.com/opentdf/platform/compare/protocol/go/v0.2.11...protocol/go/v0.2.12) (2024-08-13)


### Features

* **core:** further support in policy for namespace grants ([#1334](https://github.com/opentdf/platform/issues/1334)) ([d56231e](https://github.com/opentdf/platform/commit/d56231ea632c6072613c18cf1fcb9770cedf49e3))
* **core:** policy support for LIST of kas grants (protos/db) ([#1317](https://github.com/opentdf/platform/issues/1317)) ([599fc56](https://github.com/opentdf/platform/commit/599fc56dbcc3ae8ff2f46584c9bae7c1619a590d))

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
