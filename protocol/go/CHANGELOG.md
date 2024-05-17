# Changelog

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
