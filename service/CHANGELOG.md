# Changelog

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
