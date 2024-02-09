--
-- PostgreSQL database dump
--

-- Dumped from database version 16.1 (Debian 16.1-1.pgdg120+1)
-- Dumped by pg_dump version 16.1 (Debian 16.1-1.pgdg120+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: attribute_namespaces; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.attribute_namespaces (id, name) FROM stdin;
d1406bcf-c4fc-4053-bfca-1df45955e287    abc
\.


--
-- Data for Name: attribute_definitions; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.attribute_definitions (id, namespace_id, name, rule, metadata) FROM stdin;
5a0f8631-09f9-488b-98b8-b7d63530a969    d1406bcf-c4fc-4053-bfca-1df45955e287    abc     ALL_OF  {"createdAt": "2024-02-09T17:46:43.260297Z", "updatedAt": "2024-02-09T17:46:43.260298Z"}
\.


--
-- Data for Name: key_access_servers; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.key_access_servers (id, uri, public_key, metadata) FROM stdin;
\.


--
-- Data for Name: attribute_definition_key_access_grants; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.attribute_definition_key_access_grants (attribute_definition_id, key_access_server_id) FROM stdin;
\.


--
-- Data for Name: attribute_values; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.attribute_values (id, attribute_definition_id, value, members, metadata) FROM stdin;
\.


--
-- Data for Name: attribute_value_key_access_grants; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.attribute_value_key_access_grants (attribute_value_id, key_access_server_id) FROM stdin;
\.


--
-- Data for Name: goose_db_version; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.goose_db_version (id, version_id, is_applied, tstamp) FROM stdin;
1       0       t       2024-02-06 18:20:33.133555
2       20230101000000  t       2024-02-06 18:20:33.14084
3       20231208092252  t       2024-02-06 18:20:33.141652
4       20240131000000  t       2024-02-06 18:20:33.144578
\.


--
-- Data for Name: resource_mappings; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.resource_mappings (id, attribute_value_id, terms, metadata) FROM stdin;
\.


--
-- Data for Name: resources; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.resources (id, name, namespace, version, fqn, labels, description, policytype, resource) FROM stdin;
\.


--
-- Data for Name: subject_mappings; Type: TABLE DATA; Schema: opentdf; Owner: postgres
--

COPY opentdf.subject_mappings (id, attribute_value_id, operator, subject_attribute, subject_attribute_values, metadata) FROM stdin;
\.


--
-- Data for Name: goose_db_version; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.goose_db_version (id, version_id, is_applied, tstamp) FROM stdin;
1       0       t       2024-02-07 14:58:37.295497
\.


--
-- Name: goose_db_version_id_seq; Type: SEQUENCE SET; Schema: opentdf; Owner: postgres
--

SELECT pg_catalog.setval('opentdf.goose_db_version_id_seq', 4, true);


--
-- Name: resources_id_seq; Type: SEQUENCE SET; Schema: opentdf; Owner: postgres
--

SELECT pg_catalog.setval('opentdf.resources_id_seq', 1, false);


--
-- Name: goose_db_version_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.goose_db_version_id_seq', 1, true);


--
-- PostgreSQL database dump complete
--
