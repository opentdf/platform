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
-- Data for Name: attribute_namespaces; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.attribute_namespaces VALUES ('7aca0d8a-bd15-476d-93a4-00d8bb12fd48', 'acme');


--
-- Data for Name: attribute_definitions; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.attribute_definitions VALUES ('b6a63345-c8c8-4f90-9b76-da55097ca702', '7aca0d8a-bd15-476d-93a4-00d8bb12fd48', 'abc', 'ALL_OF', '{"createdAt": "2024-02-12T17:56:33.059504Z", "updatedAt": "2024-02-12T17:56:33.059504Z"}');


--
-- Data for Name: key_access_servers; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: attribute_definition_key_access_grants; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: attribute_values; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: attribute_value_key_access_grants; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: resource_mappings; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: resources; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: subject_mappings; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Name: goose_db_version_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.goose_db_version_id_seq', 1, true);


--
-- Name: resources_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.resources_id_seq', 1, false);


--
-- PostgreSQL database dump complete
--
