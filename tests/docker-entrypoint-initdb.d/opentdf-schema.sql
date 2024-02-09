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
-- Name: opentdf; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA opentdf;


--
-- Name: attribute_definition_rule; Type: TYPE; Schema: opentdf; Owner: -
--

CREATE TYPE opentdf.attribute_definition_rule AS ENUM (
    'UNSPECIFIED',
    'ALL_OF',
    'ANY_OF',
    'HIERARCHY'
);


--
-- Name: subject_mappings_operator; Type: TYPE; Schema: opentdf; Owner: -
--

CREATE TYPE opentdf.subject_mappings_operator AS ENUM (
    'UNSPECIFIED',
    'IN',
    'NOT_IN'
);


--
-- Name: attribute_definition_rule; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.attribute_definition_rule AS ENUM (
    'UNSPECIFIED',
    'ALL_OF',
    'ANY_OF',
    'HIERARCHY'
);


--
-- Name: subject_mappings_operator; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.subject_mappings_operator AS ENUM (
    'UNSPECIFIED',
    'IN',
    'NOT_IN'
);


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: attribute_definition_key_access_grants; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.attribute_definition_key_access_grants (
                                                                attribute_definition_id uuid NOT NULL,
                                                                key_access_server_id uuid NOT NULL
);


--
-- Name: attribute_definitions; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.attribute_definitions (
                                               id uuid DEFAULT gen_random_uuid() NOT NULL,
                                               namespace_id uuid NOT NULL,
                                               name character varying NOT NULL,
                                               rule opentdf.attribute_definition_rule NOT NULL,
                                               metadata jsonb
);


--
-- Name: attribute_namespaces; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.attribute_namespaces (
                                              id uuid DEFAULT gen_random_uuid() NOT NULL,
                                              name character varying NOT NULL
);


--
-- Name: attribute_value_key_access_grants; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.attribute_value_key_access_grants (
                                                           attribute_value_id uuid NOT NULL,
                                                           key_access_server_id uuid NOT NULL
);


--
-- Name: attribute_values; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.attribute_values (
                                          id uuid DEFAULT gen_random_uuid() NOT NULL,
                                          attribute_definition_id uuid NOT NULL,
                                          value character varying NOT NULL,
                                          members uuid[],
                                          metadata jsonb
);


--
-- Name: key_access_servers; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.key_access_servers (
                                            id uuid DEFAULT gen_random_uuid() NOT NULL,
                                            uri character varying NOT NULL,
                                            public_key jsonb NOT NULL,
                                            metadata jsonb
);


--
-- Name: resource_mappings; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.resource_mappings (
                                           id uuid DEFAULT gen_random_uuid() NOT NULL,
                                           attribute_value_id uuid NOT NULL,
                                           terms character varying[],
                                           metadata jsonb
);


--
-- Name: resources; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.resources (
                                   id integer NOT NULL,
                                   name character varying NOT NULL,
                                   namespace character varying NOT NULL,
                                   version integer NOT NULL,
                                   fqn character varying,
                                   labels jsonb,
                                   description character varying,
                                   policytype character varying NOT NULL,
                                   resource jsonb
);


--
-- Name: resources_id_seq; Type: SEQUENCE; Schema: opentdf; Owner: -
--

CREATE SEQUENCE opentdf.resources_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: resources_id_seq; Type: SEQUENCE OWNED BY; Schema: opentdf; Owner: -
--

ALTER SEQUENCE opentdf.resources_id_seq OWNED BY opentdf.resources.id;


--
-- Name: subject_mappings; Type: TABLE; Schema: opentdf; Owner: -
--

CREATE TABLE opentdf.subject_mappings (
                                          id uuid DEFAULT gen_random_uuid() NOT NULL,
                                          attribute_value_id uuid NOT NULL,
                                          operator opentdf.subject_mappings_operator NOT NULL,
                                          subject_attribute character varying NOT NULL,
                                          subject_attribute_values character varying[],
                                          metadata jsonb
);


--
-- Name: attribute_definition_key_access_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attribute_definition_key_access_grants (
                                                               attribute_definition_id uuid NOT NULL,
                                                               key_access_server_id uuid NOT NULL
);


--
-- Name: attribute_definitions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attribute_definitions (
                                              id uuid DEFAULT gen_random_uuid() NOT NULL,
                                              namespace_id uuid NOT NULL,
                                              name character varying NOT NULL,
                                              rule public.attribute_definition_rule NOT NULL,
                                              metadata jsonb
);


--
-- Name: attribute_namespaces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attribute_namespaces (
                                             id uuid DEFAULT gen_random_uuid() NOT NULL,
                                             name character varying NOT NULL
);


--
-- Name: attribute_value_key_access_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attribute_value_key_access_grants (
                                                          attribute_value_id uuid NOT NULL,
                                                          key_access_server_id uuid NOT NULL
);


--
-- Name: attribute_values; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attribute_values (
                                         id uuid DEFAULT gen_random_uuid() NOT NULL,
                                         attribute_definition_id uuid NOT NULL,
                                         value character varying NOT NULL,
                                         members uuid[],
                                         metadata jsonb
);


--
-- Name: key_access_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_access_servers (
                                           id uuid DEFAULT gen_random_uuid() NOT NULL,
                                           uri character varying NOT NULL,
                                           public_key jsonb NOT NULL,
                                           metadata jsonb
);


--
-- Name: resource_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_mappings (
                                          id uuid DEFAULT gen_random_uuid() NOT NULL,
                                          attribute_value_id uuid NOT NULL,
                                          terms character varying[],
                                          metadata jsonb
);


--
-- Name: subject_mappings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.subject_mappings (
                                         id uuid DEFAULT gen_random_uuid() NOT NULL,
                                         attribute_value_id uuid NOT NULL,
                                         operator public.subject_mappings_operator NOT NULL,
                                         subject_attribute character varying NOT NULL,
                                         subject_attribute_values character varying[],
                                         metadata jsonb
);



--
-- Name: resources id; Type: DEFAULT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.resources ALTER COLUMN id SET DEFAULT nextval('opentdf.resources_id_seq'::regclass);


--
-- Name: attribute_definition_key_access_grants attribute_definition_key_access_grants_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_definition_key_access_grants
    ADD CONSTRAINT attribute_definition_key_access_grants_pkey PRIMARY KEY (attribute_definition_id, key_access_server_id);


--
-- Name: attribute_definitions attribute_definitions_namespace_id_name_key; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_definitions
    ADD CONSTRAINT attribute_definitions_namespace_id_name_key UNIQUE (namespace_id, name);


--
-- Name: attribute_definitions attribute_definitions_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_definitions
    ADD CONSTRAINT attribute_definitions_pkey PRIMARY KEY (id);


--
-- Name: attribute_namespaces attribute_namespaces_name_key; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_namespaces
    ADD CONSTRAINT attribute_namespaces_name_key UNIQUE (name);


--
-- Name: attribute_namespaces attribute_namespaces_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_namespaces
    ADD CONSTRAINT attribute_namespaces_pkey PRIMARY KEY (id);


--
-- Name: attribute_value_key_access_grants attribute_value_key_access_grants_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_value_key_access_grants
    ADD CONSTRAINT attribute_value_key_access_grants_pkey PRIMARY KEY (attribute_value_id, key_access_server_id);


--
-- Name: attribute_values attribute_values_attribute_definition_id_value_key; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_values
    ADD CONSTRAINT attribute_values_attribute_definition_id_value_key UNIQUE (attribute_definition_id, value);


--
-- Name: attribute_values attribute_values_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_values
    ADD CONSTRAINT attribute_values_pkey PRIMARY KEY (id);


--
-- Name: key_access_servers key_access_servers_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.key_access_servers
    ADD CONSTRAINT key_access_servers_pkey PRIMARY KEY (id);


--
-- Name: key_access_servers key_access_servers_uri_key; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.key_access_servers
    ADD CONSTRAINT key_access_servers_uri_key UNIQUE (uri);


--
-- Name: resource_mappings resource_mappings_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.resource_mappings
    ADD CONSTRAINT resource_mappings_pkey PRIMARY KEY (id);


--
-- Name: resources resources_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.resources
    ADD CONSTRAINT resources_pkey PRIMARY KEY (id);


--
-- Name: subject_mappings subject_mappings_pkey; Type: CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.subject_mappings
    ADD CONSTRAINT subject_mappings_pkey PRIMARY KEY (id);


--
-- Name: attribute_definition_key_access_grants attribute_definition_key_access_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_definition_key_access_grants
    ADD CONSTRAINT attribute_definition_key_access_grants_pkey PRIMARY KEY (attribute_definition_id, key_access_server_id);


--
-- Name: attribute_definitions attribute_definitions_namespace_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_definitions
    ADD CONSTRAINT attribute_definitions_namespace_id_name_key UNIQUE (namespace_id, name);


--
-- Name: attribute_definitions attribute_definitions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_definitions
    ADD CONSTRAINT attribute_definitions_pkey PRIMARY KEY (id);


--
-- Name: attribute_namespaces attribute_namespaces_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_namespaces
    ADD CONSTRAINT attribute_namespaces_name_key UNIQUE (name);


--
-- Name: attribute_namespaces attribute_namespaces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_namespaces
    ADD CONSTRAINT attribute_namespaces_pkey PRIMARY KEY (id);


--
-- Name: attribute_value_key_access_grants attribute_value_key_access_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_value_key_access_grants
    ADD CONSTRAINT attribute_value_key_access_grants_pkey PRIMARY KEY (attribute_value_id, key_access_server_id);


--
-- Name: attribute_values attribute_values_attribute_definition_id_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_values
    ADD CONSTRAINT attribute_values_attribute_definition_id_value_key UNIQUE (attribute_definition_id, value);


--
-- Name: attribute_values attribute_values_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_values
    ADD CONSTRAINT attribute_values_pkey PRIMARY KEY (id);


--
-- Name: key_access_servers key_access_servers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_access_servers
    ADD CONSTRAINT key_access_servers_pkey PRIMARY KEY (id);


--
-- Name: key_access_servers key_access_servers_uri_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_access_servers
    ADD CONSTRAINT key_access_servers_uri_key UNIQUE (uri);


--
-- Name: resource_mappings resource_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_mappings
    ADD CONSTRAINT resource_mappings_pkey PRIMARY KEY (id);


--
-- Name: subject_mappings subject_mappings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subject_mappings
    ADD CONSTRAINT subject_mappings_pkey PRIMARY KEY (id);


--
-- Name: attribute_definition_key_access_grants attribute_definition_key_access_gr_attribute_definition_id_fkey; Type: FK CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_definition_key_access_grants
    ADD CONSTRAINT attribute_definition_key_access_gr_attribute_definition_id_fkey FOREIGN KEY (attribute_definition_id) REFERENCES opentdf.attribute_definitions(id);


--
-- Name: attribute_definition_key_access_grants attribute_definition_key_access_grant_key_access_server_id_fkey; Type: FK CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_definition_key_access_grants
    ADD CONSTRAINT attribute_definition_key_access_grant_key_access_server_id_fkey FOREIGN KEY (key_access_server_id) REFERENCES opentdf.key_access_servers(id);


--
-- Name: attribute_definitions attribute_definitions_namespace_id_fkey; Type: FK CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_definitions
    ADD CONSTRAINT attribute_definitions_namespace_id_fkey FOREIGN KEY (namespace_id) REFERENCES opentdf.attribute_namespaces(id);


--
-- Name: attribute_value_key_access_grants attribute_value_key_access_grants_attribute_value_id_fkey; Type: FK CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_value_key_access_grants
    ADD CONSTRAINT attribute_value_key_access_grants_attribute_value_id_fkey FOREIGN KEY (attribute_value_id) REFERENCES opentdf.attribute_values(id);


--
-- Name: attribute_value_key_access_grants attribute_value_key_access_grants_key_access_server_id_fkey; Type: FK CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_value_key_access_grants
    ADD CONSTRAINT attribute_value_key_access_grants_key_access_server_id_fkey FOREIGN KEY (key_access_server_id) REFERENCES opentdf.key_access_servers(id);


--
-- Name: attribute_values attribute_values_attribute_definition_id_fkey; Type: FK CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.attribute_values
    ADD CONSTRAINT attribute_values_attribute_definition_id_fkey FOREIGN KEY (attribute_definition_id) REFERENCES opentdf.attribute_definitions(id);


--
-- Name: resource_mappings resource_mappings_attribute_value_id_fkey; Type: FK CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.resource_mappings
    ADD CONSTRAINT resource_mappings_attribute_value_id_fkey FOREIGN KEY (attribute_value_id) REFERENCES opentdf.attribute_values(id);


--
-- Name: subject_mappings subject_mappings_attribute_value_id_fkey; Type: FK CONSTRAINT; Schema: opentdf; Owner: -
--

ALTER TABLE ONLY opentdf.subject_mappings
    ADD CONSTRAINT subject_mappings_attribute_value_id_fkey FOREIGN KEY (attribute_value_id) REFERENCES opentdf.attribute_values(id);


--
-- Name: attribute_definition_key_access_grants attribute_definition_key_access_gr_attribute_definition_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_definition_key_access_grants
    ADD CONSTRAINT attribute_definition_key_access_gr_attribute_definition_id_fkey FOREIGN KEY (attribute_definition_id) REFERENCES public.attribute_definitions(id);


--
-- Name: attribute_definition_key_access_grants attribute_definition_key_access_grant_key_access_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_definition_key_access_grants
    ADD CONSTRAINT attribute_definition_key_access_grant_key_access_server_id_fkey FOREIGN KEY (key_access_server_id) REFERENCES public.key_access_servers(id);


--
-- Name: attribute_definitions attribute_definitions_namespace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_definitions
    ADD CONSTRAINT attribute_definitions_namespace_id_fkey FOREIGN KEY (namespace_id) REFERENCES public.attribute_namespaces(id);


--
-- Name: attribute_value_key_access_grants attribute_value_key_access_grants_attribute_value_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_value_key_access_grants
    ADD CONSTRAINT attribute_value_key_access_grants_attribute_value_id_fkey FOREIGN KEY (attribute_value_id) REFERENCES public.attribute_values(id);


--
-- Name: attribute_value_key_access_grants attribute_value_key_access_grants_key_access_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_value_key_access_grants
    ADD CONSTRAINT attribute_value_key_access_grants_key_access_server_id_fkey FOREIGN KEY (key_access_server_id) REFERENCES public.key_access_servers(id);


--
-- Name: attribute_values attribute_values_attribute_definition_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attribute_values
    ADD CONSTRAINT attribute_values_attribute_definition_id_fkey FOREIGN KEY (attribute_definition_id) REFERENCES public.attribute_definitions(id);


--
-- Name: resource_mappings resource_mappings_attribute_value_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_mappings
    ADD CONSTRAINT resource_mappings_attribute_value_id_fkey FOREIGN KEY (attribute_value_id) REFERENCES public.attribute_values(id);


--
-- Name: subject_mappings subject_mappings_attribute_value_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.subject_mappings
    ADD CONSTRAINT subject_mappings_attribute_value_id_fkey FOREIGN KEY (attribute_value_id) REFERENCES public.attribute_values(id);


--
-- PostgreSQL database dump complete
--

