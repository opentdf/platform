---
title: Manage KAS registrations
command:
  name: kas-registry
  aliases:
    - kasr
    - kas-registries
---

The Key Access Server (KAS) registry is a record of KASes safeguarding access and maintaining public keys.

The registry contains critical information like each server's uri, its public key (which can be
either cached or at a remote uri), and any metadata about the server.

Registered Key Access Servers may grant keys for specified Namespaces, Attributes, and their Values via KAS Grants.

For more information about grants and how KASs are utilized once registered, see the manual for the
`kas-grants` command.
