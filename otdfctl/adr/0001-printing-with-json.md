---
status: accepted
date: 2024-08-29
decision: Encapsulate printing to ensure consistent output format
author: '@jrschumacher'
deciders: ['@jakedoublev', '@ryanulit', '@suchak1']
---

# Consistent output format for printing JSON and pretty-print

## Context and Problem Statement

We need to develop a printer that can globally determine when to print in pretty-print format versus JSON format. This decision is crucial to ensure consistent and appropriate output formatting across different use cases and environments.

## Decision Drivers

- **Consistency**: Ensure uniform output format across the application.
- **Flexibility**: Ability to switch between pretty-print and JSON formats based on context.
- **Ease of Implementation**: Simplicity in implementing and maintaining the solution.

## Considered Options

1. Keep existing code as is
2. Move the printing into a global function that has context about the CLI flags to drive output format

## Decision Outcome

It was decided to encapsulate printing to ensure there is consistent output format. This function will have context about the CLI flags to drive the output format. This approach provides the flexibility to switch between pretty-print and JSON formats based on the context.

### Consequences

- **Positive**:
  - Provides flexibility to switch formats without changing the code.
  - Ensures consistent output format across different environments.
  - Simplifies the implementation and maintenance process.

- **Negative**:
  - Requires careful management of configuration settings.
  - Potential for misconfiguration leading to incorrect output format when developers use `fmt` directly.
