---
title: Migrate Registered Resources

command:
    name: registered-resources
    description: Migrate Registered Resources to Namespaced Resources
---

Migrate all registered resources to be associated with a namespace.

For a non-interactive migration, use the `--commit` flag. This will prompt once
for a target namespace and assign all registered resources to it.

For an interactive migration, use the `--interactive --commit` flags together.
This allows per-resource namespace assignment with options to skip individual
resources or abort the migration.

Running without `--commit` displays a preview of resources that need migration
without making any changes.
