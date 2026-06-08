---
title: Migrate resources

command:
  name: migrate
  aliases:
    - migration
  description: Migrate policy resources
  flags:
    - name: commit
      shorthand: c
      description: Writes changes to policy storage
      default: false
    - name: interactive
      shorthand: i
      description: Interactive walk through of migrations
      default: false
---

`migrate` groups migration and migration-related cleanup workflows.

Use this command family when you want to inspect a migration plan, review changes interactively, or apply migration-related updates.

The parent `migrate` command owns flags shared by its subcommands:

- `--commit`, `-c`: apply the planned changes instead of only rendering the plan
- `--interactive`, `-i`: walk through the plan interactively before continuing
