---
status: accepted
date: 2024-08-29
decision: Use ADRs in the `adr` directory of the repo to document architectural decisions
author: '@jakedoublev'
deciders: ['@ryanulit', '@jrschumacher']
---

# Use a ADR storage format that make diffs easier to read

## Context and Problem Statement

We've been using Github Issues to document ADR decisions, but it's hard to read the diffs when changes are made. We need a better way to store and manage ADRs. ADRs sometimes get updated and it's hard to track the changes and decision using the edit history dropdown or the comments section.

## Decision Drivers

- **Low barrier of entry**: A primary goal of our ADR process is to ensure decisions are captured.
- **Ease of management**: Make it easy to manage the ADRs.
- **Ensure appropriate tracking and review**: Make it easy to track and review the changes in the ADRs.

## Considered Options

1. Use Github Issues
2. Use Github Discussions
3. Use a shared ADR repository
4. Use an `adr` directory in the repo

## Decision Outcome

It was decided to use an `adr` directory in the repo to store ADRs. This approach provides a low barrier of entry for developers to document decisions and ensures that the decisions are tracked and reviewed appropriately.

Additionally, this change does not impact other teams or repositories, and it is easy to manage and maintain. We can experiment with this decision and if it works promote it to other repositories.

### Consequences

- **Positive**:
  - Low barrier of entry for developers to document decisions.
  - Easy to manage and maintain.
  - Ensures appropriate tracking and review of decisions via git history and code review.
- **Negative**:
  - Requires developers to be aware of the ADR process and where to find the ADRs.
  - May require additional tooling to manage and maintain the ADRs.
  - May require additional training for developers to understand the ADR process and how to use it effectively.

