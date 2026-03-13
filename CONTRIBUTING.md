# Contributing to opentdf/platform

Thank you for your interest in contributing to OpenTDF! This document describes
how to engage with the community, report issues, request features, and contribute
code.

## Code of Conduct

This project is governed by the OpenTDF [Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold this code.

## Community Feedback

| Goal | Where to go |
|---|---|
| Report a bug | [Open an issue](https://github.com/opentdf/platform/issues/new/choose) |
| Request a feature or share an idea | [Start a Discussion](https://github.com/opentdf/platform/discussions) |
| Ask a question | [GitHub Discussions — Q&A](https://github.com/opentdf/platform/discussions/categories/q-a) |
| Suggest a docs improvement | [Open an issue in opentdf/docs](https://github.com/opentdf/docs/issues/new) |

Feature requests and questions from all OpenTDF repos are welcome here —
platform Discussions is the central community space for the project.

## How to Contribute

1. **Check first**: look at [open issues](https://github.com/opentdf/platform/issues)
   and [Discussions](https://github.com/opentdf/platform/discussions) to avoid
   duplicating effort.
2. **Align before building**: for anything non-trivial, open an issue or Discussion
   to agree on approach before investing in a PR.
3. **Fork and branch**: fork the repository and create a branch from `main`
   (see [Branch Naming](#branch-naming) below).
4. **Make your changes**: follow the [Development Setup](#development-setup) and guidelines below.
5. **Sign off your commits**: see [DCO](#developer-certificate-of-origin-dco) below.
6. **Open a pull request**: a [maintainer](CODEOWNERS) will review and merge.

## Development Setup

For a complete walkthrough, see [docs/Contributing.md](docs/Contributing.md).

Quick summary:
1. Install [Go](https://go.dev/) (see `go.mod` for the required version).
2. Run `.github/scripts/init-temp-keys.sh` to create local dev keys.
3. Run `docker compose up` to start Postgres and Keycloak.
4. Copy and configure `opentdf-dev.yaml` as your `opentdf.yaml`.
5. Run `go run github.com/opentdf/platform/service start` to start the server.

## Branch Naming

Use `<type>/<short-description>`:

| Type | When to use |
|---|---|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `chore` | Maintenance, dependency updates, CI |
| `docs` | Documentation only |
| `refactor` | Code restructuring without behavior change |
| `test` | Adding or updating tests |

If the branch is tied to a ticket, you may prefix it with the ticket ID:
`feat/DSPX-1234-short-description`.

Examples: `feat/attribute-wildcard`, `fix/kas-timeout`, `docs/contributing-guide`

## Commit Messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer(s)]
```

- **type**: same values as branch naming above
- **scope**: optional, the subsystem affected (e.g., `sdk`, `kas`, `policy`)
- **description**: present tense, lowercase, no trailing period
- **body**: explain *why*, not *what* — the diff shows what changed

Examples:
```
feat(sdk): add wildcard support for attribute values

fix(kas): correct timeout handling on rewrap requests

docs: add branch naming and commit format guide
```

## Pull Request Guidelines

- Reference the relevant issue or Discussion in the PR description.
- Keep PRs focused — one logical change per PR is easier to review and revert.
- Update documentation for any interface or behavior changes.
- Ensure all CI checks pass before requesting review.
- Run `make lint` and `make test` before pushing.

## Developer Certificate of Origin (DCO)

To ensure that contributions are properly licensed and that the project has the right to distribute them, this project requires that all contributions adhere to the Developer Certificate of Origin (DCO).

### What is the DCO?

The DCO is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project. It is a simple statement asserting your rights to contribute the code.

### How to Comply with the DCO

Compliance is straightforward. When you contribute code, you simply need to "sign off" on your commits. You do this by adding a `Signed-off-by` line to your Git commit messages:

Signed-off-by: Your Real Name your.email@example.com
**Using the `-s` flag with `git commit`**

The easiest way to do this is to use the `-s` or `--signoff` flag when making your commit:

```bash
git commit -s -m "Your descriptive commit message here"
```
This automatically appends the Signed-off-by line to your commit message using the name and email address configured in your local Git settings. Ensure your Git `user.name` and `user.email` are set correctly to your real name and a valid email address.

### What does "Signing Off" mean?

By adding the Signed-off-by line, you are certifying to the following (from [developercertificate.org](https://developercertificate.org/)):

> Developer Certificate of Origin
> Version 1.1
>
> Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
>
> Everyone is permitted to copy and distribute verbatim copies of this
> license document, but changing it is not allowed.
>
>
> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
>    have the right to submit it under the open source license
>    indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>    of my knowledge, is covered under an appropriate open source
>    license and I have the right under that license to submit that
>    work with modifications, whether created in whole or in part
>    by me, under the same open source license (unless I am
>    permitted to submit under a different license), as indicated
>    in the file; or
>
> (c) The contribution was provided directly to me by some other
>    person who certified (a), (b) or (c) and I have not modified
>    it.
>
> (d) I understand and agree that this project and the contribution
>    are public and that a record of the contribution (including all
>    personal information I submit with it, including my sign-off) is
>    maintained indefinitely and may be redistributed consistent with
>    this project or the open source license(s) involved.

### Using Your Real Name

Please use your real name (not a pseudonym or anonymous contributions) in the Signed-off-by line.

### What if I forgot to sign off my commits?

If you have already made commits without signing off, you can amend your previous commits:

For the most recent commit:
```bash
git commit --amend -s
```
If you need to update the commit message as well, you can omit the -m flag and edit it in your editor.

For older commits: You will need to use interactive rebase:
```bash
git rebase -i --signoff HEAD~N # Replace N with the number of commits to rebase
```
Follow the instructions during the interactive rebase. You might need to force-push (git push --force-with-lease) your changes if you've already pushed the branch. Be careful when force-pushing, especially on shared branches.

We appreciate your contributions and your adherence to this process ensures the legal integrity of the project for everyone involved. If you have any questions about the DCO, please don't hesitate to ask.
