# Contributing to OpenTDF

This project requires two things from every commit:

1. **DCO sign-off** — a `Signed-off-by` trailer asserting your right to contribute the code
2. **Commit signature verification** — a cryptographic (GPG or SSH) signature proving the commit came from you

Both are enforced by CI and org-level rulesets. The combined command is:

```bash
git commit -s -S -m "Your descriptive commit message here"
```

Read on for setup details.

---

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

---

## Commit Signature Verification

In addition to the DCO sign-off, this organization requires that every commit is **cryptographically signed** so that GitHub can verify the commit actually came from you. This is a separate requirement from the DCO — you need both.

| | DCO sign-off (`-s`) | Commit signature (`-S`) |
|---|---|---|
| **What it is** | `Signed-off-by:` trailer in the commit message | Cryptographic GPG or SSH signature on the commit |
| **What it proves** | You have the right to submit the code | The commit actually came from you |
| **Checked by** | DCO probot | GitHub signature verification + org ruleset |

### Setting Up Commit Signing

You can sign commits with either a **GPG key** or an **SSH key**. Choose whichever you prefer.

#### Option A: GPG signing

Follow GitHub's guide to [generate a new GPG key](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key) and [add it to your GitHub account](https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account), then configure Git:

```bash
git config --global user.signingkey YOUR_GPG_KEY_ID
git config --global gpg.format openpgp
```

#### Option B: SSH signing

If you already have an SSH key added to GitHub, you can reuse it for commit signing. See GitHub's guide on [SSH commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification), then configure Git:

```bash
git config --global user.signingkey ~/.ssh/id_ed25519.pub  # Replace with /path/to/your/public_key.pub if different
git config --global gpg.format ssh
```

### Making It the Default

To avoid passing `-S` on every commit, enable automatic signing:

```bash
git config --global commit.gpgsign true
```

With this set, `git commit -s -m "message"` will automatically sign and sign-off every commit.

### Verifying Your Setup

After configuring, make a test commit and check that it shows as **Verified** on GitHub:

```bash
git log --show-signature -1
```

### What if my commits are not verified?

If your PR is blocked because commits are not verified:

For the most recent commit:
```bash
git commit --amend -S --no-edit
```

For older commits:
```bash
git rebase --exec 'git commit --amend --no-edit -S' HEAD~N  # Replace N with the number of commits
```

You will need to force-push afterward:
```bash
git push --force-with-lease
```

For full details, see [GitHub's commit signature verification docs](https://docs.github.com/en/authentication/managing-commit-signature-verification).

---

We appreciate your contributions and your adherence to this process ensures the legal integrity of the project for everyone involved. If you have any questions about the DCO or commit signing, please don't hesitate to ask.
