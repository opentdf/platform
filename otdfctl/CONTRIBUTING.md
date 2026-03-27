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