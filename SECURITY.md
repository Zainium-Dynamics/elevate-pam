# Security policy

elevate-pam sits in front of logins, so security reports get priority over everything else.

## Reporting a vulnerability

Please don't open a public issue for a security problem. Email
**alizain@zainiumdynamics.tech** instead, with:

- what the problem is and what an attacker could do with it
- the version or commit you tested
- steps or a config that shows it, if you have them

You can also use GitHub's private vulnerability reporting on this repository.

## What happens next

- You get a reply within 7 days.
- I confirm the problem, work on a fix and keep you updated.
- The fix is released first, then the details are published, normally within 90 days of
  your report, or sooner once a fix is out.
- You're credited in the advisory and the release notes, unless you'd rather not be.

## Supported versions

elevate-pam has no stable release yet. Fixes go into the latest version on `main` and into
the next release.

## Scope

In scope: the elevate-pam library and its built-in modules, the C API, its config parsing,
the `unix_chkpwd` helper and the `elevate-crypto` crate.

Out of scope: third-party C modules loaded through elevate-pam, and problems that need an
attacker to already be root.
