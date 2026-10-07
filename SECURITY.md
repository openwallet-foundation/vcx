# Security Policy

This project follows the [OpenWallet Foundation security vulnerability disclosure
policy](https://tac.openwallet.foundation/governance/security/).

## Supported versions

Security fixes are applied to the `main` branch and published in the next
release. Older releases are not patched; consumers are expected to upgrade to
the latest release.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security problems.

Report vulnerabilities privately through GitHub Security Advisories:

- <https://github.com/openwallet-foundation/vcx/security/advisories/new>

See GitHub's guide on [privately reporting a security
vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
if you are unfamiliar with the process.

If you are unable to use GitHub Security Advisories, contact the maintainers on
the `vcx` [Discord channel](https://discord.com/channels/1022962884864643214/1344319756324311123)
and ask for a private channel to disclose the issue. Do not include details of
the vulnerability in a public message.

Include as much of the following as you can:

- The affected crate(s) and version or commit.
- A description of the issue and its impact.
- Steps to reproduce, including a proof of concept where possible.
- Any suggested mitigation.

## What to expect

- Acknowledgement of your report within 5 business days.
- An initial assessment, including whether we consider it a vulnerability,
  within 10 business days.
- Coordinated disclosure: we aim to publish a fix and a GitHub Security Advisory
  (with a CVE where applicable) within 90 days of the report. We will keep you
  informed of progress and agree a disclosure date with you.
- Credit in the published advisory, unless you ask to remain anonymous.

## Scope

In scope: the crates and agents in this repository.

Out of scope: vulnerabilities in upstream dependencies (report those to the
relevant project, and let us know so we can bump the dependency), and issues
that require an already-compromised host or wallet.
