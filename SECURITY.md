# Security policy

## Supported versions

The project is pre-1.0. Security fixes are applied to the latest release and the
default branch. Do not use an older checkout for live social or Apify credentials.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository host's
private security-advisory feature. Do not open a public issue containing a
working exploit, credential, private feedback, or platform data. Include:

- affected version or commit;
- reproducible steps using synthetic data;
- likely impact and security boundary crossed;
- any suggested mitigation.

Maintainers should acknowledge a report within five business days, preserve the
reporter's confidentiality, assess affected versions, and coordinate a fix and
advisory before public disclosure. Never send real Reddit/X content or tokens as
part of a report.

## Credential handling

- Supply credentials through an OS secret facility where an integration is
  available, or through a documented environment-variable reference.
- Never put secret values in `feedback.yml`, CLI arguments, Git, reports, logs,
  screenshots, or issue descriptions.
- Use separate, least-privilege, read-only apps for this tool.
- Use a dedicated Apify token where account controls permit it, set an account
  spending limit, and review retained Actor inputs, logs, and datasets.
- Rotate a token immediately if it may have appeared in output or source control.
- The application never loads `.env` automatically or forwards API variables to
  an external collector.

## Release security gates

A release is blocked when there is an unresolved critical or high-severity
finding, a failing security test, an unexplained scanner exclusion, a secret in
the repository, or stale social-policy metadata. The release process should:

1. run the complete offline test matrix on supported Python and operating-system
   versions;
2. audit direct and resolved transitive runtime dependencies plus the pinned
   build backend, installer, and CI/release toolchain; manually review licenses
   and record that review in the release checklist (CI does not automate license
   compatibility decisions);
3. run static analysis, secret scanning, and dependency review;
4. build a wheel and source archive in an isolated environment;
5. generate an SBOM and preserve build provenance;
6. create attestations with short-lived OIDC; if package-index publication is
   added, use that index's OIDC trusted publisher rather than an upload token;
7. verify the installed artifact and bundled zero-key workflow.

This baseline follows the current final NIST Secure Software Development
Framework, [SP 800-218 v1.1](https://csrc.nist.gov/pubs/sp/800/218/final), and is
informed—but does not claim compliance with—the 2026 SSDF v1.2 public draft.
Network and supply-chain controls also follow the relevant
[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/).

## Platform data incidents

If credentials or retained source data may have been exposed, stop collection,
revoke credentials, preserve only redacted diagnostic evidence, run
`feedback purge`, follow the relevant platform notification process, and publish
a security advisory when users need to act.
