# Release security runbook

This runbook turns the repository's security policy into a repeatable release
gate. A release is a reviewed `v*` tag created from the protected `main` branch;
the tag itself does not publish to a package index.

## Repository controls

- Protect `main` and release tags. Require pull requests, an independent review,
  resolved review threads, and all `CI` jobs before merge.
- Restrict workflow changes to trusted reviewers. GitHub Actions are pinned to
  full commit SHAs, with their release tags recorded in comments so Dependabot
  can propose auditable updates.
- Keep the default `GITHUB_TOKEN` read-only. Only the tag-provenance job receives
  `id-token: write` and `attestations: write`; no pull-request job receives a
  secret or a write-capable token.
- Enable private vulnerability reporting, Dependabot alerts and security
  updates, secret scanning, push protection, and immutable releases where the
  repository host supports them.
- Do not approve a dependency or action update until its upstream release and
  changed commit have been reviewed. Never replace an immutable action SHA with
  a mutable tag.

## Required gates

The workflow must pass on Python 3.11, 3.12, 3.13, and 3.14. It runs the synthetic offline
tests, byte-compiles source and tests, checks the installed dependency graph,
lints all source and tests with the Ruff policy in `pyproject.toml`, type-checks
all source with the mypy policy in `pyproject.toml`, audits both application and
CI dependencies without vulnerability ignores, builds both distribution
formats, validates their metadata and wheel contents, installs and invokes the
built wheel in a clean environment, installs the source archive separately, and
runs its installed zero-key workflow end to end. It then emits a CycloneDX SBOM
plus SHA-256 manifest. New code must not add exclusions or weaken either static-analysis
policy merely to make a gate pass.

Networked Reddit or X smoke tests are intentionally outside public CI. Run them
only from a trusted environment with operator-owned, least-privilege credentials
and the smallest practical collection and cost limits. Never attach live output,
tokens, retained source text, a local database, or a salt to a CI run or release.

## Release procedure

1. Start from a clean checkout of reviewed `main`; confirm the version and
   changelog/release notes describe the intended changes.
2. Confirm every required CI job passed for the exact commit and inspect the
dependency-audit and packaging logs. There are no accepted vulnerability
ignores in the baseline. The application audit and CycloneDX file describe the
runtime graph; the separate pinned CI-requirements audit covers the build backend,
installer, and release tooling.
Manually review direct and transitive dependency licenses for compatibility with
the intended distribution and record the result in the release notes or reviewed
checklist; this judgment is deliberately not represented as an automated CI gate.
3. Recheck the current Reddit and X platform terms, pricing, approved uses, data
   retention, and deletion obligations. Update dated policy metadata when it is
   stale; do not infer that a previous approval still applies.
4. Create a signed, protected `v*` tag. The tag run rebuilds the package and
   creates GitHub artifact attestations using short-lived OIDC credentials.
5. Download `python-package`, then verify it before any publication:

   ```bash
   cd python-package
   sha256sum --check SHA256SUMS
   python -m pip install --no-deps --force-reinstall ./*.whl
   python -c "import feedback_aggregator"
   ```

6. Inspect the wheel, source archive, SBOM, and release notes for credentials,
   local paths, user content, databases, salts, or generated reports. Stop if
   any sensitive or unexplained file is present.
7. If package-index publication is added later, use that index's trusted
   publisher with a narrowly scoped GitHub environment and required approval.
   Do not introduce a long-lived upload token. Attest the exact files that are
   published and verify the index hashes afterward.

## Stop and incident conditions

Do not release with a failed gate, high or critical known vulnerability,
unreviewed scanner suppression, stale platform-policy metadata, unexpected
network activity, or suspected secret/private-data exposure. Revoke exposed
credentials, preserve only redacted diagnostic evidence, follow `SECURITY.md`,
and cut a corrected release from a reviewed commit instead of modifying an
existing release asset.
