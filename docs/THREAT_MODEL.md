# Threat model

Reference date: 25 September 2026

## Assets

- Reddit and X API credentials, Apify tokens, and application identity;
- raw feedback text, source IDs, URLs, timestamps, and pseudonymous author keys;
- local database, author salt, cursors, run manifests, and reports;
- the integrity of classifications, clusters, rankings, and release artifacts;
- the user's machine, network, and paid API budget.

## Trust boundaries

```text
Untrusted sources ──> bounded connectors ──> normalized records ──> local analysis
 Reddit / X / URL       API + SSRF gates       SQLite lineage       no tools/models
 JSON / NDJSON
 Apify Actors           fixed IDs + budgets

Trusted user config ──> validated config ──> explicit limits/policy capabilities
External collector ──> isolated subprocess ──> external-labelled NDJSON
Local provider adapter ─> bounded subprocess ─> validated cached JSON (library only)
```

Source text, source metadata, redirects, DNS answers, JSON/YAML, HTTP headers,
model-like instructions embedded in text, and external collector output are
untrusted. The local user, selected executable collector, operating system,
Python runtime, certificate store, selected local-provider executable, and machine
administrator remain trusted or out of scope. The subprocess controls are a
bounded process interface, not an operating-system sandbox.

## Primary abuse cases and controls

| Threat | Controls | Verification |
|---|---|---|
| SSRF and cloud metadata access | HTTPS by default; strict URL parsing; IDNA normalization; all DNS answers must be global; connection pins the validated IP while TLS checks the original host; every redirect is revalidated; no ambient proxy/cookies | private IPv4/IPv6, mapped-IP, mixed-DNS, redirect, parser-confusion, timeout, and rebinding tests |
| Credential theft | fixed API origins, TLS verification, environment-name references, redaction, metadata-only diagnostics, no `.env`, private state permissions, minimal child environment | canary secrets absent from outputs and subprocess environment |
| Prompt or instruction injection | deterministic CLI algorithms; source content is data; the optional library provider receives one fixed-schema request and its output cannot select tools, shell, network, filesystem, or SQL actions | hostile instructions produce ordinary signals only; provider output is schema validated |
| Command injection | no shell; absolute executable plus bounded argv; no source text in argv; minimal environment; closed descriptors; trusted-code warning | shell metacharacters remain literal; timeout/output/nonzero failures and descendant processes are contained |
| Parser denial of service | file/line/body/decompressed-byte/item/depth/node/time limits; duplicate keys and non-finite numbers rejected; streamed NDJSON | malformed, deeply nested, duplicate, huge, gzip-bomb, and slow fixtures |
| Report/terminal injection | control-sequence stripping, bounded text, JSON encoding, Markdown escaping, no executable HTML | ANSI/OSC/Markdown fixtures cannot alter terminal or create active output |
| SQL injection or stale derived data | parameterized statements, stable IDs, foreign keys, cascades, transactions, expiry and reconciliation before analysis/report | malicious strings remain data; purge removes and invalidates descendants |
| Paid-API runaway | non-network plan, maximum items/pages/source-wide HTTP runtime/cost, worst-case reservation before each X page, no address-failover retry after an API request may have been sent, query-scoped durable cursors, atomic partial-page persistence | synthetic X tests prove caps are never exceeded and completed pages resume without avoidable repeat reads |
| Paid Actor runaway | fixed Actor IDs and exact builds; explicit remote-processing approval; offline plan; API and Actor item caps; server-side total-charge cap; automatic restart disabled; no uncertain POST retry; run ID and dataset offsets committed in normal mode | synthetic Apify tests verify request caps, header authentication, resume without a second POST, strict normalization, and partial-page checkpoints |
| Cross-platform profiling | salted per-install pseudonyms; no raw author export by default; no identity linking or sensitive-trait inference | normalization and report tests contain no original author value |
| Supply-chain compromise | minimal exact direct pins, dependency auditing, CycloneDX SBOM, static/secret scanning, full-SHA Actions, isolated builds, protected publishing, checksummed and attested release bundles | CI and release checklist; no high/critical unresolved findings |

## URL security notes

OWASP recommends disabling automatic redirects and validating destinations for
SSRF-sensitive fetches. This application handles redirects itself and re-runs
syntax, domain, DNS, and public-IP validation on every hop. Generic URL input
never fetches Reddit, X, Twitter, `redd.it`, or `t.co`; those domains require
their dedicated connectors.

The application cannot prevent a permitted public website from returning
sensitive material that the user was already authorized to access through some
machine-wide mechanism. It therefore sends no ambient cookies, proxy credentials,
or authorization headers in the generic connector.

## Data lifecycle

Each record stores its source, native identity, retrieval query, policy class,
expiry, and derived lineage. Conservative defaults expire Reddit raw fields
within 48 hours and X hydrated text within 24 hours. Reconciliation or purge
removes raw text and identifying fields and invalidates dependent signals,
clusters, scores, optional provider-cache outputs, and generated reports.
Filesystem snapshots and backups are an OS/operator concern; SQLite secure
deletion cannot erase historical snapshots.

## Residual risks

- Lexical heuristics can misclassify legitimate feedback. Suppression remains
  inspectable and is not a statement about a person's identity.
- DNS pinning protects the request path implemented here, but a compromised OS,
  resolver, CA store, Python runtime, or local administrator is out of scope.
- An external collector is arbitrary trusted code and can access whatever the OS
  account permits independently of this wrapper.
- An enabled local semantic-provider executable has the same trusted-code risk.
  The v0.1 CLI does not invoke it; a library integration must enforce source
  remote-processing policy before supplying text.
- Strict collection deliberately rolls back social checkpoints with all other
  source data. A strict retry can repeat a previously completed API page or cost;
  use the default source-isolated mode when resumable paid reads are preferred.
- Apify Actors are third-party, community-maintained executable dependencies and
  remotely retain run inputs, logs, and datasets according to Apify account
  settings. Exact build pinning prevents silent upgrades but does not make the
  selected build trustworthy; operators must review upgrades and remote retention.
- Apify does not document an idempotency key for Actor-run creation. A lost POST
  response is not retried, but the application cannot recover an unknown run ID;
  the operator must inspect Apify Console before starting another collection.
- Platform rules, endpoints, prices, and approvals change. A successful request
  is not proof that a use is lawful or approved.
- This alpha is a batch CLI, not a daemon. It does not yet run Reddit `/api/info`
  or X Batch Compliance removal jobs. Expiry is enforced whenever the CLI runs
  and expired rows cannot be reported, but a dormant local database is not
  automatically erased; operators needing a deletion deadline must schedule
  `feedback reconcile` within that interval.
- A local plaintext database protects permissions and minimizes retention but is
  not full-disk encryption. Use OS disk encryption for sensitive projects.
- Direct application and CI dependencies are exactly pinned, but transitive
  build/tool dependencies are not installed from a cross-platform hash lock.
  Review the SBOM and attestation; organizations requiring hermetic builds must
  add platform-specific, hash-locked constraints in their release environment.
