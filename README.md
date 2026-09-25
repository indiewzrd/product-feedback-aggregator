# Product Feedback Aggregator

A local-first Python CLI that converts permitted product-feedback inputs into
reviewable, explainable themes. It works offline with JSON files, can use
operator-owned Reddit and X API credentials, or can run two fixed Apify Actors
without official Reddit/X developer credentials when that remote, paid mode is
explicitly configured and approved.

This repository is an alpha. It helps organize observed feedback; it does not
measure market prevalence, identify people, or make product decisions.

## Quick start

Python 3.11 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
python -m pip install -e .
feedback init
feedback check
feedback collect --plan
feedback run
```

`feedback init` creates a synthetic example and a `feedback.yml` file without
overwriting existing files. The same workflow is available directly from this
repository:

```bash
feedback run --example
```

Generated databases, salts, and reports are private local artifacts and are
ignored by Git.

## What the application does

1. Collects bounded records from JSON/NDJSON, exact public URLs, an explicit
   external NDJSON boundary, Reddit's approved Data API, X API v2, or the fixed
   Reddit/X Apify connectors.
2. Normalizes text, provenance, timestamps, pseudonymous author keys, engagement,
   acquisition metadata, retention, and policy capabilities.
3. Separately estimates relevance, noise, spam, and automation likelihood.
4. Extracts atomic signals, detects exact repetition, groups lexically similar
   signals, and ranks clusters with stored score components.
5. Writes versioned JSON and Markdown reports and explains any stored decision.

The deterministic local pipeline is always available. Collected content is never
sent to a model provider by the CLI, and source text cannot invoke tools or change
program instructions.

## Architecture

The Python CLI and library are the product. The Codex and Claude skills are thin,
equivalent operating guides around that same interface; removing either skill
does not remove application behavior.

```text
bounded connectors -> canonical records -> private SQLite -> local analysis -> reports
 JSON / URL /       provenance + TTL       lineage + runs    quality, signals   JSON +
 external / API /                                              groups, ranking   Markdown
 Apify
```

Connectors do acquisition and normalization only. Analysis never reaches back to
a source, reporting never performs collection or inference, and every derived
item retains stable lineage to the record that produced it. This separation is
why the application remains testable without a coding agent or network access.

## Commands

```text
feedback init [--directory DIR]
feedback check [--probe]
feedback collect --plan
feedback collect [--strict]
feedback reconcile [SOURCE]
feedback analyze [--from STAGE]
feedback report
feedback run [--example] [--strict]
feedback explain ID
feedback review {include,exclude,clear} ID [--rationale TEXT]
feedback purge [SOURCE] [--yes]
```

Add `--json` before or after the command for a stable machine-readable envelope.
`feedback check` and `feedback collect --plan` do not collect data. `--probe`
may make read-only HEAD requests to configured exact-URL sources; social checks
remain local and never spend API resources.

## Source configuration

The bundled [example configuration](examples/feedback.example.yml) demonstrates
the zero-key workflow. The published [configuration schema](schemas/feedback.schema.json)
and [input schema](schemas/input.schema.json) document the structural format. The
authoritative semantic, credential, policy-freshness, and cost-readiness check is
always `feedback check`.
JSON files may contain one record, an array, or a `records` wrapper; NDJSON and external
collectors emit one input-schema record per line. Source credentials are referenced
by environment-variable name; secret values never belong in YAML, command-line
arguments, reports, or the repository.

### Reddit

The connector uses a registered, operator-owned, explicitly approved OAuth app.
It searches posts and then retrieves bounded comment trees. It is best-effort
discovery, not a complete comment archive. Required options include:

```yaml
- id: reddit-feedback
  type: reddit
  max_items: 500
  options:
    approval_confirmed: true
    client_id_env: REDDIT_CLIENT_ID
    client_secret_env: REDDIT_CLIENT_SECRET
    user_agent: "macos:feedback-aggregator:0.1.0 (by /u/your_username)"
    subreddits: [yourcommunity]
    query: '"Acme Notes" OR "Acme"'
    max_comments_per_post: 100
  policy:
    policy_version: reddit-2026-09-25
    policy_version_checked_at: "2026-09-25"
    max_cost_usd: 0
```

Reddit currently requires approval for API access, including noncommercial apps.
Recheck the linked platform policies before every public release.

This alpha does not run a background deletion service. Reddit records receive a
hard expiry of no more than 48 hours, further reduced by configured policy; the
CLI purges expiry during `reconcile`, `analyze`, and `run`, and before `explain`
returns evidence. Run the CLI at least as often as the configured reconciliation
interval. Active `/api/info` removal
reconciliation is not yet implemented.

### X

The connector uses an operator-owned bearer token, Recent Search or the selected
account's mentions endpoint, and mandatory resource and dollar caps:

```yaml
- id: x-feedback
  type: x
  max_items: 500
  options:
    approval_confirmed: true
    bearer_token_env: X_BEARER_TOKEN
    mode: recent_search
    query: '"Acme Notes" -is:retweet lang:en'
  policy:
    policy_version: x-pricing-2026-09-25
    policy_version_checked_at: "2026-09-25"
    cost_per_resource_usd: 0.005
    max_cost_usd: 2.50
```

Pricing is configuration, not a permanent code constant. `collect --plan` shows
the exact query and per-invocation upper-bound cost, and collection reserves the
worst-case page cost before each request. A resumed checkpoint is a new invocation,
so operators must use their X developer dashboard to monitor cumulative spend.

Reddit and X checkpoints are versioned and bound to the query, source settings,
and local author salt. A failure after a complete page preserves that validated
page and its next-page checkpoint in the default isolated mode, so avoidable paid
reads are not repeated. `--strict` intentionally rolls back all source data and
checkpoints if any source fails; a later strict retry can therefore repeat an API
read or charge.

X records receive a hard expiry of no more than 24 hours, further reduced by
configured policy. This alpha does not yet implement X Batch Compliance jobs and
therefore cannot promise active deletion while the CLI is dormant. Reports refuse
expired rows; use `feedback reconcile` from a trusted scheduler if retained X data
requires an operational deletion deadline.

### Apify: Reddit and X without official platform API keys

The optional `reddit_apify` and `x_apify` source types use Apify's REST API with
these fixed community Actors:

- [`trudax/reddit-scraper-lite`](https://apify.com/trudax/reddit-scraper-lite)
- [`apidojo/twitter-scraper-lite`](https://apify.com/apidojo/twitter-scraper-lite)

This mode does not require Reddit or X developer credentials. It does require an
Apify account and an `APIFY_TOKEN`, may incur Actor charges, and sends query terms
and collected public data to Apify. Availability of an Actor is not permission
to use it; the operator remains responsible for platform terms, Apify terms,
applicable law, and the intended use.

Use an exact Actor build number from the Actor's Apify Console page. Floating
tags such as `latest` are rejected because both Actors are community-maintained
code and their schemas can change.

```yaml
- id: reddit-apify-feedback
  type: reddit_apify
  max_items: 500
  options:
    approval_confirmed: true
    token_env: APIFY_TOKEN
    actor_build: 1.2.345          # replace with the reviewed exact build
    searches: ['"Acme Notes" OR "Acme"']
    search_community_name: acmenotes
    search_comments: true
    max_post_count: 300
    max_comments: 20
    include_nsfw: false
    initial_lookback_days: 30
    overlap_hours: 48
  policy:
    acquisition_mode: third_party_scraper
    approval_required: true
    approval_reference: Operator-reviewed Reddit and Apify terms
    remote_processing_allowed: true
    raw_ttl_hours: 48
    deletion_reconcile_interval_hours: 48
    redistribution_mode: ids_links_aggregates
    max_cost_usd: 2.00
    policy_version: reddit-apify-review-2026-09-25
    policy_version_checked_at: "2026-09-25"

- id: x-apify-feedback
  type: x_apify
  max_items: 500
  options:
    approval_confirmed: true
    token_env: APIFY_TOKEN
    actor_build: 1.2.345          # replace with the reviewed exact build
    search_terms: ['"Acme Notes"', '@acmenotes']
    sort: Latest
    tweet_language: en
    exclude_retweets: true
    initial_lookback_days: 7
    overlap_hours: 24
  policy:
    acquisition_mode: third_party_scraper
    approval_required: true
    approval_reference: Operator-reviewed X and Apify terms
    remote_processing_allowed: true
    raw_ttl_hours: 24
    deletion_reconcile_interval_hours: 24
    redistribution_mode: ids_links_aggregates
    max_cost_usd: 2.00
    policy_version: x-apify-review-2026-09-25
    policy_version_checked_at: "2026-09-25"
```

`feedback collect --plan` is offline and reports the exact Actor/build, queries,
maximum items, and per-run dollar cap. Collection passes both `maxItems` and
`maxTotalChargeUsd` to Apify, disables automatic Actor restart, and never places
the token in a URL. Normal mode checkpoints the run ID immediately and the
dataset offset after every completed page, allowing a later invocation to resume
without starting another Actor. `--strict` deliberately disables those durable
mid-source checkpoints and can therefore repeat a paid run after failure.

The connectors accept only the fixed Actor IDs and `api.apify.com`, reject HTTP
redirects, validate social start URLs, and discard profiles, avatars, media,
raw HTML, and other unnecessary fields. Reddit community/user result objects are
ignored; only Reddit posts/comments and X tweet objects are normalized.

Apify MCP is optional for documentation and manual diagnostics. It is not the
application data plane: `call-actor` returns storage IDs rather than results,
and retrieving a dataset through an AI client can place raw feedback in the
agent context. Claude and Codex should invoke the local CLI instead. See the
[Apify MCP documentation](https://docs.apify.com/integrations/mcp).

### External collectors

An external collector must emit canonical NDJSON through a file, standard input,
or an explicitly configured absolute executable plus argv. Collector code is
trusted arbitrary code. The runner uses no shell, passes a minimal environment,
closes inherited descriptors, provides no credential variables, and enforces
time and output limits. Imported records are labeled `external` and
`policy_assurance: user`.

### Optional semantic-provider boundary

The v0.1 CLI always uses the deterministic analyzer. The library also contains a
strict, cached adapter for an explicitly configured local subprocess so future
analysis integrations can use a local model without coupling the core to one AI
vendor. It accepts and returns versioned bounded JSON, uses no shell, defaults to
zero retries, and stores only input/prompt hashes plus validated output.

This adapter is not an OS sandbox, is not invoked by `feedback run`, and ships no
hosted-model transport. A selected executable is trusted code and could access
the operator's files or network independently. See
[the semantic-provider contract](docs/SEMANTIC_PROVIDERS.md).

## Security model

Security-sensitive behavior is fail-closed:

- exact HTTP(S) pages are protected against SSRF, unsafe redirects, DNS rebinding,
  decompression bombs, oversized bodies, slow responses, and unexpected MIME types;
- generic URL collection refuses Reddit, X, Twitter, `redd.it`, and `t.co` domains;
- JSON/YAML parsing is bounded and rejects duplicate keys, non-finite numbers,
  custom tags, aliases, and excessive nesting;
- SQLite uses parameterized statements, foreign keys, cascade invalidation,
  private file permissions, and secure deletion settings;
- social cursors are query-scoped, strict JSON checkpoints, and completed partial
  pages are committed atomically with their cursor in non-strict mode;
- Apify Actor IDs are fixed, builds are exact-pinned, POST redirects and implicit
  retries are disabled, tokens use authorization headers, and server-side item
  and total-charge caps bound each run;
- optional subprocesses run without a shell, inherit only a minimal environment,
  and have combined output and time limits; failure cleanup terminates their
  process trees, and POSIX also rejects lingering children after parent success;
- terminal control sequences are removed and report data is escaped;
- logs and errors contain metadata, not source text, secrets, or response bodies;
- telemetry and update checks are absent.

See [SECURITY.md](SECURITY.md) and [the threat model](docs/THREAT_MODEL.md) for the
supported boundary and remaining risks. A local process running as the same OS
user, a trusted external collector or local-provider executable, the operating
system, and machine administrator remain outside the application's security
boundary.

## Testing

All default tests are synthetic and make no public network calls:

```bash
python -m pip install -e '.[dev]'
pytest
python -m ruff check src tests
python -m mypy src
python -m compileall -q src tests
python -m pip_audit --strict --progress-spinner=off .
```

Live Reddit/X/Apify smoke tests are intentionally not present in public CI. Run
them only with your own approved credentials and a tightly bounded test configuration.
Synthetic tests cover their request/response contracts, cost caps, pagination,
failure checkpoints, stale-cursor rejection, and retention behavior.

## Project layout

```text
src/feedback_aggregator/       application and library
src/feedback_aggregator/connectors/ built-in acquisition adapters
tests/                         offline unit, contract, and end-to-end tests
examples/                      synthetic zero-key example
schemas/                       published configuration and input schemas
.agents/skills/                Codex workflow wrapper
.claude/skills/                Claude workflow wrapper
docs/                          PRD, threat model, and operating guidance
```

Licensed under Apache-2.0. Contributions should preserve the local-first,
explainable, policy-aware design.
