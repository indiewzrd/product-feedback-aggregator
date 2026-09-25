# Reddit and X setup

Reference date: 25 September 2026. Recheck every linked source before release or
live use. Free/open-source distribution does not create an access exemption.

## Reddit

The supported connector uses an operator-owned, approved OAuth application. It
never falls back to HTML, RSS, anonymous JSON, cookies, or browser automation.

1. Review and satisfy Reddit's
   [Responsible Builder Policy](https://support.reddithelp.com/hc/en-us/articles/42728983564564-Responsible-Builder-Policy).
2. Register the application and request the access described in
   [Accessing Reddit Data](https://support.reddithelp.com/hc/en-us/articles/14945211791892-Developer-Platform-Accessing-Reddit-Data).
3. Configure environment-variable *names* and a truthful unique user agent.
4. Limit subreddits, product terms, posts, comments, pages, and runtime. The
   configured `total_timeout_seconds` is one deadline shared by all HTTP
   requests in a source invocation, not a fresh allowance for each page.
5. Keep raw retention short and reconcile removals before report/export.

The implementation uses post search followed by bounded comment-tree retrieval.
Reddit does not document a general comment-search endpoint, so coverage is
best-effort. The adapter records fullname cursors and rate-limit headers described
in the [Data API Wiki](https://support.reddithelp.com/hc/en-us/articles/16160319875092-Reddit-Data-API-Wiki).

Incremental state stores a high-water fullname for each configured subreddit and
an in-progress listing/comment checkpoint. The state is versioned and fingerprinted
to the query, subreddits, comment limits, author salt, and other stream-defining
settings. Changing those settings fails closed with instructions to purge the old
source rather than silently skipping records.

The alpha currently enforces bounded local expiry when the CLI runs; active
`/api/info` removal reconciliation is not implemented.

## X

The supported connector uses an operator-owned developer application and API v2.
It never uses browser automation, guest tokens, private endpoints, or scraping.

1. Create an approved Project and App following
   [Getting Access](https://docs.x.com/x-api/getting-started/getting-access).
2. Use a least-privilege bearer token for public Recent Search, or an appropriate
   user-context token for the selected account's operations.
3. Configure the current per-resource price, its review date, a maximum number of
   posts, and a maximum dollar cost.
4. Inspect `feedback collect --plan` before a paid run.
5. Reconcile removals according to the
   [Developer Guidelines](https://docs.x.com/developer-guidelines).

Recent Search covers the previous seven days. Full Archive is intentionally not
part of the alpha connector. Current behavior and limits are documented in
[Search Posts](https://docs.x.com/x-api/posts/search/introduction),
[rate limits](https://docs.x.com/x-api/fundamentals/rate-limits), and
[pricing](https://docs.x.com/x-api/getting-started/pricing).

Incremental state uses `since_id` plus a resumable `pagination_token`, and it is
fingerprinted to the exact query, mode, settings, and author salt. The connector
does not automatically retry a social request. If a later page fails, the default
source-isolated mode atomically stores fully validated earlier pages and their
checkpoint while marking the source and run partial. `--strict` instead rolls
everything back, so a strict retry can repeat a paid page.

[X Batch Compliance](https://docs.x.com/x-api/compliance/batch-compliance/introduction)
jobs are not implemented in this alpha. The local TTL is purged only when
`reconcile`, `analyze`, or `run` executes, so schedule `feedback reconcile` when
an operational 24-hour deletion deadline applies.

## Apify alternatives without official platform API keys

The application also supports two opt-in third-party acquisition modes:

- `reddit_apify`, fixed to
  [`trudax/reddit-scraper-lite`](https://apify.com/trudax/reddit-scraper-lite);
- `x_apify`, fixed to
  [`apidojo/twitter-scraper-lite`](https://apify.com/apidojo/twitter-scraper-lite).

They avoid Reddit/X developer credentials, but they are not anonymous or local:
running either Actor requires an Apify account token, can incur charges, and
causes Apify and the Actor maintainer's code to process source queries and public
social data. Both Actors are community-maintained dependencies. The connector
therefore rejects arbitrary Actor IDs and floating build tags, and requires the
operator to supply an exact reviewed build number.

Before collection, the configuration must contain all of the following:

1. `options.approval_confirmed: true` after the operator reviews the relevant
   platform and Apify terms;
2. `policy.acquisition_mode: third_party_scraper`;
3. an explicit `policy.remote_processing_allowed: true`;
4. a positive per-run `policy.max_cost_usd`;
5. versioned, fresh policy-review metadata and the ordinary short social TTL.

`feedback check` remains local and only checks the named token environment
variable. `feedback collect --plan` remains offline. Actual collection uses the
asynchronous [Run Actor API](https://docs.apify.com/api/v2/actors-runs-post),
polls the returned run ID, and paginates the default dataset with the
[dataset items API](https://docs.apify.com/api/v2/dataset-items-get).

The POST carries the token only in an `Authorization: Bearer` header. It also
sets an exact build number, `restartOnError=false`, the API-level `maxItems`
charged-item bound, and `maxTotalChargeUsd`. The Actor input independently sets
its own `maxItems`. No request is automatically retried after it may have reached
Apify, because that could create a second paid run.

In normal source-isolated mode, the run and dataset IDs are committed immediately
after run creation and the dataset offset is committed after each validated page.
If the Actor is still running when the local deadline is reached, the next CLI
invocation resumes it. If a later dataset page fails, already normalized pages
and their offset are retained. Strict mode intentionally suppresses these
mid-source commits and can repeat paid work after interruption.

Incremental searches retain a source-scoped high-water timestamp, reread a
bounded overlap window, and deduplicate using Reddit fullname or X tweet ID.
Search coverage and platform pagination are best-effort and must not be reported
as a complete population. A settings or build change invalidates the checkpoint
and requires an explicit source purge.

The hosted [Apify MCP server](https://docs.apify.com/integrations/mcp) is useful
for Actor documentation or manual diagnostics, and its OAuth flow avoids placing
a token in an AI client's configuration. It is not used by the application.
`call-actor` returns run/storage identifiers, and reading the dataset through MCP
would send raw feedback through the AI client context. Claude and Codex operating
this repository should call the local CLI so cost, state, validation, privacy,
and lineage remain deterministic.

## What the tool can and cannot guarantee

The application enforces its configured transport, retention, export, and budget
rules and records the assumptions used. It cannot grant platform approval,
determine whether a user's purpose is commercial, or guarantee complete discovery
or deletion coverage. Users remain responsible for authorization and applicable
law and policy.

The batch CLI is not a daemon. Neither Reddit `/api/info` nor X Batch Compliance
actively synchronizes removals yet. The Apify connectors also do not presently
delete the Actor's remote dataset after import; operators must apply their Apify
storage-retention settings. These limitations are explicit so that a successful
request is never presented as a compliance guarantee.
