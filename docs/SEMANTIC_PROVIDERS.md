# Optional local semantic providers

The deterministic analyzer is the default and requires no provider, model key,
or network access. The library exposes an optional provider adapter for explicit
Python integrations. The v0.1 CLI validates configured provider availability but
does not invoke it during `feedback analyze` or `feedback run`. The supported
provider boundary is an operator-trusted local executable; this repository does
not ship a hosted-model transport.

## Security boundary

The executable runs with an argument vector, never a shell. It receives a
minimal environment, bounded standard input, a total timeout, and a combined
standard-output and standard-error limit. Its output is parsed as strict JSON,
must match schema version 1, and cannot select tools or application actions.

This boundary is not an operating-system sandbox. A configured executable is
trusted code running as the current user, so review it before enabling it. It
may implement a local model or, if an operator intentionally writes it that
way, send data elsewhere. That external data flow remains outside this
application's supported security boundary and must comply with every source's
processing policy.

## Configuration

Providers are omitted by default. An example explicit configuration is:

```yaml
providers:
  - id: local-semantic
    type: local_subprocess
    enabled: true
    command: [/absolute/path/to/provider]
    model: local-model-version
    output_schema_version: 1
    timeout_seconds: 30
    max_output_bytes: 1048576
    max_retries: 0
```

The executable path must be absolute. Retry count defaults to zero and is
limited to two when explicitly configured.

## Process protocol

The application writes one UTF-8 JSON object to standard input:

```json
{
  "contract_version": 1,
  "output_schema_version": 1,
  "task": "extract_signals",
  "model": "local-model-version",
  "prompt": "Summarize the product feedback.",
  "input": "The export crashes every time."
}
```

The executable returns one UTF-8 JSON object. The `result` must contain at
least one of `summary`, `labels`, or `embedding`; unknown fields fail closed.

```json
{
  "schema_version": 1,
  "result": {
    "summary": "Export crashes consistently.",
    "labels": [{"name": "reliability", "confidence": 0.9}],
    "embedding": [0.12, -0.04, 0.8]
  }
}
```

## Cache behavior

Validated results are stored in the private SQLite database. A cache key covers
the sanitized input, provider identifier and type, model, task, exact prompt,
and output schema version. Raw input and prompt are not stored in the cache
table; only their hashes and validated output are retained. The first valid
result for a key wins atomically. Record edits, deletion, expiry, and source
purge clear the optional cache conservatively so derived text does not outlive
its source data.
