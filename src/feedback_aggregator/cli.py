"""Small command-line interface for the Product Feedback Aggregator."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .config import AppConfig, load_config
from .errors import FeedbackError, ReadinessError, SecurityError
from .pipeline import FeedbackApplication
from .privacy import create_author_salt
from .util import atomic_write_text, safe_json, sanitize_text

OUTPUT_SCHEMA_VERSION = 1

_SAMPLE_RECORDS = [
    {
        "id": "sample-001",
        "text": "Acme Notes crashes when I open a large shared notebook.",
        "url": "https://feedback.example.test/items/sample-001",
        "created_at": "2026-09-20T09:00:00Z",
        "author": "sample-person-a",
        "engagement": {"votes": 12},
    },
    {
        "id": "sample-002",
        "text": "Acme Notes crashes when opening a large shared notebook.",
        "url": "https://feedback.example.test/items/sample-002",
        "created_at": "2026-09-21T10:00:00Z",
        "author": "sample-person-b",
        "engagement": {"votes": 5},
    },
    {
        "id": "sample-003",
        "text": "I wish Acme Notes supported PDF export from the editor.",
        "url": "https://feedback.example.test/items/sample-003",
        "created_at": "2026-09-22T11:00:00Z",
        "author": "sample-person-c",
        "engagement": {"votes": 8},
    },
    {
        "id": "sample-004",
        "text": "Search in Acme Notes is slow after the latest update.",
        "url": "https://feedback.example.test/items/sample-004",
        "created_at": "2026-09-23T12:00:00Z",
        "author": "sample-person-d",
        "engagement": {"votes": 3},
    },
    {
        "id": "sample-005",
        "text": "The new Acme Notes editor is fast and helpful.",
        "url": "https://feedback.example.test/items/sample-005",
        "created_at": "2026-09-24T13:00:00Z",
        "author": "sample-person-e",
        "engagement": {"votes": 4},
    },
]

_SAMPLE_CONFIG = """version: 1

product:
  name: Acme Notes
  aliases: [Acme]
  terms: [note, notebook, editor, sync, search, export]
  exclusions: [hiring, stock price]
  languages: [en]

storage:
  path: .feedback/feedback.db

privacy:
  author_salt_file: .feedback/author_salt

limits:
  max_items_per_source: 1000
  max_file_bytes: 10485760
  max_line_bytes: 1048576
  max_url_bytes: 2097152
  max_decompressed_bytes: 4194304
  connect_timeout_seconds: 5
  read_timeout_seconds: 15
  total_timeout_seconds: 30
  max_redirects: 3
  external_timeout_seconds: 60
  external_output_bytes: 10485760

analysis:
  relevance_threshold: 0.35
  suppression_threshold: 0.80
  cluster_similarity_threshold: 0.42
  weights:
    authors: 0.28
    sources: 0.17
    recency: 0.15
    severity: 0.18
    relevance: 0.17
    engagement: 0.05

outputs:
  directory: reports

sources:
  - id: sample-json
    type: json
    enabled: true
    max_items: 100
    options:
      paths: [feedback.sample.json]
    policy:
      acquisition_mode: user_file
      approval_required: false
      approval_reference: Local synthetic example
      remote_processing_allowed: false
      raw_ttl_hours: 0
      redistribution_mode: local_only
      policy_version: local-v1
      policy_version_checked_at: "2026-09-25"
"""

_PRIVATE_GITIGNORE_ENTRIES = (".feedback/", "reports/")


def _exclusive_write(path: Path, content: str, *, mode: int = 0o600) -> bool:
    """Create a file once without following or replacing a final symlink."""

    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError:
        return False
    try:
        data = content.encode("utf-8")
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return True


def _ensure_private_gitignore(root: Path) -> tuple[str, Path]:
    """Create or minimally extend ignore rules without replacing user content."""

    path = root / ".gitignore"
    block = (
        "# Product Feedback Aggregator private local state\n"
        + "\n".join(_PRIVATE_GITIGNORE_ENTRIES)
        + "\n"
    )
    if _exclusive_write(path, block, mode=0o644):
        return "created", path
    if path.is_symlink() or not path.is_file():
        raise SecurityError(".gitignore must be a regular file and not a symbolic link")
    try:
        if path.stat().st_size > 1_048_576:
            raise SecurityError(".gitignore is too large to update safely")
        original = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise SecurityError(".gitignore must be valid UTF-8") from error
    existing = {line.strip() for line in original.splitlines()}
    missing = [entry for entry in _PRIVATE_GITIGNORE_ENTRIES if entry not in existing]
    if not missing:
        return "preserved", path
    separator = "" if not original or original.endswith("\n") else "\n"
    addition = (
        "# Product Feedback Aggregator private local state\n"
        + "\n".join(missing)
        + "\n"
    )
    mode = stat.S_IMODE(path.stat().st_mode) if os.name != "nt" else 0o644
    atomic_write_text(path, original + separator + addition, mode=mode)
    return "updated", path


def initialize(directory: str | Path) -> dict[str, Any]:
    root = Path(directory).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_path = root / "feedback.yml"
    sample_path = root / "feedback.sample.json"
    created: list[str] = []
    skipped: list[str] = []
    updated: list[str] = []
    ignore_status, ignore_path = _ensure_private_gitignore(root)
    if ignore_status == "created":
        created.append(str(ignore_path))
    elif ignore_status == "updated":
        updated.append(str(ignore_path))
    else:
        skipped.append(str(ignore_path))
    if _exclusive_write(config_path, _SAMPLE_CONFIG):
        created.append(str(config_path))
    else:
        skipped.append(str(config_path))
    sample = json.dumps(_SAMPLE_RECORDS, ensure_ascii=False, indent=2) + "\n"
    if _exclusive_write(sample_path, sample):
        created.append(str(sample_path))
    else:
        skipped.append(str(sample_path))

    config = load_config(config_path)
    salt_existed = (
        config.privacy.author_salt_file.exists() or config.privacy.author_salt_file.is_symlink()
    )
    create_author_salt(config.privacy.author_salt_file)
    if salt_existed:
        skipped.append(str(config.privacy.author_salt_file))
    else:
        created.append(str(config.privacy.author_salt_file))
    return {
        "directory": str(root),
        "config": str(config_path),
        "created": created,
        "updated": updated,
        "preserved_existing": skipped,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="feedback",
        description="Collect and rank product feedback locally and explainably.",
    )
    parser.add_argument("--config", default="feedback.yml", help="Path to feedback.yml")
    parser.add_argument("--json", action="store_true", help="Emit a versioned JSON envelope")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a safe synthetic starter project")
    init.add_argument("--directory", default=".", help="Directory to initialize")

    check = commands.add_parser("check", help="Validate readiness without collecting")
    check.add_argument(
        "--probe",
        action="store_true",
        help="Allow read-only URL probes (social checks remain local)",
    )

    collect = commands.add_parser("collect", help="Plan or collect configured sources")
    collect.add_argument("--plan", action="store_true", help="Show bounds without network access")
    collect.add_argument(
        "--strict", action="store_true", help="Persist no source if any source fails"
    )

    reconcile = commands.add_parser("reconcile", help="Apply expiry and deletion reconciliation")
    reconcile.add_argument("source", nargs="?", help="Optional source ID")

    analyze = commands.add_parser("analyze", help="Run deterministic local analysis")
    analyze.add_argument(
        "--from",
        dest="from_stage",
        choices=("raw",),
        default="raw",
        help="Stored stage to analyze",
    )

    commands.add_parser("report", help="Write JSON and Markdown reports from stored analysis")

    run = commands.add_parser("run", help="Collect, analyze, and report")
    run.add_argument(
        "--example", action="store_true", help="Use the repository's synthetic example"
    )
    run.add_argument("--strict", action="store_true", help="Persist no source if any source fails")

    explain = commands.add_parser("explain", help="Explain a stored record, signal, or cluster")
    explain.add_argument("identifier", help="Stored item ID")

    review = commands.add_parser("review", help="Override one record's include/exclude decision")
    review.add_argument("action", choices=("include", "exclude", "clear"))
    review.add_argument("identifier", help="Stored record ID")
    review.add_argument("--rationale", default="", help="Short local review note")

    purge = commands.add_parser("purge", help="Delete retained feedback and derived data")
    purge.add_argument("source", nargs="?", help="Optional source ID; omit to purge all")
    purge.add_argument("--yes", action="store_true", help="Confirm the destructive operation")
    return parser


def _example_path() -> Path:
    candidate = Path(__file__).resolve().parents[2] / "examples" / "feedback.example.yml"
    if not candidate.is_file():
        raise ReadinessError(
            "The repository example is unavailable; run feedback init and then feedback run"
        )
    return candidate


def _stdin_for(config: AppConfig) -> bytes | None:
    needs_stdin = any(
        source.enabled and source.type == "external" and "stdin" in source.options
        for source in config.sources
    )
    if not needs_stdin:
        return None
    if sys.stdin.isatty():
        raise ReadinessError("An enabled external source expects NDJSON on standard input")
    maximum = config.limits.external_output_bytes
    data = sys.stdin.buffer.read(maximum + 1)
    if len(data) > maximum:
        raise ReadinessError("Standard input exceeds the configured external-output limit")
    return data


def _application(config_path: Path, *, read_stdin: bool = False) -> FeedbackApplication:
    config = load_config(config_path)
    return FeedbackApplication(config, stdin_bytes=_stdin_for(config) if read_stdin else None)


def _execute(args: argparse.Namespace) -> dict[str, Any]:
    command = str(args.command)
    if command == "init":
        return initialize(args.directory)

    config_path = Path(args.config)
    if command == "run" and args.example:
        config_path = _example_path()
        example_config = load_config(config_path)
        create_author_salt(example_config.privacy.author_salt_file)

    reads_stdin = command == "run" or (command == "collect" and not args.plan)
    app = _application(config_path, read_stdin=reads_stdin)
    if command == "check":
        return app.check(probe=args.probe)
    if command == "collect":
        return app.plans() if args.plan else app.collect(strict=args.strict)
    if command == "reconcile":
        return app.reconcile(args.source)
    if command == "analyze":
        return app.analyze()
    if command == "report":
        return app.report()
    if command == "run":
        return app.run(strict=args.strict)
    if command == "explain":
        return app.explain(args.identifier)
    if command == "review":
        return app.review(args.identifier, args.action, args.rationale)
    if command == "purge":
        if not args.yes:
            raise ReadinessError("Purge requires --yes because it permanently deletes local data")
        return app.purge(args.source)
    raise ReadinessError("Unknown command")


def _human_output(command: str, data: dict[str, Any]) -> str:
    if command == "check":
        lines = ["Ready" if data.get("ready") else "Not ready"]
        for item in data.get("items", []):
            status = str(item.get("status", "")).upper()
            source = f" [{item.get('source_id')}]" if item.get("source_id") else ""
            lines.append(f"{status}{source} {item.get('name')}: {item.get('message')}")
        return "\n".join(lines)
    if command == "collect" and data.get("network_access") is False:
        total = data.get("totals", {})
        lines = [
            "Collection plan (no network access):",
            f"Maximum items: {total.get('max_items', 0)}",
            f"Estimated requests: {total.get('estimated_requests', 0)}",
            f"Upper-bound cost: ${total.get('upper_bound_cost_usd', 0):.6f}",
        ]
        for source in data.get("sources", []):
            lines.append(
                f"- {source.get('source_id')}: {source.get('query')} "
                f"(max {source.get('max_items')})"
            )
        return "\n".join(lines)
    if command == "report":
        paths = data.get("paths", {})
        return f"Wrote report:\n- {paths.get('markdown', '')}\n- {paths.get('json', '')}"
    if command == "run":
        report = data.get("report", {})
        paths = report.get("paths", {}) if isinstance(report, dict) else {}
        collection = data.get("collection", {})
        analysis = data.get("analysis", {})
        return (
            f"Run {collection.get('status', 'complete')}: "
            f"{collection.get('record_count', 0)} collected, "
            f"{analysis.get('signals', 0)} signals, "
            f"{analysis.get('clusters', 0)} clusters.\n"
            f"Markdown report: {paths.get('markdown', '')}"
        )
    return safe_json(data, pretty=True)


def _envelope(command: str, *, ok: bool, data: Any = None, error: Any = None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "ok": ok,
        "command": command,
    }
    if ok:
        value["data"] = data
    else:
        value["error"] = error
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    if raw_arguments.count("--json") > 1:
        parser.error("--json may be provided only once")
    if "--json" in raw_arguments:
        raw_arguments.remove("--json")
        raw_arguments.insert(0, "--json")
    args = parser.parse_args(raw_arguments)
    command = str(args.command)
    try:
        data = _execute(args)
        if args.json:
            print(safe_json(_envelope(command, ok=True, data=data)))
        else:
            print(_human_output(command, data))
        if command == "check" and not data.get("ready", True):
            return ReadinessError.exit_code
        return 0
    except FeedbackError as error:
        safe_message = sanitize_text(str(error), max_chars=1000)
        if args.json:
            print(
                safe_json(
                    _envelope(
                        command,
                        ok=False,
                        error={
                            "type": type(error).__name__,
                            "message": safe_message,
                            "exit_code": error.exit_code,
                        },
                    )
                ),
                file=sys.stderr,
            )
        else:
            print(f"Error: {safe_message}", file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except Exception:
        # Unexpected failures do not echo source content, response bodies,
        # command output, paths with embedded credentials, or environment data.
        if args.json:
            print(
                safe_json(
                    _envelope(
                        command,
                        ok=False,
                        error={
                            "type": "InternalError",
                            "message": "The command failed unexpectedly",
                            "exit_code": 1,
                        },
                    )
                ),
                file=sys.stderr,
            )
        else:
            print("Error: the command failed unexpectedly", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
