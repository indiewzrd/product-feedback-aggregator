"""Versioned JSON and Markdown reports built only from local stored analysis."""

from __future__ import annotations

import json
import stat
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .analysis import CLUSTERING_VERSION, EXTRACTION_VERSION, QUALITY_VERSION, SCORING_VERSION
from .analysis import AnalysisConfig as RuntimeAnalysisConfig
from .config import RESERVED_REPORT_FILENAMES, AppConfig
from .errors import ReadinessError, SecurityError
from .models import utc_now
from .policy import can_export_verbatim
from .storage import Storage
from .util import (
    atomic_write_text,
    canonical_json,
    safe_json,
    safe_provenance_url,
    sanitize_text,
    stable_hash,
)

REPORT_SCHEMA_VERSION = 1
JSON_REPORT_NAME, MARKDOWN_REPORT_NAME = RESERVED_REPORT_FILENAMES


def _json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _runtime_analysis_config(config: AppConfig) -> RuntimeAnalysisConfig:
    product_terms = (
        config.product.name,
        *config.product.aliases,
        *config.product.terms,
    )
    return RuntimeAnalysisConfig.from_runtime(
        config.analysis,
        product_terms=product_terms,
        exclusions=config.product.exclusions,
        languages=config.product.languages,
    ).validated()


def _analysis_hash(config: AppConfig) -> str:
    runtime = _runtime_analysis_config(config)
    return stable_hash(
        canonical_json(runtime.to_dict()),
        QUALITY_VERSION,
        EXTRACTION_VERSION,
        CLUSTERING_VERSION,
        SCORING_VERSION,
        prefix="config_",
    )[:47]


def _scoring_hash(config: AppConfig) -> str:
    runtime = _runtime_analysis_config(config)
    return stable_hash(
        canonical_json(runtime.to_dict()), SCORING_VERSION, prefix="config_"
    )[:47]


def _assert_current_analysis(store: Storage, config: AppConfig) -> None:
    expired_count = int(
        store.connection.execute(
            "SELECT COUNT(*) FROM raw_records "
            "WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime(?)",
            (utc_now(),),
        ).fetchone()[0]
    )
    if expired_count:
        raise ReadinessError(
            "Stored feedback has expired; run feedback reconcile and feedback analyze"
        )
    raw_count = store.count("raw_records")
    assessment_count = store.count("assessments")
    signal_count = store.count("signals")
    membership_count = store.count("cluster_signals")
    cluster_count = store.count("clusters")
    score_count = store.count("scores")
    if raw_count != assessment_count:
        raise ReadinessError("Stored analysis is stale; run feedback analyze")
    if signal_count != membership_count or cluster_count != score_count:
        raise ReadinessError("Stored clusters are stale; run feedback analyze")
    ranks = [
        int(row[0])
        for row in store.connection.execute(
            "SELECT rank FROM scores ORDER BY rank, cluster_id"
        ).fetchall()
    ]
    if ranks != list(range(1, len(ranks) + 1)):
        raise ReadinessError("Stored ranking is stale; run feedback analyze")
    expected_hash = _analysis_hash(config)
    state = store.connection.execute(
        "SELECT configuration_hash, record_count, signal_count, cluster_count "
        "FROM analysis_state WHERE state_id = 1"
    ).fetchone()
    if state is None:
        raise ReadinessError("Stored analysis is stale; run feedback analyze")
    if (
        str(state["configuration_hash"]) != expected_hash
        or int(state["record_count"]) != raw_count
        or int(state["signal_count"]) != signal_count
        or int(state["cluster_count"]) != cluster_count
    ):
        raise ReadinessError("Analysis configuration or input changed; run feedback analyze")
    hashes = {
        str(row[0])
        for row in store.connection.execute(
            "SELECT DISTINCT configuration_hash FROM scores"
        ).fetchall()
    }
    if hashes and hashes != {_scoring_hash(config)}:
        raise ReadinessError("Analysis configuration changed; run feedback analyze")
    version_checks = (
        ("assessments", "version", QUALITY_VERSION),
        ("signals", "extraction_version", EXTRACTION_VERSION),
        ("clusters", "clustering_version", CLUSTERING_VERSION),
        ("scores", "formula_version", SCORING_VERSION),
    )
    for table, column, expected in version_checks:
        versions = {
            str(row[0])
            for row in store.connection.execute(
                f"SELECT DISTINCT {column} FROM {table}"  # noqa: S608 - fixed identifiers
            ).fetchall()
        }
        if versions and versions != {expected}:
            raise ReadinessError("Analysis implementation changed; run feedback analyze")
    duplicate_versions = {
        str(row[0])
        for row in store.connection.execute(
            "SELECT DISTINCT method_version FROM duplicate_groups"
        ).fetchall()
    }
    if duplicate_versions and duplicate_versions != {EXTRACTION_VERSION}:
        raise ReadinessError("Duplicate analysis changed; run feedback analyze")


def _cluster_evidence(
    store: Storage,
    cluster_id: str,
    config: AppConfig,
) -> tuple[list[dict[str, Any]], bool, str]:
    policies = {source.id: source.policy for source in config.sources}
    rows = store.connection.execute(
        "SELECT s.signal_id, s.signal_type, s.normalized_statement, "
        "s.evidence_start, s.evidence_end, r.text, r.source_id, r.source_type, "
        "r.native_id, r.canonical_url, cs.evidence_rank, cs.evidence_score, "
        "dg.group_id AS duplicate_group_id "
        "FROM cluster_signals cs "
        "JOIN signals s ON s.signal_id = cs.signal_id "
        "JOIN raw_records r ON r.record_id = s.record_id "
        "LEFT JOIN duplicate_group_signals dgs ON dgs.signal_id = s.signal_id "
        "LEFT JOIN duplicate_groups dg ON dg.group_id = dgs.group_id "
        "WHERE cs.cluster_id = ? ORDER BY cs.evidence_rank, s.signal_id",
        (cluster_id,),
    ).fetchall()
    evidence: list[dict[str, Any]] = []
    representative_source_id = ""
    representative = store.connection.execute(
        "SELECT representative_signal_id FROM clusters WHERE cluster_id = ?",
        (cluster_id,),
    ).fetchone()
    representative_signal_id = str(representative[0]) if representative else ""
    representative_restricted = False
    for row in rows:
        source_id = str(row["source_id"])
        policy = policies.get(source_id)
        exportable = policy is not None and can_export_verbatim(policy)
        item: dict[str, Any] = {
            "signal_id": row["signal_id"],
            "signal_type": row["signal_type"],
            "source_id": source_id,
            "source_type": row["source_type"],
            "native_id": row["native_id"],
            "canonical_url": safe_provenance_url(row["canonical_url"]),
            "evidence_rank": int(row["evidence_rank"]),
            "evidence_score": float(row["evidence_score"]),
            "duplicate_group_id": row["duplicate_group_id"],
            "verbatim_included": exportable,
        }
        if exportable:
            text = str(row["text"])
            start, end = int(row["evidence_start"]), int(row["evidence_end"])
            item["excerpt"] = sanitize_text(text[start:end], max_chars=2000)
        if row["signal_id"] == representative_signal_id:
            representative_source_id = source_id
            representative_restricted = not exportable
        evidence.append(item)
    return evidence, representative_restricted, representative_source_id


def build_report(store: Storage, config: AppConfig) -> dict[str, Any]:
    """Create a report object without network access or source mutation."""

    _assert_current_analysis(store, config)
    source_rows = store.connection.execute(
        "SELECT source_id, source_type, COUNT(*) AS count, "
        "MIN(created_at) AS oldest_item_at, MAX(retrieved_at) AS last_retrieved_at, "
        "MIN(expires_at) AS next_expiry_at "
        "FROM raw_records GROUP BY source_id, source_type ORDER BY source_id"
    ).fetchall()
    sources = [
        {
            "source_id": row["source_id"],
            "source_type": row["source_type"],
            "records": int(row["count"]),
            "oldest_item_at": row["oldest_item_at"],
            "last_retrieved_at": row["last_retrieved_at"],
            "next_expiry_at": row["next_expiry_at"],
        }
        for row in source_rows
    ]
    quality = {
        str(row["disposition"]): int(row["count"])
        for row in store.connection.execute(
            "SELECT disposition, COUNT(*) AS count FROM assessments "
            "GROUP BY disposition ORDER BY disposition"
        ).fetchall()
    }

    clusters: list[dict[str, Any]] = []
    cluster_rows = store.connection.execute(
        "SELECT c.*, s.total, s.rank, s.components_json, s.weights_json, "
        "s.penalties_json, s.formula_version, s.configuration_hash "
        "FROM clusters c JOIN scores s ON s.cluster_id = c.cluster_id "
        "ORDER BY s.rank, c.cluster_id"
    ).fetchall()
    for row in cluster_rows:
        evidence, representative_restricted, _source_id = _cluster_evidence(
            store, str(row["cluster_id"]), config
        )
        label = str(row["label"])
        summary = str(row["summary"])
        if representative_restricted:
            signal_types = Counter(item["signal_type"] for item in evidence)
            primary_type = signal_types.most_common(1)[0][0] if signal_types else "feedback"
            label = f"{str(primary_type).replace('_', ' ').title()} feedback"
            summary = f"{len(evidence)} restricted-source signal(s); verbatim text omitted"
        clusters.append(
            {
                "cluster_id": row["cluster_id"],
                "rank": int(row["rank"]),
                "label": sanitize_text(label, max_chars=200),
                "summary": sanitize_text(summary, max_chars=500),
                "signal_count": len(evidence),
                "distinct_authors": int(row["distinct_authors"]),
                "source_distribution": _json_object(row["source_distribution_json"]),
                "time_start": row["time_start"],
                "time_end": row["time_end"],
                "score": {
                    "total": float(row["total"]),
                    "components": _json_object(row["components_json"]),
                    "weights": _json_object(row["weights_json"]),
                    "penalties": _json_object(row["penalties_json"]),
                    "formula_version": row["formula_version"],
                    "configuration_hash": row["configuration_hash"],
                },
                "evidence": evidence,
            }
        )

    latest_run_row = store.connection.execute(
        "SELECT run_id FROM runs ORDER BY started_at DESC, run_id DESC LIMIT 1"
    ).fetchone()
    run_metadata: dict[str, Any] | None = None
    if latest_run_row is not None:
        run = store.get_run(str(latest_run_row["run_id"]))
        manifest = run.get("manifest", {})
        manifest = manifest if isinstance(manifest, dict) else {}
        run_metadata = {
            "run_id": run["run_id"],
            "status": run["status"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "manifest_schema_version": manifest.get("schema_version"),
            "application_version": manifest.get("application_version"),
            "algorithm_versions": manifest.get("algorithm_versions", {}),
        }

    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": utc_now(),
        "product": {
            "name": config.product.name,
            "aliases": list(config.product.aliases),
            "exclusions": list(config.product.exclusions),
            "languages": list(config.product.languages),
        },
        "config_hash": config.config_hash,
        "run": run_metadata,
        "summary": {
            "records": store.count("raw_records"),
            "eligible_records": quality.get("eligible", 0),
            "suppressed_records": quality.get("suppressed", 0),
            "pending_review_records": quality.get("pending_review", 0),
            "signals": store.count("signals"),
            "duplicate_groups": store.count("duplicate_groups"),
            "clusters": len(clusters),
        },
        "sources": sources,
        "quality_dispositions": quality,
        "clusters": clusters,
        "limitations": [
            "This report summarizes collected feedback; it does not measure market prevalence.",
            "Noise, spam, automation, clustering, and ranking are deterministic heuristics and require human review.",
            "Reddit and X discovery is bounded and incomplete; restricted-source verbatim text is omitted.",
            "Apify sources are remotely processed by fixed community Actors; Actor availability is not a compliance assurance.",
            "Social removals are not actively synchronized in this alpha; expiry is purged only when the CLI runs, and reports refuse expired rows.",
            "Scores prioritize the configured evidence dimensions and are not product decisions.",
        ],
    }
    return report


def _markdown(value: object) -> str:
    """Escape untrusted data so it remains inert CommonMark text."""

    raw = "" if value is None else str(value)
    text = sanitize_text(raw, max_chars=20_000).replace("\\", "\\\\")
    for character in ("`", "*", "_", "{", "}", "[", "]", "#", "!", "|"):
        text = text.replace(character, f"\\{character}")
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def _code(value: object) -> str:
    raw = "" if value is None else str(value)
    return sanitize_text(raw, max_chars=1000).replace("`", "'").replace("\n", " ")


def render_markdown(report: Mapping[str, Any]) -> str:
    product = report.get("product", {})
    summary = report.get("summary", {})
    lines = [
        f"# Feedback check: {_markdown(product.get('name', 'Product'))}",
        "",
        f"Generated: {_markdown(report.get('generated_at', ''))}",
        f"Report schema: {_markdown(report.get('schema_version', ''))}",
        "",
        "## Summary",
        "",
        f"- Records: {_markdown(summary.get('records', 0))}",
        f"- Eligible records: {_markdown(summary.get('eligible_records', 0))}",
        f"- Suppressed records: {_markdown(summary.get('suppressed_records', 0))}",
        f"- Pending review: {_markdown(summary.get('pending_review_records', 0))}",
        f"- Signals: {_markdown(summary.get('signals', 0))}",
        f"- Exact duplicate groups: {_markdown(summary.get('duplicate_groups', 0))}",
        f"- Ranked clusters: {_markdown(summary.get('clusters', 0))}",
        "",
        "## Sources and scope",
        "",
        "Configured exclusions: "
        + _markdown(", ".join(product.get("exclusions", [])) or "none"),
        "",
    ]
    sources = report.get("sources", [])
    for source in sources if isinstance(sources, list) else []:
        if not isinstance(source, Mapping):
            continue
        lines.append(
            "- "
            + _markdown(
                f"{source.get('source_id', '')} ({source.get('source_type', '')}): "
                f"{source.get('records', 0)} records; last retrieved "
                f"{source.get('last_retrieved_at', '')}"
            )
        )
    lines.extend(
        [
            "",
        "## Ranked feedback",
        "",
        ]
    )
    clusters = report.get("clusters", [])
    if not clusters:
        lines.extend(["No eligible feedback clusters were produced.", ""])
    for cluster in clusters if isinstance(clusters, list) else []:
        if not isinstance(cluster, Mapping):
            continue
        score = cluster.get("score", {})
        total = score.get("total", 0) if isinstance(score, Mapping) else 0
        lines.extend(
            [
                f"### {_markdown(cluster.get('rank', '?'))}. {_markdown(cluster.get('label', 'Feedback'))}",
                "",
                f"Score: {_markdown(total)}/100 · Signals: {_markdown(cluster.get('signal_count', 0))} · Distinct authors: {_markdown(cluster.get('distinct_authors', 0))}",
                "",
                _markdown(cluster.get("summary", "")),
                "",
                f"Cluster ID: `{_code(cluster.get('cluster_id', ''))}`",
                "",
            ]
        )
        evidence = cluster.get("evidence", [])
        if isinstance(evidence, list) and evidence:
            lines.extend(["Evidence:", ""])
            for item in evidence:
                if not isinstance(item, Mapping):
                    continue
                prefix = (
                    f"#{item.get('evidence_rank', '?')} "
                    f"{item.get('source_type', '')}/{item.get('source_id', '')} "
                    f"({item.get('native_id', '')})"
                )
                excerpt = item.get("excerpt")
                detail = (
                    f": {excerpt}"
                    if isinstance(excerpt, str) and excerpt
                    else " (verbatim omitted)"
                )
                # URLs are intentionally rendered as escaped plain text.  They
                # remain useful provenance without becoming active Markdown.
                url = item.get("canonical_url", "")
                safe_line = f"- {_markdown(prefix + detail)}"
                if url:
                    safe_line += f" — `{_code(url)}`"
                lines.append(safe_line)
            lines.append("")
    lines.extend(["## Limitations", ""])
    limitations = report.get("limitations", [])
    for limitation in limitations if isinstance(limitations, list) else []:
        lines.append(f"- {_markdown(limitation)}")
    lines.extend(
        [
            "",
            "Use `feedback explain ID` to inspect stored score components and reason codes.",
            "",
        ]
    )
    return "\n".join(lines)


def _safe_destination(directory: Path, name: str) -> Path:
    directory = directory.expanduser().absolute()
    try:
        if directory.is_symlink():
            raise SecurityError("Report output directory must not be a symbolic link")
        if directory.exists() and not directory.is_dir():
            raise SecurityError("Report output path must be a directory")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    except SecurityError:
        raise
    except OSError as error:
        raise SecurityError("Report output directory could not be prepared safely") from error
    path = directory / name
    if path.is_symlink():
        raise SecurityError(f"Report destination must not be a symbolic link: {name}")
    if path.exists() and not stat.S_ISREG(path.stat().st_mode):
        raise SecurityError(f"Report destination must be a regular file: {name}")
    return path


def write_reports(report: Mapping[str, Any], directory: Path) -> dict[str, Path]:
    json_path = _safe_destination(directory, JSON_REPORT_NAME)
    markdown_path = _safe_destination(directory, MARKDOWN_REPORT_NAME)
    atomic_write_text(json_path, safe_json(report, pretty=True) + "\n")
    atomic_write_text(markdown_path, render_markdown(report))
    return {"json": json_path, "markdown": markdown_path}


__all__ = ["build_report", "render_markdown", "write_reports"]
