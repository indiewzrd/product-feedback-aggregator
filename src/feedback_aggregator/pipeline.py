"""Application orchestration for collection, analysis, and lifecycle operations.

Connectors, storage, and analysis deliberately remain separate modules.  This
class is the small piece that wires them together for the CLI and for callers
that prefer to embed the application in Python.
"""

from __future__ import annotations

import os
import stat
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from . import __version__
from .analysis import (
    CLUSTERING_VERSION,
    EXTRACTION_VERSION,
    QUALITY_VERSION,
    SCORING_VERSION,
    analyze_records,
)
from .analysis import (
    AnalysisConfig as RuntimeAnalysisConfig,
)
from .config import (
    RESERVED_REPORT_FILENAMES,
    AppConfig,
    SourceConfig,
    load_config,
    validate_path_ownership,
)
from .connectors import Connector, ConnectorContext, connector_for
from .connectors.base import CONNECTOR_CONTRACT_VERSION
from .errors import (
    CollectionError,
    ConfigurationError,
    FeedbackError,
    PartialCollectionError,
    ReadinessError,
    SecurityError,
)
from .http_client import ApiHttpClient, SafeHttpClient
from .models import SCHEMA_VERSION, CheckItem, CollectionPlan, CollectionResult, utc_now
from .policy import can_export_verbatim, policy_checks
from .privacy import read_author_salt
from .providers import LocalSubprocessProvider
from .storage import Storage
from .util import sanitize_text, stable_hash


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _retention_hours(source: SourceConfig) -> int | None:
    """Return the effective configured TTL, including stricter social caps."""

    if source.policy.raw_ttl_hours <= 0:
        return None
    hours = source.policy.raw_ttl_hours
    if source.type in {"reddit", "x", "reddit_apify", "x_apify"}:
        platform_cap = 48 if source.type in {"reddit", "reddit_apify"} else 24
        hours = min(
            hours,
            platform_cap,
            source.policy.deletion_reconcile_interval_hours,
        )
    return hours


def _cursor_reference(cursor: str | None) -> str | None:
    return stable_hash(cursor, prefix="cursor_")[:31] if cursor else None


class FeedbackApplication:
    """Run the bounded local feedback workflow described by one config file."""

    def __init__(self, config: AppConfig, *, stdin_bytes: bytes | None = None) -> None:
        validate_path_ownership(config)
        self.config = config
        self.stdin_bytes = stdin_bytes

    @classmethod
    def from_path(
        cls, path: str | Path, *, stdin_bytes: bytes | None = None
    ) -> "FeedbackApplication":
        return cls(load_config(path), stdin_bytes=stdin_bytes)

    @property
    def enabled_sources(self) -> tuple[SourceConfig, ...]:
        return tuple(source for source in self.config.sources if source.enabled)

    def _source(self, source_id: str) -> SourceConfig:
        for source in self.config.sources:
            if source.id == source_id:
                return source
        raise ConfigurationError(f"Unknown source id: {source_id}")

    def _http_for(self, source: SourceConfig) -> SafeHttpClient | ApiHttpClient | None:
        limits = self.config.limits
        common: dict[str, Any] = {
            "max_redirects": limits.max_redirects,
            "max_download_bytes": limits.max_url_bytes,
            "max_response_bytes": limits.max_decompressed_bytes,
            "connect_timeout": limits.connect_timeout_seconds,
            "read_timeout": limits.read_timeout_seconds,
            "total_timeout": limits.total_timeout_seconds,
        }
        if source.type == "url":
            return SafeHttpClient(
                allow_http=source.options.get("allow_http") is True,
                **common,
            )
        if source.type == "reddit":
            return ApiHttpClient(
                ("www.reddit.com", "oauth.reddit.com"),
                allowed_post_paths=("/api/v1/access_token",),
                allowed_content_types=("application/json",),
                **common,
            )
        if source.type == "x":
            return ApiHttpClient(
                ("api.x.com",),
                allowed_content_types=("application/json",),
                **common,
            )
        if source.type in {"reddit_apify", "x_apify"}:
            actor_path = (
                "/v2/actors/trudax~reddit-scraper-lite/runs"
                if source.type == "reddit_apify"
                else "/v2/actors/apidojo~twitter-scraper-lite/runs"
            )
            apify_common = {**common, "max_redirects": 0}
            return ApiHttpClient(
                ("api.apify.com",),
                allowed_post_paths=(actor_path,),
                allowed_content_types=("application/json",),
                **apify_common,
            )
        return None

    def _connector(
        self,
        source: SourceConfig,
        author_salt: str,
        *,
        checkpoint: Callable[[CollectionResult], None] | None = None,
    ) -> Connector:
        context = ConnectorContext(
            config=self.config,
            source=source,
            author_salt=author_salt,
            http=self._http_for(source),
            stdin_bytes=self.stdin_bytes,
            checkpoint=checkpoint,
        )
        return connector_for(context)

    def _source_readiness_errors(self, source: SourceConfig, author_salt: str) -> list[CheckItem]:
        """Return local, fail-closed errors that must block this source."""

        items = policy_checks(source)
        items.extend(self._connector(source, author_salt).check(probe=False))
        return [item for item in items if item.status == "error"]

    def check(self, *, probe: bool = False) -> dict[str, Any]:
        """Perform readiness checks; only an explicit probe may access a URL."""

        items: list[CheckItem] = [
            CheckItem(
                "configuration",
                "ok",
                f"Configuration version {self.config.version} is valid",
            )
        ]
        try:
            salt = read_author_salt(self.config.privacy.author_salt_file)
            items.append(CheckItem("author-salt", "ok", "Private author salt is ready"))
        except FeedbackError as error:
            # A placeholder is sufficient for non-collecting connector checks.
            salt = "0" * 64
            items.append(CheckItem("author-salt", "error", str(error)))

        database = self.config.storage.path
        if database.exists() or database.is_symlink():
            try:
                mode = database.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                    items.append(
                        CheckItem(
                            "storage",
                            "error",
                            "Database path must be a regular file and not a symbolic link",
                        )
                    )
                else:
                    items.append(CheckItem("storage", "ok", "Existing database path is regular"))
            except OSError:
                items.append(CheckItem("storage", "error", "Database path could not be inspected"))
        else:
            items.append(
                CheckItem(
                    "storage",
                    "ok",
                    "Database will be created privately on the first mutating command",
                )
            )

        def writable_parent(path: Path, label: str) -> CheckItem:
            candidate = path
            while not candidate.exists() and candidate != candidate.parent:
                candidate = candidate.parent
            if not candidate.is_dir():
                return CheckItem(label, "error", f"Existing parent is not a directory: {candidate}")
            if not os.access(candidate, os.W_OK | os.X_OK):
                return CheckItem(label, "error", f"Parent directory is not writable: {candidate}")
            return CheckItem(label, "ok", f"Writable parent is ready: {candidate}")

        items.append(writable_parent(database.parent, "storage-parent"))
        output = self.config.outputs.directory
        if output.exists() or output.is_symlink():
            try:
                mode = output.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                    items.append(
                        CheckItem(
                            "output-directory",
                            "error",
                            "Output path must be a directory and not a symbolic link",
                        )
                    )
                elif not os.access(output, os.W_OK | os.X_OK):
                    items.append(
                        CheckItem("output-directory", "error", "Output directory is not writable")
                    )
                else:
                    items.append(CheckItem("output-directory", "ok", "Output directory is ready"))
            except OSError:
                items.append(
                    CheckItem("output-directory", "error", "Output path could not be inspected")
                )
        else:
            items.append(writable_parent(output.parent, "output-directory"))

        for source in self.config.sources:
            if not source.enabled:
                items.append(
                    CheckItem(
                        f"connector:{source.id}",
                        "skipped",
                        "Source is disabled",
                        source.id,
                    )
                )
                continue
            items.extend(policy_checks(source))
            try:
                items.extend(self._connector(source, salt).check(probe=probe))
            except FeedbackError as error:
                items.append(
                    CheckItem(
                        f"connector:{source.id}",
                        "error",
                        str(error),
                        source.id,
                    )
                )
            except Exception:
                items.append(
                    CheckItem(
                        f"connector:{source.id}",
                        "error",
                        "Connector readiness check failed safely",
                        source.id,
                    )
                )
        for provider in self.config.providers:
            items.append(
                LocalSubprocessProvider(provider, root=self.config.root).check()
            )
        counts = {
            status: sum(item.status == status for item in items)
            for status in ("ok", "warning", "error", "skipped")
        }
        return {
            "ready": counts["error"] == 0,
            "probe": probe,
            "counts": counts,
            "items": [item.to_dict() for item in items],
        }

    def plans(self) -> dict[str, Any]:
        """Return collection plans without opening storage or making requests."""

        plans: list[CollectionPlan] = []
        placeholder_salt = "0" * 64
        for source in self.enabled_sources:
            plans.append(self._connector(source, placeholder_salt).plan())
        return {
            "network_access": False,
            "sources": [plan.to_dict() for plan in plans],
            "totals": {
                "max_items": sum(plan.max_items for plan in plans),
                "estimated_requests": sum(plan.estimated_requests for plan in plans),
                "upper_bound_cost_usd": round(sum(plan.upper_bound_cost_usd for plan in plans), 6),
            },
        }

    @staticmethod
    def _result_summary(result: CollectionResult) -> dict[str, Any]:
        return {
            "records": len(result.records),
            "requests_made": result.requests_made,
            "resources_read": result.resources_read,
            "cost_usd": round(result.cost_usd, 6),
            "stop_reason": result.stop_reason,
            "has_checkpoint_state": result.cursor is not None,
        }

    @staticmethod
    def _persist_result(
        store: Storage, source: SourceConfig, result: CollectionResult
    ) -> tuple[str, ...]:
        normalized_records = []
        retention_hours = _retention_hours(source)
        for record in result.records:
            retrieved = _parse_timestamp(record.retrieved_at)
            if retrieved is None:
                raise CollectionError("Connector returned an invalid retrieved_at timestamp")
            connector_expiry = None
            if record.expires_at is not None:
                connector_expiry = _parse_timestamp(record.expires_at)
                if connector_expiry is None:
                    raise CollectionError("Connector returned an invalid expires_at timestamp")
            policy_expiry = (
                retrieved + timedelta(hours=retention_hours)
                if retention_hours is not None
                else None
            )
            candidates = [value for value in (connector_expiry, policy_expiry) if value is not None]
            effective_expiry = min(candidates) if candidates else None
            created_at = record.created_at
            if record.metadata.get("created_at_inferred") is True:
                existing = store.connection.execute(
                    "SELECT created_at FROM raw_records "
                    "WHERE source_type = ? AND source_id = ? AND native_id = ?",
                    (source.type, source.id, record.native_id),
                ).fetchone()
                if existing is not None:
                    created_at = str(existing["created_at"])
            normalized_records.append(
                replace(
                    record,
                    source_id=source.id,
                    source_type=source.type,
                    created_at=created_at,
                    expires_at=_timestamp(effective_expiry) if effective_expiry else None,
                )
            )
        identifiers = store.upsert_raw_records(normalized_records)
        if result.cursor:
            store.save_cursor(
                source.id,
                result.cursor,
                {
                    "stop_reason": result.stop_reason,
                    "resources_read": result.resources_read,
                    "requests_made": result.requests_made,
                    "cost_usd": result.cost_usd,
                },
            )
        else:
            with store.transaction() as connection:
                connection.execute("DELETE FROM cursors WHERE source_id = ?", (source.id,))
        return identifiers

    def collect(self, *, strict: bool = False) -> dict[str, Any]:
        """Collect enabled sources, isolating failures unless strict is requested."""

        if not self.enabled_sources:
            raise ReadinessError("No enabled sources are configured")
        salt = read_author_salt(self.config.privacy.author_salt_file)
        # A collection can invalidate every downstream score.  Remove reports
        # before the first write so stale evidence is never left behind.
        self.invalidate_reports()
        manifest: dict[str, Any] = {
            "schema_version": 2,
            "application_version": __version__,
            "config_hash": self.config.config_hash,
            "record_schema_version": SCHEMA_VERSION,
            "connector_contract_version": CONNECTOR_CONTRACT_VERSION,
            "algorithm_versions": {
                "quality": QUALITY_VERSION,
                "extraction": EXTRACTION_VERSION,
                "clustering": CLUSTERING_VERSION,
                "scoring": SCORING_VERSION,
            },
            "limits": asdict(self.config.limits),
            "providers": [],
            "prompts": [],
            "seeds": [],
            "strict": strict,
            "stages": {"collection": {"started_at": utc_now(), "status": "running"}},
            "sources": {},
            "errors": [],
        }
        with Storage(self.config.storage.path) as store:
            run_id = store.start_run(manifest)
            collected: list[tuple[SourceConfig, CollectionResult]] = []
            failures: list[dict[str, str]] = []
            limited_sources: list[dict[str, str]] = []
            try:
                for source in self.enabled_sources:
                    cursor_state = store.get_cursor(source.id)
                    cursor = str(cursor_state["cursor"]) if cursor_state else None
                    try:
                        readiness_errors = self._source_readiness_errors(source, salt)
                        if readiness_errors:
                            messages = "; ".join(item.message for item in readiness_errors[:3])
                            raise ReadinessError(f"Source {source.id} is not ready: {messages}")
                        checkpoint_callback: Callable[[CollectionResult], None] | None = None
                        if not strict:

                            def _checkpoint_progress(
                                progress: CollectionResult,
                                *,
                                selected_source: SourceConfig = source,
                            ) -> None:
                                with store.transaction():
                                    self._persist_result(store, selected_source, progress)

                            checkpoint_callback = _checkpoint_progress

                        connector = self._connector(
                            source,
                            salt,
                            checkpoint=checkpoint_callback,
                        )
                        plan = connector.plan()
                        result = connector.collect(cursor=cursor)
                        summary = self._result_summary(result)
                        summary.update(
                            {
                                "cursor_before": _cursor_reference(cursor),
                                "cursor_after": _cursor_reference(result.cursor),
                                "query": plan.query,
                                "max_items": plan.max_items,
                                "upper_bound_cost_usd": plan.upper_bound_cost_usd,
                            }
                        )
                        if result.stop_reason != "complete":
                            limited_sources.append(
                                {"source_id": source.id, "stop_reason": result.stop_reason}
                            )
                        if strict:
                            collected.append((source, result))
                            manifest["sources"][source.id] = summary
                        else:
                            # Raw rows and their cursor are one source-level unit.
                            # Do not report a source as collected until that unit
                            # has committed successfully.
                            with store.transaction():
                                self._persist_result(store, source, result)
                            collected.append((source, result))
                            manifest["sources"][source.id] = summary
                    except PartialCollectionError as error:
                        # A social API may fail after one or more complete,
                        # billable pages. In the default isolated mode, retain
                        # those validated pages and their resume checkpoint so
                        # the next run does not repeat avoidable paid reads.
                        # Strict mode deliberately keeps its all-or-nothing
                        # contract and therefore does not persist this state.
                        failure = {
                            "source_id": source.id,
                            "error_type": type(error).__name__,
                            "message": sanitize_text(str(error), max_chars=500),
                        }
                        failures.append(failure)
                        partial = error.result
                        summary = self._result_summary(partial)
                        summary.update(
                            {
                                "cursor_before": _cursor_reference(cursor),
                                "cursor_after": _cursor_reference(partial.cursor),
                                "query": plan.query,
                                "max_items": plan.max_items,
                                "upper_bound_cost_usd": plan.upper_bound_cost_usd,
                                "error_type": failure["error_type"],
                                "message": failure["message"],
                            }
                        )
                        manifest["sources"][source.id] = summary
                        limited_sources.append(
                            {"source_id": source.id, "stop_reason": "partial_error"}
                        )
                        if strict:
                            raise
                        with store.transaction():
                            self._persist_result(store, source, partial)
                        collected.append((source, partial))
                    except FeedbackError as error:
                        failure = {
                            "source_id": source.id,
                            "error_type": type(error).__name__,
                            "message": sanitize_text(str(error), max_chars=500),
                        }
                        failures.append(failure)
                        manifest["sources"][source.id] = {
                            **failure,
                            "cursor_before": _cursor_reference(cursor),
                        }
                        if strict:
                            raise
                    except Exception as error:
                        failure = {
                            "source_id": source.id,
                            "error_type": "CollectionError",
                            "message": "Connector failed unexpectedly without persisting source data",
                        }
                        failures.append(failure)
                        manifest["sources"][source.id] = {
                            **failure,
                            "cursor_before": _cursor_reference(cursor),
                        }
                        if strict:
                            raise CollectionError(failure["message"]) from error

                if strict:
                    with store.transaction():
                        for source, result in collected:
                            self._persist_result(store, source, result)

                if not collected:
                    raise CollectionError("All enabled sources failed; no feedback was collected")

                status = "partial" if failures or limited_sources else "complete"
                finished_at = utc_now()
                manifest["stages"]["collection"] = {
                    "started_at": manifest["stages"]["collection"]["started_at"],
                    "finished_at": finished_at,
                    "status": status,
                }
                manifest.update(
                    {
                        "status": status,
                        "record_count": sum(len(result.records) for _, result in collected),
                        "failure_count": len(failures),
                        "limited_sources": limited_sources,
                        "total_requests": sum(result.requests_made for _, result in collected),
                        "total_resources": sum(result.resources_read for _, result in collected),
                        "total_cost_usd": round(
                            sum(result.cost_usd for _, result in collected), 6
                        ),
                    }
                )
                manifest["errors"] = failures
                store.finish_run(run_id, status=status, manifest=manifest)
                return {
                    "run_id": run_id,
                    "status": status,
                    "sources": manifest["sources"],
                    "record_count": manifest["record_count"],
                    "failures": failures,
                    "limited_sources": limited_sources,
                }
            except Exception as error:
                manifest["status"] = "failed"
                manifest["failure_count"] = len(failures)
                manifest["stages"]["collection"]["status"] = "failed"
                manifest["stages"]["collection"]["finished_at"] = utc_now()
                if not failures:
                    manifest["errors"] = [
                        {
                            "error_type": type(error).__name__,
                            "message": sanitize_text(str(error), max_chars=500),
                        }
                    ]
                store.finish_run(run_id, status="failed", manifest=manifest)
                raise

    def reconcile(self, source_id: str | None = None) -> dict[str, Any]:
        """Apply local expiry rules and invalidate reports before any mutation."""

        selected: tuple[SourceConfig, ...]
        if source_id is not None:
            selected = (self._source(source_id),)
        else:
            # Retention is a privacy boundary, so disabling collection must not
            # exempt already-stored rows from a newly tightened policy.
            selected = self.config.sources
        expired = 0
        removed = 0
        now = datetime.now(timezone.utc)
        # Reconciliation is a privacy operation.  If stale reports cannot be
        # removed, fail before deleting or rewriting private database rows.
        removed_reports = self.invalidate_reports()
        with Storage(self.config.storage.path) as store:
            if source_id is None:
                expired = store.expire_records()
            else:
                for record in store.list_raw_records(source_id=source_id, include_expired=True):
                    expiry = _parse_timestamp(record.expires_at or "")
                    if expiry is not None and expiry <= now:
                        expired += int(
                            store.delete_raw_record(record_id_for(store, record), reason="expired")
                        )

            for source in selected:
                records = store.list_raw_records(source_id=source.id, include_expired=True)
                retention_hours = _retention_hours(source)
                if retention_hours is not None:
                    retained_records = []
                    for record in records:
                        retrieved = _parse_timestamp(record.retrieved_at)
                        stored_expiry = _parse_timestamp(record.expires_at or "")
                        policy_expiry = (
                            retrieved + timedelta(hours=retention_hours)
                            if retrieved is not None
                            else stored_expiry
                        )
                        effective_expiry = min(
                            candidate
                            for candidate in (stored_expiry, policy_expiry)
                            if candidate is not None
                        )
                        if effective_expiry <= now:
                            expired += int(
                                store.delete_raw_record(
                                    record_id_for(store, record), reason="expired"
                                )
                            )
                            continue
                        effective_text = _timestamp(effective_expiry)
                        if record.expires_at != effective_text:
                            with store.transaction() as connection:
                                connection.execute(
                                    "UPDATE raw_records SET expires_at = ? "
                                    "WHERE source_id = ? AND source_type = ? AND native_id = ?",
                                    (
                                        effective_text,
                                        record.source_id,
                                        record.source_type,
                                        record.native_id,
                                    ),
                                )
                        retained_records.append(record)
                    records = tuple(retained_records)
                # Active platform-deletion synchronization is intentionally not
                # implemented in this alpha.  Social records are bounded by the
                # conservative TTL above, independent of credentials or salt.
                del records
        return {
            "source_id": source_id,
            "expired_records": expired,
            "source_removed_records": removed,
            "reports_invalidated": bool(removed_reports),
            "removed_reports": removed_reports,
            "deletion_strategy": "bounded_ttl_on_cli_run",
        }

    def analyze(self) -> dict[str, Any]:
        """Run deterministic local analysis and atomically replace derived state."""

        self.invalidate_reports()
        with Storage(self.config.storage.path) as store:
            expired = store.expire_records()
            records = store.list_raw_records()
            product_terms = (
                self.config.product.name,
                *self.config.product.aliases,
                *self.config.product.terms,
            )
            analysis_config = RuntimeAnalysisConfig.from_runtime(
                self.config.analysis,
                product_terms=product_terms,
                exclusions=self.config.product.exclusions,
                languages=self.config.product.languages,
            )
            result = analyze_records(
                records,
                analysis_config,
                disposition_overrides=store.review_overrides(),
            )
            store.save_analysis(result)
        dispositions: dict[str, int] = {}
        for assessment in result.assessments:
            dispositions[assessment.disposition] = dispositions.get(assessment.disposition, 0) + 1
        return {
            "records": len(result.assessments),
            "signals": len(result.signals),
            "clusters": len(result.clusters),
            "scores": len(result.scores),
            "expired_records": expired,
            "dispositions": dispositions,
            "reference_time": result.reference_time,
            "analysis_configuration_hash": result.configuration_hash,
            "versions": {
                "quality": QUALITY_VERSION,
                "extraction": EXTRACTION_VERSION,
                "clustering": CLUSTERING_VERSION,
                "scoring": SCORING_VERSION,
            },
        }

    def report(self) -> dict[str, Any]:
        from .reports import build_report, write_reports

        # A failed validation or write must not leave an older report that can
        # be mistaken for current (or retain evidence that has since expired).
        self.invalidate_reports()
        with Storage(self.config.storage.path) as store:
            report = build_report(store, self.config)
        paths = write_reports(report, self.config.outputs.directory)
        return {
            "summary": report["summary"],
            "paths": {name: str(path) for name, path in paths.items()},
        }

    def run(self, *, strict: bool = False) -> dict[str, Any]:
        collection = self.collect(strict=strict)
        run_id = str(collection["run_id"])

        def update_manifest(
            stage: str,
            *,
            started_at: str,
            status: str,
            overall_status: str | None = None,
            summary: dict[str, Any] | None = None,
            error: BaseException | None = None,
        ) -> None:
            with Storage(self.config.storage.path) as store:
                run = store.get_run(run_id)
                manifest = run.get("manifest", {})
                manifest = dict(manifest) if isinstance(manifest, dict) else {}
                stages = manifest.setdefault("stages", {})
                stages[stage] = {
                    "started_at": started_at,
                    "finished_at": utc_now(),
                    "status": status,
                }
                if summary is not None:
                    stages[stage]["summary"] = summary
                if error is not None:
                    safe_error = {
                        "stage": stage,
                        "error_type": type(error).__name__,
                        "message": sanitize_text(str(error), max_chars=500),
                    }
                    stages[stage]["error"] = safe_error
                    errors = manifest.setdefault("errors", [])
                    if isinstance(errors, list):
                        errors.append(safe_error)
                resolved_status = overall_status or status
                manifest["status"] = resolved_status
                store.finish_run(run_id, status=resolved_status, manifest=manifest)

        current_stage = "reconciliation"
        stage_started = utc_now()
        try:
            reconciliation = self.reconcile()
            update_manifest(
                current_stage,
                started_at=stage_started,
                status="complete",
                overall_status="running",
                summary=reconciliation,
            )
            current_stage = "analysis"
            stage_started = utc_now()
            analysis = self.analyze()
            update_manifest(
                current_stage,
                started_at=stage_started,
                status="complete",
                overall_status="running",
                summary=analysis,
            )
            current_stage = "reporting"
            stage_started = utc_now()
            final_status = str(collection["status"])
            # Record the intended terminal state before report construction so
            # the report can include its own complete run metadata.  A failed
            # write is caught below, marked failed, and all reports removed.
            update_manifest(
                current_stage,
                started_at=stage_started,
                status=final_status,
                summary={"formats": ["json", "markdown"]},
            )
            report = self.report()
            return {
                "reconciliation": reconciliation,
                "collection": collection,
                "analysis": analysis,
                "report": report,
            }
        except Exception as error:
            cleanup_error: Exception | None = None
            try:
                self.invalidate_reports()
            except Exception as invalidation_error:
                cleanup_error = invalidation_error
            try:
                update_manifest(
                    current_stage,
                    started_at=stage_started,
                    status="failed",
                    error=error,
                )
            except Exception as manifest_error:
                # A manifest diagnostic must not replace the stage failure.
                error.add_note(
                    "The failed stage could not be recorded in the run manifest: "
                    f"{type(manifest_error).__name__}"
                )
            if cleanup_error is not None:
                raise cleanup_error from error
            raise

    def explain(self, identifier: str) -> dict[str, Any]:
        with Storage(self.config.storage.path) as store:
            as_of = utc_now()
            expired = store.connection.execute(
                "SELECT 1 FROM raw_records WHERE expires_at IS NOT NULL "
                "AND expires_at <= ? LIMIT 1",
                (as_of,),
            ).fetchone()
            if expired is not None:
                # Fail before deleting private rows if stale exported evidence
                # cannot also be invalidated.
                self.invalidate_reports()
                store.expire_records(as_of=as_of)
            explanation = store.explain(identifier)
        return redact_explanation(explanation, self.config)

    def review(self, identifier: str, action: str, rationale: str = "") -> dict[str, Any]:
        """Save or clear a record-level human disposition override."""

        with Storage(self.config.storage.path) as store:
            if action == "clear":
                exists = store.connection.execute(
                    "SELECT 1 FROM review_overrides WHERE record_id = ?", (identifier,)
                ).fetchone()
                if exists is None:
                    raise ReadinessError("No review override exists for this record")
                self.invalidate_reports()
                changed = store.clear_review_override(identifier)
                if not changed:
                    raise ReadinessError("No review override exists for this record")
            else:
                exists = store.connection.execute(
                    "SELECT 1 FROM raw_records WHERE record_id = ?", (identifier,)
                ).fetchone()
                if exists is None:
                    raise ReadinessError("Feedback record was not found")
                self.invalidate_reports()
                store.save_review_override(identifier, action, rationale)
        return {"record_id": identifier, "action": action, "analysis_invalidated": True}

    def purge(self, source_id: str | None = None) -> dict[str, Any]:
        with Storage(self.config.storage.path) as store:
            stored_sources = tuple(
                str(row[0])
                for row in store.connection.execute(
                    "SELECT source_id FROM raw_records "
                    "UNION SELECT source_id FROM cursors ORDER BY source_id"
                ).fetchall()
            )
            sources: tuple[str, ...]
            if source_id is not None:
                configured = any(source.id == source_id for source in self.config.sources)
                if not configured and source_id not in stored_sources:
                    raise ConfigurationError(f"Unknown source id: {source_id}")
                sources = (source_id,)
            else:
                configured_sources = {source.id for source in self.config.sources}
                sources = tuple(sorted(configured_sources.union(stored_sources)))
            # Report deletion is part of the privacy operation.  Fail before
            # deleting database rows if complete invalidation is impossible.
            removed_reports = self.invalidate_reports()
            deleted = sum(store.purge_source(source) for source in sources)
        return {
            "source_ids": list(sources),
            "deleted_records": deleted,
            "removed_reports": removed_reports,
        }

    def invalidate_reports(self) -> list[str]:
        removed: list[str] = []
        directory = self.config.outputs.directory.expanduser().absolute()
        try:
            if directory.is_symlink():
                raise SecurityError("Report output directory must not be a symbolic link")
            if directory.exists() and not directory.is_dir():
                raise SecurityError("Report output path must be a directory")
        except OSError as error:
            raise SecurityError("Report output directory could not be inspected safely") from error
        for name in RESERVED_REPORT_FILENAMES:
            path = directory / name
            try:
                if path.is_symlink():
                    # Never follow output symlinks.  Removing the link is safe and
                    # prevents a later report from replacing an unrelated target.
                    path.unlink()
                    removed.append(str(path))
                elif path.is_file():
                    path.unlink()
                    removed.append(str(path))
                elif path.exists():
                    raise SecurityError(
                        f"Report destination cannot be invalidated safely: {path.name}"
                    )
            except SecurityError:
                raise
            except OSError as error:
                raise SecurityError(
                    f"Report could not be invalidated safely: {path.name}"
                ) from error
        return removed


def record_id_for(store: Storage, record: Any) -> str:
    """Resolve a stored record's internal ID without duplicating its hash rule."""

    row = store.connection.execute(
        "SELECT record_id FROM raw_records WHERE source_id = ? AND source_type = ? AND native_id = ?",
        (record.source_id, record.source_type, record.native_id),
    ).fetchone()
    if row is None:
        raise CollectionError("Stored feedback record disappeared during reconciliation")
    return str(row["record_id"])


def redact_explanation(value: dict[str, Any], config: AppConfig) -> dict[str, Any]:
    """Remove verbatim evidence when a source policy only permits IDs/links."""

    policy_by_source = {source.id: source.policy for source in config.sources}
    signals: Iterable[dict[str, Any]]
    if value.get("kind") == "signal":
        signals = (value.get("signal", {}),)
    else:
        raw_signals = value.get("signals", [])
        signals = raw_signals if isinstance(raw_signals, list) else ()

    representative = ""
    cluster = value.get("cluster")
    if isinstance(cluster, dict):
        representative = str(cluster.get("representative_signal_id", ""))

    representative_restricted = False
    for signal in signals:
        if not isinstance(signal, dict):
            continue
        source = signal.get("source", {})
        source_id = source.get("source_id") if isinstance(source, dict) else None
        policy = policy_by_source.get(str(source_id))
        # Fail closed when a stored source was removed from configuration: no
        # current policy means there is no permission to export its text.
        if policy is None or not can_export_verbatim(policy):
            if signal.get("signal_id") == representative:
                representative_restricted = True
            signal.pop("normalized_statement", None)
            signal.pop("evidence_text", None)
            signal["evidence_redacted"] = True

    if representative_restricted and isinstance(cluster, dict):
        cluster["label"] = "Restricted-source feedback cluster"
        cluster["summary"] = "Verbatim evidence is omitted by the source policy"
    value["schema_version"] = 1
    value["generated_at"] = utc_now()
    return value


__all__ = ["FeedbackApplication", "redact_explanation"]
