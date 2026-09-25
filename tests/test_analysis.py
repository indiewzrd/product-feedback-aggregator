from __future__ import annotations

import json
import os
import sqlite3
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from feedback_aggregator.analysis import (
    QUALITY_VERSION,
    AnalysisConfig,
    _engagement_percentiles,
    analyze_records,
    assess_record,
    extract_signals,
    lexical_similarity,
    raw_record_id,
)
from feedback_aggregator.errors import SecurityError
from feedback_aggregator.models import RawRecord
from feedback_aggregator.storage import DATABASE_SCHEMA_VERSION, Storage


def record(
    native_id: str,
    text: str,
    *,
    source_id: str = "fixture",
    source_type: str = "json",
    author_key: str = "author-1",
    created_at: str = "2026-09-20T12:00:00Z",
    retrieved_at: str = "2026-09-25T12:00:00Z",
    expires_at: str | None = None,
    engagement: dict[str, float] | None = None,
    metadata: dict[str, object] | None = None,
) -> RawRecord:
    return RawRecord(
        source_id=source_id,
        source_type=source_type,
        native_id=native_id,
        canonical_url=f"https://example.test/feedback/{native_id}",
        text=text,
        created_at=created_at,
        retrieved_at=retrieved_at,
        author_key=author_key,
        engagement=engagement or {},
        metadata=metadata or {},
        query="Acme",
        expires_at=expires_at,
    )


class DeterministicAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AnalysisConfig(product_terms=("Acme",), cluster_similarity=0.40)

    def test_quality_is_separate_cautious_and_explainable(self) -> None:
        useful = record("one", "Acme crashes whenever I open the settings page.")
        assessment = assess_record(useful, self.config)
        self.assertEqual(assessment.version, QUALITY_VERSION)
        self.assertEqual(assessment.disposition, "eligible")
        self.assertGreater(assessment.relevance, assessment.noise)
        self.assertIn("relevance:product_term_match", assessment.relevance_reasons)
        self.assertIn("spam:no_strong_evidence", assessment.spam_reasons)
        self.assertIn("automation:no_strong_evidence", assessment.automation_reasons)

        automated = record(
            "two",
            "Acme needs a better export format.",
            metadata={"is_bot": True},
        )
        automated_assessment = assess_record(automated, self.config)
        self.assertEqual(automated_assessment.disposition, "pending_review")
        self.assertGreaterEqual(automated_assessment.automation, 0.9)
        self.assertNotEqual(automated_assessment.disposition, "suppressed")

        missing_metadata = record("three", "Acme is slow on startup.", metadata={})
        missing_assessment = assess_record(missing_metadata, self.config)
        self.assertLess(missing_assessment.automation, 0.1)

    def test_sentence_signals_have_exact_offsets_and_stable_ids(self) -> None:
        item = record(
            "offsets",
            "Acme crashes on launch. I wish Acme supported CSV export!",
        )
        assessment = assess_record(item, self.config)
        first = extract_signals(item, assessment, self.config)
        second = extract_signals(item, assessment, self.config)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 2)
        self.assertEqual(first[0].signal_type, "bug")
        self.assertEqual(first[1].signal_type, "feature_request")
        for signal in first:
            self.assertEqual(
                item.text[signal.evidence_start : signal.evidence_end],
                signal.evidence_text,
            )
            self.assertTrue(signal.signal_id.startswith("signal_"))

    def test_full_analysis_is_deterministic_and_scores_reconstruct(self) -> None:
        records = (
            record(
                "a",
                "Acme crashes on launch.",
                source_type="reddit",
                source_id="reddit-main",
                author_key="author-a",
                engagement={"score": 12},
                created_at="2026-09-22T12:00:00Z",
            ),
            record(
                "b",
                "Acme crashes on launch.",
                source_type="x",
                source_id="x-main",
                author_key="author-b",
                engagement={"likes": 4},
                created_at="2026-09-23T12:00:00Z",
            ),
            record(
                "c",
                "I wish Acme supported PDF export.",
                source_type="json",
                source_id="survey",
                author_key="author-c",
                created_at="2026-09-24T12:00:00Z",
            ),
        )
        first = analyze_records(records, self.config)
        second = analyze_records(reversed(records), self.config)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(len(first.duplicate_groups), 1)
        self.assertTrue(all(0 <= score.total <= 100 for score in first.scores))
        self.assertEqual(
            [score.rank for score in first.scores], list(range(1, len(first.scores) + 1))
        )

        for score in first.scores:
            positive = sum(
                score.components[name] * score.weights[name] for name in score.components
            )
            penalty = sum(
                score.penalties[name] * score.weights[f"{name}_penalty"] for name in score.penalties
            )
            reconstructed = round(100 * max(0.0, min(1.0, positive - penalty)), 3)
            self.assertAlmostEqual(score.total, reconstructed, places=3)

    def test_lexical_similarity_is_simple_and_predictable(self) -> None:
        self.assertEqual(
            lexical_similarity("The app crashes on startup", "App crashes at startup"),
            1.0,
        )
        self.assertEqual(lexical_similarity("export PDF", "dark mode"), 0.0)

    def test_public_runtime_configuration_adapts_without_module_coupling(self) -> None:
        runtime = SimpleNamespace(
            relevance_threshold=0.30,
            suppression_threshold=0.85,
            cluster_similarity_threshold=0.50,
            weights={
                "authors": 0.28,
                "sources": 0.17,
                "recency": 0.15,
                "severity": 0.18,
                "relevance": 0.17,
                "engagement": 0.05,
            },
        )
        adapted = AnalysisConfig.from_runtime(runtime, product_terms=("Acme",))
        self.assertEqual(adapted.product_terms, ("Acme",))
        self.assertEqual(adapted.spam_threshold, 0.85)
        result = analyze_records(
            (record("runtime", "Acme crashes on startup."),),
            runtime,  # type: ignore[arg-type]
            product_terms=("Acme",),
        )
        self.assertEqual(result.assessments[0].disposition, "eligible")

    def test_exclusions_and_declared_languages_are_enforced(self) -> None:
        config = replace(
            self.config,
            exclusions=("stock price",),
            languages=("en",),
        )
        excluded = assess_record(
            record("excluded", "Acme stock price needs a better chart."), config
        )
        self.assertEqual(excluded.disposition, "suppressed")
        self.assertIn("noise:configured_exclusion", excluded.noise_reasons)

        wrong_language = assess_record(
            record(
                "language",
                "Acme crashes whenever I open a shared notebook.",
                metadata={"lang": "pt"},
            ),
            config,
        )
        self.assertEqual(wrong_language.disposition, "suppressed")
        self.assertIn("noise:language_not_allowed", wrong_language.noise_reasons)

    def test_engagement_percentiles_scale_without_quadratic_scans(self) -> None:
        records = tuple(
            record(str(index), "Acme needs export.", engagement={"votes": float(index % 101)})
            for index in range(20_000)
        )
        percentiles = _engagement_percentiles(records)
        self.assertEqual(len(percentiles), len(records))
        self.assertTrue(all(0 < value <= 1 for value in percentiles.values()))


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "private" / "feedback.sqlite3"
        self.config = AnalysisConfig(product_terms=("Acme",), cluster_similarity=0.40)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_schema_security_permissions_and_manifest_redaction(self) -> None:
        with Storage(self.database) as store:
            self.assertEqual(store.schema_version, DATABASE_SCHEMA_VERSION)
            self.assertEqual(store.connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(store.connection.execute("PRAGMA secure_delete").fetchone()[0], 1)
            run_id = store.start_run(
                {
                    "source": "fixture",
                    "access_token": "must-not-be-stored",
                    "nested": {"client_secret": "also-secret", "config_hash": "safe"},
                }
            )
            stored = store.get_run(run_id)
            self.assertEqual(stored["manifest"]["access_token"], "[REDACTED]")
            self.assertEqual(stored["manifest"]["nested"]["client_secret"], "[REDACTED]")
            self.assertEqual(stored["manifest"]["nested"]["config_hash"], "safe")
        if os.name != "nt":
            mode = stat.S_IMODE(self.database.stat().st_mode)
            self.assertEqual(mode, 0o600)
        self.assertNotIn("must-not-be-stored", self.database.read_bytes().decode("utf-8", "ignore"))

    def test_symlink_database_and_non_finite_metadata_are_rejected(self) -> None:
        if os.name != "nt":
            target = Path(self.temporary.name) / "target.sqlite3"
            target.touch()
            link = Path(self.temporary.name) / "linked.sqlite3"
            link.symlink_to(target)
            with self.assertRaises(SecurityError):
                Storage(link)

        with Storage(self.database) as store:
            with self.assertRaises(ValueError):
                store.upsert_raw_record(
                    record("nan", "Acme crashes.", metadata={"probability": float("nan")})
                )
            with self.assertRaises(ValueError):
                store.upsert_raw_record(
                    replace(record("time", "Acme crashes."), expires_at="not-a-time")
                )

    def test_idempotent_upsert_and_changed_content_invalidate_analysis(self) -> None:
        original = record("same", "Acme crashes on launch.")
        with Storage(self.database) as store:
            first_id = store.upsert_raw_record(original)
            self.assertEqual(first_id, raw_record_id(original))
            result = analyze_records(store.list_raw_records(), self.config)
            store.save_analysis(result)
            counts_before = {
                table: store.count(table)
                for table in ("raw_records", "assessments", "signals", "clusters", "scores")
            }

            second_id = store.upsert_raw_record(original)
            self.assertEqual(first_id, second_id)
            self.assertEqual(store.count("raw_records"), 1)
            self.assertEqual(
                {
                    table: store.count(table)
                    for table in ("raw_records", "assessments", "signals", "clusters", "scores")
                },
                counts_before,
            )

            changed = replace(original, text="Acme now needs PDF export.")
            self.assertEqual(store.upsert_raw_record(changed), first_id)
            self.assertEqual(store.count("raw_records"), 1)
            self.assertEqual(store.count("assessments"), 0)
            self.assertEqual(store.count("signals"), 0)
            self.assertEqual(store.count("clusters"), 0)
            self.assertEqual(store.count("scores"), 0)

    def test_operational_metadata_does_not_invalidate_unchanged_analysis(self) -> None:
        original = record(
            "social",
            "Acme crashes on launch.",
            source_type="x",
            metadata={"rate_limit": {"remaining": 10}},
        )
        with Storage(self.database) as store:
            store.upsert_raw_record(original)
            store.save_analysis(analyze_records(store.list_raw_records(), self.config))
            self.assertEqual(store.count("assessments"), 1)
            store.upsert_raw_record(
                replace(original, metadata={"rate_limit": {"remaining": 9}})
            )
            self.assertEqual(store.count("assessments"), 1)
            self.assertEqual(store.count("clusters"), 1)

    def test_declared_language_change_invalidates_analysis(self) -> None:
        original = record(
            "language",
            "Acme crashes on launch.",
            metadata={"lang": "en"},
        )
        with Storage(self.database) as store:
            store.upsert_raw_record(original)
            store.save_analysis(analyze_records(store.list_raw_records(), self.config))
            self.assertEqual(store.count("assessments"), 1)

            store.upsert_raw_record(replace(original, metadata={"lang": "fr"}))

            self.assertEqual(store.count("assessments"), 0)
            self.assertEqual(store.count("signals"), 0)
            self.assertEqual(store.count("clusters"), 0)
            self.assertEqual(store.count("scores"), 0)

    def test_visually_equivalent_unicode_edit_invalidates_signal_offsets(self) -> None:
        original = record("unicode", "İ Acme crashes on launch.")
        with Storage(self.database) as store:
            store.upsert_raw_record(original)
            store.save_analysis(analyze_records(store.list_raw_records(), self.config))
            self.assertEqual(store.count("analysis_state"), 1)

            store.upsert_raw_record(replace(original, text="i\u0307 Acme crashes on launch."))

            self.assertEqual(store.count("analysis_state"), 0)
            self.assertEqual(store.count("assessments"), 0)
            self.assertEqual(store.count("signals"), 0)

    def test_expiry_cascades_and_invalidates_whole_cluster_score(self) -> None:
        expired = record(
            "expired",
            "Acme crashes on launch.",
            author_key="expired-author",
            expires_at="2026-09-24T00:00:00Z",
        )
        retained = record(
            "retained",
            "Acme crashes on launch.",
            author_key="retained-author",
            expires_at="2026-10-01T00:00:00Z",
        )
        with Storage(self.database) as store:
            store.upsert_raw_records((expired, retained))
            store.save_analysis(
                analyze_records(store.list_raw_records(include_expired=True), self.config)
            )
            self.assertEqual(store.count("clusters"), 1)
            self.assertEqual(store.expire_records(as_of="2026-09-25T00:00:00Z"), 1)
            self.assertEqual(store.count("raw_records"), 1)
            self.assertEqual(store.count("assessments"), 1)
            self.assertEqual(store.count("signals"), 1)
            self.assertEqual(store.count("clusters"), 0)
            self.assertEqual(store.count("scores"), 0)
            self.assertEqual(store.count("audit_events"), 1)

    def test_large_expiry_is_chunked_below_runtime_sqlite_parameter_limit(self) -> None:
        expired = tuple(
            record(
                f"expired-{index}",
                f"Acme crashes on launch {index}.",
                author_key=f"author-{index}",
                expires_at="2026-09-24T00:00:00Z",
            )
            for index in range(30)
        )
        with Storage(self.database) as store:
            store.upsert_raw_records(expired)
            store.save_analysis(
                analyze_records(store.list_raw_records(include_expired=True), self.config)
            )
            previous = store.connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 8)
            try:
                self.assertEqual(
                    store.expire_records(as_of="2026-09-25T00:00:00Z"),
                    len(expired),
                )
            finally:
                store.connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, previous)
            self.assertEqual(store.count("raw_records"), 0)
            self.assertEqual(store.count("clusters"), 0)
            self.assertEqual(store.count("analysis_state"), 0)

    def test_purge_uses_parameters_and_keeps_only_redacted_audit_reference(self) -> None:
        hostile_source_id = "source'; DELETE FROM raw_records; --"
        first = record(
            "one",
            "Acme crashes on launch.",
            source_id=hostile_source_id,
            author_key="one",
        )
        second = record(
            "two",
            "Acme needs PDF export.",
            source_id="safe-source",
            author_key="two",
        )
        with Storage(self.database) as store:
            store.upsert_raw_records((first, second))
            store.save_cursor(hostile_source_id, "opaque-cursor")
            store.save_analysis(analyze_records(store.list_raw_records(), self.config))
            self.assertEqual(store.purge_source(hostile_source_id), 1)
            self.assertEqual(store.count("raw_records"), 1)
            self.assertIsNone(store.get_cursor(hostile_source_id))
            audit = store.connection.execute(
                "SELECT details_json FROM audit_events WHERE event_type = ?",
                ("source_purged",),
            ).fetchone()[0]
            self.assertNotIn(hostile_source_id, audit)
            self.assertIn("source_reference_hash", json.loads(audit))

    def test_explain_returns_evidence_and_score_arithmetic(self) -> None:
        items = (
            record("one", "Acme crashes on launch.", author_key="one"),
            record("two", "Acme crashes on launch.", author_key="two"),
        )
        with Storage(self.database) as store:
            store.upsert_raw_records(items)
            result = analyze_records(store.list_raw_records(), self.config)
            store.save_analysis(result)

            cluster_explanation = store.explain(result.clusters[0].cluster_id)
            self.assertEqual(cluster_explanation["kind"], "cluster")
            self.assertIsNotNone(cluster_explanation["score"])
            self.assertEqual(len(cluster_explanation["signals"]), 2)
            self.assertEqual(store.count("duplicate_groups"), 1)
            for signal in cluster_explanation["signals"]:
                self.assertEqual(signal["evidence_text"], "Acme crashes on launch.")
                self.assertIsNotNone(signal["duplicate_group_id"])
                self.assertGreaterEqual(signal["evidence_rank"], 1)

            signal_explanation = store.explain(result.signals[0].signal_id)
            self.assertEqual(signal_explanation["kind"], "signal")
            self.assertEqual(signal_explanation["assessment"]["disposition"], "eligible")


if __name__ == "__main__":
    unittest.main()
