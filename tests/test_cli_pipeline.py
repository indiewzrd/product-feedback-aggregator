from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from feedback_aggregator.cli import initialize, main
from feedback_aggregator.errors import (
    CollectionError,
    NotFoundError,
    PartialCollectionError,
    ReadinessError,
    SecurityError,
)
from feedback_aggregator.models import CollectionPlan, CollectionResult
from feedback_aggregator.pipeline import FeedbackApplication
from feedback_aggregator.storage import Storage


class EndToEndWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        initialize(self.root)
        self.config = self.root / "feedback.yml"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_zero_key_workflow_is_offline_idempotent_and_explainable(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        readiness = app.check()
        self.assertTrue(readiness["ready"])
        plan = app.plans()
        self.assertFalse(plan["network_access"])
        self.assertEqual(plan["totals"]["estimated_requests"], 0)

        first = app.run()
        second = app.run()
        self.assertEqual(first["collection"]["record_count"], 5)
        self.assertEqual(second["analysis"]["records"], 5)
        self.assertGreater(first["analysis"]["clusters"], 0)

        report_path = Path(first["report"]["paths"]["json"])
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["summary"]["records"], 5)
        self.assertEqual(report["run"]["status"], "complete")
        self.assertIn("algorithm_versions", report["run"])
        ranks = [cluster["rank"] for cluster in report["clusters"]]
        self.assertEqual(ranks, list(range(1, len(ranks) + 1)))
        explanation = app.explain(report["clusters"][0]["cluster_id"])
        self.assertEqual(explanation["kind"], "cluster")
        self.assertIn("components", explanation["score"])

        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 5)
            run = store.get_run(first["collection"]["run_id"])
            self.assertEqual(run["manifest"]["schema_version"], 2)
            self.assertEqual(
                set(run["manifest"]["stages"]),
                {"collection", "reconciliation", "analysis", "reporting"},
            )
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(app.config.storage.path.stat().st_mode), 0o600)
            self.assertEqual(
                stat.S_IMODE(app.config.privacy.author_salt_file.stat().st_mode),
                0o600,
            )

    def test_init_preserves_existing_files(self) -> None:
        original = self.config.read_text(encoding="utf-8")
        result = initialize(self.root)
        self.assertEqual(self.config.read_text(encoding="utf-8"), original)
        self.assertIn(str(self.config.resolve()), result["preserved_existing"])

    def test_init_safely_merges_private_gitignore_rules_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ignore = root / ".gitignore"
            ignore.write_text("# keep this rule\ncustom-output/\n.feedback/\n", encoding="utf-8")

            first = initialize(root)
            after_first = ignore.read_text(encoding="utf-8")
            second = initialize(root)

            self.assertIn("# keep this rule", after_first)
            self.assertEqual(after_first.count(".feedback/"), 1)
            self.assertEqual(after_first.count("reports/"), 1)
            self.assertEqual(ignore.read_text(encoding="utf-8"), after_first)
            self.assertIn(str(ignore.resolve()), first["updated"])
            self.assertIn(str(ignore.resolve()), second["preserved_existing"])

    def test_check_validates_provider_without_creating_storage(self) -> None:
        text = self.config.read_text(encoding="utf-8").replace(
            "sources:\n",
            "providers:\n"
            "  - id: local-semantic\n"
            "    type: local_subprocess\n"
            "    enabled: true\n"
            f"    command: [{json.dumps(sys.executable)}]\n"
            "    model: fixture-model-v1\n\n"
            "sources:\n",
        )
        self.config.write_text(text, encoding="utf-8")
        app = FeedbackApplication.from_path(self.config)
        self.assertFalse(app.config.storage.path.exists())

        result = app.check()

        provider = next(item for item in result["items"] if item["name"] == "provider:local-semantic")
        self.assertEqual(provider["status"], "ok")
        self.assertFalse(app.config.storage.path.exists())

    def test_cli_json_envelope_and_stable_error_code(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["--config", str(self.config), "--json", "collect", "--plan"])
        self.assertEqual(result, 0)
        value = json.loads(stdout.getvalue())
        self.assertTrue(value["ok"])
        self.assertEqual(value["schema_version"], 1)
        self.assertEqual(stderr.getvalue(), "")

        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["--config", str(self.config), "--json", "purge"])
        self.assertEqual(result, ReadinessError.exit_code)
        self.assertEqual(stdout.getvalue(), "")
        error = json.loads(stderr.getvalue())
        self.assertFalse(error["ok"])
        self.assertEqual(error["error"]["exit_code"], ReadinessError.exit_code)

        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["--config", str(self.config), "check", "--json"])
        self.assertEqual(result, 0)
        self.assertTrue(json.loads(stdout.getvalue())["ok"])
        self.assertEqual(stderr.getvalue(), "")


class IntegrationBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        initialize(self.root)
        self.config = self.root / "feedback.yml"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _add_missing_source(self) -> None:
        text = self.config.read_text(encoding="utf-8")
        text += """
  - id: missing-json
    type: json
    enabled: true
    max_items: 10
    options:
      paths: [does-not-exist.json]
    policy:
      acquisition_mode: user_file
      approval_required: false
      approval_reference: Local test input
      raw_ttl_hours: 0
      redistribution_mode: local_only
      policy_version: local-v1
      policy_version_checked_at: 2026-09-25
"""
        self.config.write_text(text, encoding="utf-8")

    def test_strict_collection_rolls_back_and_default_isolates_source(self) -> None:
        self._add_missing_source()
        app = FeedbackApplication.from_path(self.config)
        with self.assertRaises(ReadinessError):
            app.collect(strict=True)
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 0)

        result = app.collect(strict=False)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["record_count"], 5)
        self.assertEqual(result["failures"][0]["source_id"], "missing-json")
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 5)

    def test_partial_social_progress_is_checkpointed_except_in_strict_mode(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        partial = CollectionResult.from_records(
            (),
            cursor="safe-page-checkpoint",
            requests_made=1,
            resources_read=10,
            cost_usd=0.05,
            stop_reason="partial_error",
        )

        class FailingAfterPageConnector:
            def plan(self) -> CollectionPlan:
                return CollectionPlan(
                    "sample-json",
                    "json",
                    "bounded query",
                    100,
                    2,
                    0.10,
                    (),
                )

            def collect(self, *, cursor: str | None = None) -> CollectionResult:
                del cursor
                raise PartialCollectionError("second page failed", partial)

        connector = FailingAfterPageConnector()
        with (
            patch.object(app, "_source_readiness_errors", return_value=[]),
            patch.object(app, "_connector", return_value=connector),
        ):
            result = app.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["sources"]["sample-json"]["resources_read"], 10)
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.get_cursor("sample-json")["cursor"], "safe-page-checkpoint")

        app.purge()
        with (
            patch.object(app, "_source_readiness_errors", return_value=[]),
            patch.object(app, "_connector", return_value=connector),
            self.assertRaises(PartialCollectionError),
        ):
            app.collect(strict=True)
        with Storage(app.config.storage.path) as store:
            self.assertIsNone(store.get_cursor("sample-json"))

    def test_persistence_failure_is_not_reported_as_collected(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        with patch.object(
            app,
            "_persist_result",
            side_effect=ValueError("synthetic storage failure"),
        ):
            with self.assertRaises(CollectionError):
                app.collect()
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 0)

    def test_restricted_policy_removes_verbatim_from_reports_and_explanations(self) -> None:
        canary = "Acme Notes crashes <script>alert('REPORT_CANARY')</script>."
        records_path = self.root / "feedback.sample.json"
        records_path.write_text(
            json.dumps(
                [
                    {
                        "id": "restricted-1",
                        "text": canary,
                        "created_at": "2026-09-25T00:00:00Z",
                        "author": "private-author",
                    }
                ]
            ),
            encoding="utf-8",
        )
        text = self.config.read_text(encoding="utf-8").replace(
            "redistribution_mode: local_only",
            "redistribution_mode: ids_links_aggregates",
        )
        self.config.write_text(text, encoding="utf-8")
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        json_path = Path(result["report"]["paths"]["json"])
        markdown_path = Path(result["report"]["paths"]["markdown"])
        self.assertNotIn("REPORT_CANARY", json_path.read_text(encoding="utf-8"))
        self.assertNotIn("REPORT_CANARY", markdown_path.read_text(encoding="utf-8"))
        report = json.loads(json_path.read_text(encoding="utf-8"))
        cluster = report["clusters"][0]
        self.assertEqual(cluster["label"], "Bug feedback")
        self.assertFalse(cluster["evidence"][0]["verbatim_included"])
        explanation = app.explain(cluster["cluster_id"])
        serialized = json.dumps(explanation)
        self.assertNotIn("REPORT_CANARY", serialized)
        self.assertTrue(explanation["signals"][0]["evidence_redacted"])

    def test_local_markdown_is_escaped_and_report_symlink_is_replaced_safely(self) -> None:
        canary = "Acme Notes has a bug <script>REPORT_CANARY</script> [click](javascript:alert(1))."
        records_path = self.root / "feedback.sample.json"
        records_path.write_text(
            json.dumps(
                [
                    {
                        "id": "hostile-1",
                        "text": canary,
                        "created_at": "2026-09-25T00:00:00Z",
                    }
                ]
            ),
            encoding="utf-8",
        )
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        markdown_path = Path(result["report"]["paths"]["markdown"])
        markdown = markdown_path.read_text(encoding="utf-8")
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("[click](javascript:", markdown)
        self.assertIn("&lt;script&gt;", markdown)

        markdown_path.unlink()
        target = self.root / "must-not-change.txt"
        target.write_text("safe", encoding="utf-8")
        markdown_path.symlink_to(target)
        app.report()
        self.assertEqual(target.read_text(encoding="utf-8"), "safe")
        self.assertTrue(markdown_path.is_file())
        self.assertFalse(markdown_path.is_symlink())

    def test_data_change_makes_old_analysis_unreportable(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        app.run()
        records = json.loads((self.root / "feedback.sample.json").read_text(encoding="utf-8"))
        records[0]["text"] = "Acme Notes now needs a calendar export feature."
        (self.root / "feedback.sample.json").write_text(json.dumps(records), encoding="utf-8")
        app.collect()
        with self.assertRaises(ReadinessError):
            app.report()

    def test_policy_error_blocks_collection_and_run(self) -> None:
        text = self.config.read_text(encoding="utf-8").replace(
            'policy_version_checked_at: "2026-09-25"',
            'policy_version_checked_at: "2099-01-01"',
        )
        self.config.write_text(text, encoding="utf-8")
        app = FeedbackApplication.from_path(self.config)
        self.assertFalse(app.check()["ready"])
        with self.assertRaises(CollectionError):
            app.run()
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 0)

    def test_expired_rows_cannot_be_reported(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        report_paths = tuple(Path(path) for path in result["report"]["paths"].values())
        with Storage(app.config.storage.path) as store, store.transaction() as connection:
            connection.execute(
                "UPDATE raw_records SET expires_at = ? WHERE native_id = ?",
                ("2000-01-01T00:00:00Z", "sample-001"),
            )
        with self.assertRaises(ReadinessError):
            app.report()
        self.assertTrue(all(not path.exists() for path in report_paths))

    def test_deleting_any_record_invalidates_the_global_analysis_snapshot(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        app.run()
        with Storage(app.config.storage.path) as store, store.transaction() as connection:
            connection.execute(
                "UPDATE raw_records SET expires_at = ? WHERE native_id = ?",
                ("2000-01-01T00:00:00Z", "sample-005"),
            )

        app.reconcile()

        with self.assertRaises(ReadinessError):
            app.report()
        self.assertGreater(app.analyze()["records"], 0)
        self.assertTrue(app.report()["paths"]["json"].endswith("feedback-report.json"))

    def test_zero_signal_analysis_detects_configuration_changes(self) -> None:
        (self.root / "feedback.sample.json").write_text(
            json.dumps(
                [
                    {
                        "id": "irrelevant",
                        "text": "weather today",
                        "created_at": "2026-09-25T00:00:00Z",
                    }
                ]
            ),
            encoding="utf-8",
        )
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        self.assertEqual(result["analysis"]["scores"], 0)
        report_paths = tuple(Path(path) for path in result["report"]["paths"].values())

        self.config.write_text(
            self.config.read_text(encoding="utf-8").replace(
                "relevance_threshold: 0.35", "relevance_threshold: 0.99"
            ),
            encoding="utf-8",
        )
        changed = FeedbackApplication.from_path(self.config)

        with self.assertRaisesRegex(ReadinessError, "configuration or input changed"):
            changed.report()
        self.assertTrue(all(not path.exists() for path in report_paths))

    def test_explain_expires_rows_before_returning_evidence(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        json_report = Path(result["report"]["paths"]["json"])
        markdown_report = Path(result["report"]["paths"]["markdown"])
        with Storage(app.config.storage.path) as store, store.transaction() as connection:
            row = connection.execute(
                "SELECT record_id FROM raw_records WHERE native_id = ?", ("sample-001",)
            ).fetchone()
            connection.execute(
                "UPDATE raw_records SET expires_at = ? WHERE record_id = ?",
                ("2000-01-01T00:00:00Z", row["record_id"]),
            )

        with self.assertRaises(NotFoundError):
            app.explain(str(row["record_id"]))

        self.assertFalse(json_report.exists())
        self.assertFalse(markdown_report.exists())

    @unittest.skipIf(os.name == "nt", "symlink behavior requires POSIX privileges")
    def test_report_output_directory_symlink_is_rejected(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        output = app.config.outputs.directory
        target = self.root / "unrelated-reports"
        target.mkdir()
        output.symlink_to(target, target_is_directory=True)

        with self.assertRaises(SecurityError):
            app.invalidate_reports()

    def test_configured_ttl_is_enforced_for_json_at_persistence_boundary(self) -> None:
        text = self.config.read_text(encoding="utf-8").replace(
            "raw_ttl_hours: 0", "raw_ttl_hours: 1"
        )
        self.config.write_text(text, encoding="utf-8")
        app = FeedbackApplication.from_path(self.config)
        app.collect()
        with Storage(app.config.storage.path) as store:
            records = store.list_raw_records(include_expired=True)
        self.assertTrue(records)
        for record in records:
            retrieved = datetime.fromisoformat(record.retrieved_at.replace("Z", "+00:00"))
            expires = datetime.fromisoformat(str(record.expires_at).replace("Z", "+00:00"))
            self.assertEqual((expires - retrieved).total_seconds(), 3600)

    def test_report_and_explain_strip_url_credentials_and_query_secrets(self) -> None:
        records_path = self.root / "feedback.sample.json"
        records = json.loads(records_path.read_text(encoding="utf-8"))
        records[0]["url"] = "https://user:password@example.test/items/one?token=SECRET#part"
        records_path.write_text(json.dumps(records), encoding="utf-8")
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        report_text = Path(result["report"]["paths"]["json"]).read_text(encoding="utf-8")
        self.assertNotIn("SECRET", report_text)
        self.assertNotIn("password", report_text)
        report = json.loads(report_text)
        signal_id = report["clusters"][0]["evidence"][0]["signal_id"]
        explanation = json.dumps(app.explain(signal_id))
        self.assertNotIn("SECRET", explanation)
        self.assertNotIn("password", explanation)

    def test_inferred_created_at_preserves_first_seen_time(self) -> None:
        records_path = self.root / "feedback.sample.json"
        records = json.loads(records_path.read_text(encoding="utf-8"))
        records[0].pop("created_at")
        records_path.write_text(json.dumps(records), encoding="utf-8")
        app = FeedbackApplication.from_path(self.config)
        with patch("feedback_aggregator.connectors.json_file.utc_now", return_value="2026-01-01T00:00:00Z"):
            app.collect()
        with patch("feedback_aggregator.connectors.json_file.utc_now", return_value="2026-02-01T00:00:00Z"):
            app.collect()
        with Storage(app.config.storage.path) as store:
            row = store.connection.execute(
                "SELECT created_at FROM raw_records WHERE native_id = ?", ("sample-001",)
            ).fetchone()
        self.assertEqual(row["created_at"], "2026-01-01T00:00:00Z")

    def test_review_override_is_persistent_and_explainable(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        app.run()
        with Storage(app.config.storage.path) as store:
            row = store.connection.execute(
                "SELECT record_id FROM assessments WHERE disposition = 'eligible' LIMIT 1"
            ).fetchone()
        record_id = str(row["record_id"])
        app.review(record_id, "exclude", "Reviewed as unrelated")
        app.analyze()
        explanation = app.explain(record_id)
        self.assertEqual(explanation["assessment"]["disposition"], "suppressed")
        self.assertIn("review:exclude", explanation["assessment"]["noise_reasons"])
        self.assertEqual(explanation["review_override"]["action"], "exclude")

    def test_failed_review_clear_preserves_reports_and_analysis(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        report_paths = tuple(Path(path) for path in result["report"]["paths"].values())
        with Storage(app.config.storage.path) as store:
            before = {
                table: store.count(table)
                for table in ("assessments", "signals", "clusters", "scores", "analysis_state")
            }

        with self.assertRaises(ReadinessError, msg="missing override must fail without mutation"):
            app.review("record_does_not_exist", "clear")

        self.assertTrue(all(path.exists() for path in report_paths))
        with Storage(app.config.storage.path) as store:
            after = {table: store.count(table) for table in before}
        self.assertEqual(after, before)

    def test_disabled_source_still_obeys_a_tightened_retention_policy(self) -> None:
        configured = self.config.read_text(encoding="utf-8").replace(
            "raw_ttl_hours: 0", "raw_ttl_hours: 100"
        )
        self.config.write_text(configured, encoding="utf-8")
        app = FeedbackApplication.from_path(self.config)
        app.collect()

        now = datetime.now(timezone.utc).replace(microsecond=0)
        old_retrieval = (now - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        future_expiry = (now + timedelta(hours=50)).isoformat().replace("+00:00", "Z")
        with Storage(app.config.storage.path) as store, store.transaction() as connection:
            connection.execute(
                "UPDATE raw_records SET retrieved_at = ?, expires_at = ? WHERE native_id = ?",
                (old_retrieval, future_expiry, "sample-001"),
            )

        tightened = self.config.read_text(encoding="utf-8")
        tightened = tightened.replace("enabled: true", "enabled: false", 1)
        tightened = tightened.replace("raw_ttl_hours: 100", "raw_ttl_hours: 1")
        self.config.write_text(tightened, encoding="utf-8")
        result = FeedbackApplication.from_path(self.config).reconcile()

        self.assertEqual(result["expired_records"], 1)
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 4)

    def test_old_algorithm_versions_cannot_be_reported(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        app.run()
        with Storage(app.config.storage.path) as store, store.transaction() as connection:
            connection.execute("UPDATE assessments SET version = 'obsolete-version'")
        with self.assertRaises(ReadinessError):
            app.report()

    def test_purge_all_includes_source_removed_from_config(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        app.run()
        with Storage(app.config.storage.path) as store, store.transaction() as connection:
            connection.execute(
                "UPDATE raw_records SET source_id = ? WHERE native_id = ?",
                ("retired-source", "sample-001"),
            )
        result = app.purge()
        self.assertIn("retired-source", result["source_ids"])
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 0)
            self.assertEqual(store.count("runs"), 0)

    def test_purge_all_includes_orphan_cursor(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        app.run()
        with Storage(app.config.storage.path) as store:
            store.save_cursor("cursor-only-source", "opaque")
        result = app.purge()
        self.assertIn("cursor-only-source", result["source_ids"])
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("cursors"), 0)

    def test_purge_fails_before_data_deletion_when_report_cannot_be_removed(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        report_path = Path(result["report"]["paths"]["json"])
        report_path.unlink()
        report_path.mkdir()
        with self.assertRaises(SecurityError):
            app.purge()
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 5)

    def test_reconcile_fails_before_data_deletion_when_report_cannot_be_removed(self) -> None:
        app = FeedbackApplication.from_path(self.config)
        result = app.run()
        with Storage(app.config.storage.path) as store, store.transaction() as connection:
            connection.execute(
                "UPDATE raw_records SET expires_at = ? WHERE native_id = ?",
                ("2000-01-01T00:00:00Z", "sample-001"),
            )
        report_path = Path(result["report"]["paths"]["json"])
        report_path.unlink()
        report_path.mkdir()
        with self.assertRaises(SecurityError):
            app.reconcile()
        with Storage(app.config.storage.path) as store:
            self.assertEqual(store.count("raw_records"), 5)


if __name__ == "__main__":
    unittest.main()
