from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from feedback_aggregator.config import load_config
from feedback_aggregator.errors import ConfigurationError


class ConfigTests(unittest.TestCase):
    def _write(self, text: str) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "feedback.yml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_bundled_example_loads(self) -> None:
        config = load_config(Path(__file__).parents[1] / "examples" / "feedback.example.yml")
        self.assertEqual(config.version, 1)
        self.assertEqual(config.product.name, "Acme Notes")
        self.assertEqual(config.sources[0].type, "json")
        self.assertTrue(config.config_hash.startswith("cfg_"))

    def test_duplicate_yaml_key_is_rejected(self) -> None:
        path = self._write("version: 1\nversion: 1\n")
        with self.assertRaisesRegex(ConfigurationError, "duplicate key"):
            load_config(path)

    def test_yaml_aliases_are_rejected(self) -> None:
        path = self._write("version: 1\nproduct: &p {name: Example}\ncopy: *p\n")
        with self.assertRaisesRegex(ConfigurationError, "anchors"):
            load_config(path)

    def test_yaml_parser_errors_do_not_echo_source_text(self) -> None:
        canary = "CANARY_SECRET_VALUE"
        path = self._write(f"version: 1\nsecret: [{canary}\n")
        with self.assertRaises(ConfigurationError) as raised:
            load_config(path)
        self.assertNotIn(canary, str(raised.exception))

    def test_report_destinations_cannot_overlap_private_or_input_files(self) -> None:
        cases = {
            "storage.path": "storage: {path: reports/feedback-report.json}\n",
            "privacy.author_salt_file": (
                "privacy: {author_salt_file: reports/feedback-report.md}\n"
            ),
            "JSON input": "",
        }
        for expected, extra in cases.items():
            with self.subTest(expected=expected):
                input_path = (
                    "reports/feedback-report.json"
                    if expected == "JSON input"
                    else "input.json"
                )
                path = self._write(
                    "version: 1\n"
                    "product: {name: Example}\n"
                    "outputs: {directory: reports}\n"
                    f"{extra}"
                    "sources:\n"
                    "  - id: local\n"
                    "    type: json\n"
                    f"    options: {{paths: [{input_path}]}}\n"
                )
                with self.assertRaisesRegex(ConfigurationError, expected):
                    load_config(path)

    def test_writable_state_paths_cannot_overlap_inputs_or_sqlite_sidecars(self) -> None:
        cases = (
            ("input.json", "input.json"),
            ("state.db", "state.db-journal"),
            ("state.db", "state.db-wal"),
            ("state.db", "state.db-shm"),
        )
        for database, input_path in cases:
            with self.subTest(input_path=input_path):
                path = self._write(
                    "version: 1\n"
                    "product: {name: Example}\n"
                    f"storage: {{path: {database}}}\n"
                    "sources:\n"
                    "  - id: local\n"
                    "    type: json\n"
                    f"    options: {{paths: [{input_path}]}}\n"
                )
                with self.assertRaisesRegex(ConfigurationError, "Path ownership conflict"):
                    load_config(path)

    def test_path_ownership_is_case_insensitive_on_case_insensitive_platforms(self) -> None:
        path = self._write(
            "version: 1\n"
            "product: {name: Example}\n"
            "storage: {path: Reports/feedback-report.json}\n"
            "outputs: {directory: reports}\n"
            "sources:\n"
            "  - id: local\n"
            "    type: json\n"
            "    options: {paths: [input.json]}\n"
        )
        with (
            patch("feedback_aggregator.config._CASE_INSENSITIVE_PATHS", True),
            self.assertRaisesRegex(ConfigurationError, "Path ownership conflict"),
        ):
            load_config(path)

    def test_path_ownership_normalizes_canonically_equivalent_unicode(self) -> None:
        path = self._write(
            "version: 1\n"
            "product: {name: Example}\n"
            "storage: {path: r\u00e9ports/feedback-report.json}\n"
            "outputs: {directory: re\u0301ports}\n"
            "sources:\n"
            "  - id: local\n"
            "    type: json\n"
            "    options: {paths: [input.json]}\n"
        )
        with self.assertRaisesRegex(ConfigurationError, "Path ownership conflict"):
            load_config(path)

    def test_unknown_top_level_key_is_rejected(self) -> None:
        path = self._write("version: 1\nproduct: {name: Example}\nsources: []\nsurprise: true\n")
        with self.assertRaisesRegex(ConfigurationError, "Unknown top-level"):
            load_config(path)

    def test_unknown_nested_keys_and_coercible_scalar_types_are_rejected(self) -> None:
        unknown = self._write(
            """
version: 1
product: {name: Example}
limits: {total_timeout_second: 30}
sources:
  - id: local
    type: json
    options: {paths: [input.json]}
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "Unknown keys in limits"):
            load_config(unknown)

        boolean_version = self._write(
            """
version: true
product: {name: Example}
sources: [{id: local, type: json, options: {paths: [input.json]}}]
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "Configuration version"):
            load_config(boolean_version)

        numeric_name = self._write(
            """
version: 1
product: {name: 123}
sources: [{id: local, type: json, options: {paths: [input.json]}}]
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "product.name must be a string"):
            load_config(numeric_name)

        numeric_string = self._write(
            """
version: 1
product: {name: Example}
limits: {max_items_per_source: "10"}
sources: [{id: local, type: json, options: {paths: [input.json]}}]
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "must be an integer"):
            load_config(numeric_string)

    def test_published_configuration_schema_is_valid_json_and_strict(self) -> None:
        schema_path = Path(__file__).parents[1] / "schemas" / "feedback.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["version"]["const"], 1)

    def test_x_source_requires_cost_cap(self) -> None:
        path = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: x-source
    type: x
    options: {bearer_token_env: X_BEARER_TOKEN}
    policy:
      policy_version: x-2026-09-25
      policy_version_checked_at: 2026-09-25
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "max_cost_usd"):
            load_config(path)

    def test_apify_source_requires_cost_cap_and_explicit_remote_processing(self) -> None:
        missing_cost = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: reddit-apify
    type: reddit_apify
    options:
      approval_confirmed: true
      actor_build: 1.2.3
    policy:
      remote_processing_allowed: true
      policy_version: apify-2026-09-25
      policy_version_checked_at: 2026-09-25
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "max_cost_usd"):
            load_config(missing_cost)

        missing_remote_approval = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: x-apify
    type: x_apify
    options:
      approval_confirmed: true
      actor_build: 1.2.3
    policy:
      max_cost_usd: 1.0
      policy_version: apify-2026-09-25
      policy_version_checked_at: 2026-09-25
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "remote_processing_allowed"):
            load_config(missing_remote_approval)

    def test_apify_configuration_accepts_only_environment_name_reference(self) -> None:
        path = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: x-apify
    type: x_apify
    max_items: 100
    options:
      approval_confirmed: true
      token_env: APIFY_TOKEN
      actor_build: 1.2.3
      search_terms: ['"Example"']
    policy:
      acquisition_mode: third_party_scraper
      approval_required: true
      approval_reference: Operator-reviewed X and Apify terms
      remote_processing_allowed: true
      raw_ttl_hours: 24
      max_cost_usd: 1.0
      policy_version: apify-2026-09-25
      policy_version_checked_at: 2026-09-25
"""
        )
        config = load_config(path)
        self.assertEqual(config.sources[0].type, "x_apify")
        self.assertEqual(config.sources[0].options["token_env"], "APIFY_TOKEN")

    def test_secret_reference_must_be_environment_name(self) -> None:
        path = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: reddit-source
    type: reddit
    options:
      client_id_env: actual-secret-value
    policy:
      policy_version: reddit-2026-09-25
      policy_version_checked_at: 2026-09-25
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "uppercase environment"):
            load_config(path)

    def test_boolean_strings_and_unknown_options_are_rejected(self) -> None:
        quoted_boolean = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: local
    type: json
    enabled: "false"
    options: {paths: [feedback.json]}
    policy:
      approval_required: false
      approval_reference: Local input
      policy_version: local-v1
      policy_version_checked_at: 2026-09-25
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "enabled must be true or false"):
            load_config(quoted_boolean)

        unknown_option = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: local
    type: json
    options:
      paths: [feedback.json]
      bearer_token: must-not-be-accepted
    policy:
      approval_required: false
      approval_reference: Local input
      policy_version: local-v1
      policy_version_checked_at: 2026-09-25
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "Unknown options"):
            load_config(unknown_option)

    def test_policy_types_fail_closed(self) -> None:
        path = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: local
    type: json
    options: {paths: [feedback.json]}
    policy:
      approval_required: "false"
      approval_reference: Local input
      policy_version: local-v1
      policy_version_checked_at: 2026-09-25
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "approval_required"):
            load_config(path)

    def test_social_sources_require_positive_raw_ttl(self) -> None:
        path = self._write(
            """
version: 1
product: {name: Example}
sources:
  - id: x-source
    type: x
    options:
      approval_confirmed: true
      bearer_token_env: X_BEARER_TOKEN
      mode: recent_search
      query: Example
    policy:
      approval_required: true
      approval_reference: X Developer Guidelines
      raw_ttl_hours: 0
      cost_per_resource_usd: 0.005
      max_cost_usd: 1.0
      policy_version: x-2026-09-25
      policy_version_checked_at: 2026-09-25
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "raw_ttl_hours of at least 1"):
            load_config(path)

    def test_optional_local_provider_is_strict_and_disabled_by_default(self) -> None:
        path = self._write(
            f"""
version: 1
product: {{name: Example}}
providers:
  - id: local-semantic
    type: local_subprocess
    command: [{json.dumps(sys.executable)}]
    model: fixture-model-v1
sources:
  - id: local
    type: json
    options: {{paths: [feedback.json]}}
"""
        )
        config = load_config(path)
        self.assertEqual(len(config.providers), 1)
        self.assertFalse(config.providers[0].enabled)
        self.assertEqual(config.providers[0].max_retries, 0)

    def test_local_provider_rejects_relative_command_and_unbounded_retries(self) -> None:
        relative = self._write(
            """
version: 1
product: {name: Example}
providers:
  - id: local-semantic
    type: local_subprocess
    command: [python, provider.py]
    model: fixture-model-v1
sources:
  - id: local
    type: json
    options: {paths: [feedback.json]}
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "absolute path"):
            load_config(relative)

        retries = self._write(
            f"""
version: 1
product: {{name: Example}}
providers:
  - id: local-semantic
    type: local_subprocess
    command: [{json.dumps(sys.executable)}]
    model: fixture-model-v1
    max_retries: 3
sources:
  - id: local
    type: json
    options: {{paths: [feedback.json]}}
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "max_retries"):
            load_config(retries)

    def test_local_provider_unknown_or_hosted_types_fail_closed(self) -> None:
        path = self._write(
            f"""
version: 1
product: {{name: Example}}
providers:
  - id: hosted
    type: hosted_api
    command: [{json.dumps(sys.executable)}]
    model: remote-model
sources:
  - id: local
    type: json
    options: {{paths: [feedback.json]}}
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "local_subprocess"):
            load_config(path)

    def test_external_command_arguments_are_bounded(self) -> None:
        oversized = "x" * 4_097
        path = self._write(
            f"""
version: 1
product: {{name: Example}}
sources:
  - id: external-input
    type: external
    options:
      command: [{json.dumps(sys.executable)}, {json.dumps(oversized)}]
"""
        )
        with self.assertRaisesRegex(ConfigurationError, "oversized argument"):
            load_config(path)


if __name__ == "__main__":
    unittest.main()
