from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from feedback_aggregator.config import load_config
from feedback_aggregator.connectors.base import ConnectorContext
from feedback_aggregator.connectors.json_file import (
    JsonFileConnector,
    iter_json_records,
    record_from_mapping,
    strict_json_loads,
)
from feedback_aggregator.errors import CollectionError


class JsonConnectorTests(unittest.TestCase):
    def test_bundled_sample_collects_deterministically(self) -> None:
        config = load_config(Path(__file__).parents[1] / "examples" / "feedback.example.yml")
        source = config.sources[0]
        connector = JsonFileConnector(ConnectorContext(config, source, "test-salt"))
        result = connector.collect()
        self.assertEqual(len(result.records), 10)
        self.assertEqual(result.records[0].native_id, "sample-001")
        self.assertTrue(result.records[0].author_key.startswith("author_"))
        self.assertNotIn("sample-user-a", result.records[0].metadata.values())

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            strict_json_loads('{"text":"one","text":"two"}')

    def test_file_parser_errors_do_not_echo_source_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            canary = "CANARY_SECRET_VALUE"
            path.write_text(f'{{"{canary}":1,"{canary}":2}}', encoding="utf-8")
            with self.assertRaises(CollectionError) as raised:
                tuple(
                    iter_json_records(
                        path,
                        max_file_bytes=10_000,
                        max_line_bytes=10_000,
                    )
                )
            self.assertNotIn(canary, str(raised.exception))

    def test_nonfinite_numbers_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            strict_json_loads('{"score":NaN}')

    def test_created_at_requires_an_explicit_timezone(self) -> None:
        with self.assertRaisesRegex(ValueError, "with a timezone"):
            record_from_mapping(
                {"id": "one", "text": "Example crashes", "created_at": "2026-09-25T12:00:00"},
                source_id="local",
                source_type="json",
                location="fixture",
                mapping={},
                author_salt="salt",
                acquisition_mode="user_file",
                policy_assurance="user",
            )

    def test_unknown_record_schema_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "schema_version must be 1"):
            record_from_mapping(
                {"schema_version": 2, "text": "Example crashes"},
                source_id="local",
                source_type="json",
                location="fixture",
                mapping={},
                author_salt="salt",
                acquisition_mode="user_file",
                policy_assurance="user",
            )

    def test_records_wrapper_version_and_fields_are_strict(self) -> None:
        invalid_documents = (
            '{"schema_version":2,"records":[]}',
            '{"records":[],"unexpected":true}',
            '{"records":{}}',
        )
        for document in invalid_documents:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "input.json"
                path.write_text(document, encoding="utf-8")
                with self.assertRaises(CollectionError):
                    tuple(
                        iter_json_records(
                            path,
                            max_file_bytes=10_000,
                            max_line_bytes=10_000,
                        )
                    )

    def test_record_fields_are_not_coerced_or_silently_truncated(self) -> None:
        kwargs = {
            "source_id": "local",
            "source_type": "json",
            "location": "fixture",
            "mapping": {},
            "author_salt": "salt",
            "acquisition_mode": "user_file",
            "policy_assurance": "user",
        }
        invalid_records = (
            {"text": 123},
            {"text": "x" * 200_001},
            {"text": "Example", "id": True},
            {"text": "Example", "id": None},
            {"text": "Example", "url": 123},
            {"text": "Example", "created_at": 123},
            {"text": "Example", "author": False},
            {"text": "Example", "metadata": {"nested": []}},
            {"text": "Example", "metadata": {"input_location": "spoofed"}},
            {"text": "Example", "metadata": {"long": "x" * 4_097}},
        )
        for item in invalid_records:
            with self.subTest(item_type=tuple(item)):
                with self.assertRaises(ValueError):
                    record_from_mapping(item, **kwargs)

        accepted = record_from_mapping(
            {"text": "Example", "id": 123, "author": None, "metadata": {"note": None}},
            **kwargs,
        )
        self.assertEqual(accepted.native_id, "123")
        self.assertIsNone(accepted.metadata["note"])

    def test_permissive_ndjson_skips_bad_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "input.ndjson"
            data.write_text(
                '{"id":"1","text":"Example works"}\nnot-json\n{"id":"2","text":"Example fails"}\n',
                encoding="utf-8",
            )
            config_file = root / "feedback.yml"
            config_file.write_text(
                """
version: 1
product: {name: Example, terms: [example]}
sources:
  - id: local
    type: json
    options: {paths: [input.ndjson], permissive: true}
    policy: {policy_version: local-v1, policy_version_checked_at: 2026-09-25}
""",
                encoding="utf-8",
            )
            config = load_config(config_file)
            connector = JsonFileConnector(ConnectorContext(config, config.sources[0], "salt"))
            self.assertEqual(len(connector.collect().records), 2)

    def test_permissive_json_array_skips_non_object_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text(
                '[{"id":"1","text":"Example works"}, 42, {"id":"2","text":"Example fails"}]',
                encoding="utf-8",
            )
            config_file = root / "feedback.yml"
            config_file.write_text(
                """
version: 1
product: {name: Example}
sources:
  - id: local
    type: json
    options: {paths: [input.json], permissive: true}
    policy: {policy_version: local-v1, policy_version_checked_at: 2026-09-25}
""",
                encoding="utf-8",
            )
            config = load_config(config_file)
            connector = JsonFileConnector(ConnectorContext(config, config.sources[0], "salt"))
            self.assertEqual(len(connector.collect().records), 2)

    def test_single_json_record_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "input.json").write_text(
                '{"schema_version":1,"id":"1","text":"Example export fails"}',
                encoding="utf-8",
            )
            config_file = root / "feedback.yml"
            config_file.write_text(
                """
version: 1
product: {name: Example}
sources:
  - id: local
    type: json
    options: {paths: [input.json]}
    policy: {policy_version: local-v1, policy_version_checked_at: 2026-09-25}
""",
                encoding="utf-8",
            )
            config = load_config(config_file)
            connector = JsonFileConnector(ConnectorContext(config, config.sources[0], "salt"))
            self.assertEqual(connector.collect().records[0].native_id, "1")


if __name__ == "__main__":
    unittest.main()
