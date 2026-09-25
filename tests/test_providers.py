from __future__ import annotations

import os
import sqlite3
import stat
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from feedback_aggregator.config import SemanticProviderConfig
from feedback_aggregator.errors import ConfigurationError, ProviderError
from feedback_aggregator.models import RawRecord
from feedback_aggregator.providers import (
    LocalSubprocessProvider,
    SemanticRequest,
    validate_semantic_output,
)
from feedback_aggregator.storage import DATABASE_SCHEMA_VERSION, Storage


def _config(
    command: tuple[str, ...],
    *,
    provider_id: str = "local-semantic",
    model: str = "fixture-model-v1",
    schema_version: int = 1,
    retries: int = 0,
) -> SemanticProviderConfig:
    return SemanticProviderConfig(
        id=provider_id,
        type="local_subprocess",
        enabled=True,
        command=command,
        model=model,
        output_schema_version=schema_version,
        timeout_seconds=2,
        max_output_bytes=64 * 1024,
        max_retries=retries,
    )


def _request(
    *,
    input_text: str = "The export crashes every time.",
    prompt: str = "Summarize the product feedback.",
    schema_version: int = 1,
) -> SemanticRequest:
    return SemanticRequest(
        task="extract_signals",
        input_text=input_text,
        prompt=prompt,
        output_schema_version=schema_version,
    )


def test_local_provider_validates_and_persistently_caches_output() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        counter = root / "invocations.txt"
        database = root / "feedback.db"
        script = "\n".join(
            (
                "import json,sys",
                "from pathlib import Path",
                "counter = Path(sys.argv[1])",
                "count = int(counter.read_text()) if counter.exists() else 0",
                "counter.write_text(str(count + 1))",
                "request = json.load(sys.stdin)",
                "assert request['contract_version'] == 1",
                "assert request['output_schema_version'] == 1",
                "result = {'schema_version': 1, 'result': {",
                "    'summary': request['input'],",
                "    'labels': [{'name': 'reliability', 'confidence': 0.9}],",
                "}}",
                "print(json.dumps(result))",
            )
        )
        command = (sys.executable, "-c", script, str(counter))

        with Storage(database) as store:
            provider = LocalSubprocessProvider(_config(command), root=root, storage=store)
            first = provider.infer(_request())
            second = provider.infer(_request())
            assert first.cached is False
            assert first.attempts == 1
            assert second.cached is True
            assert second.attempts == 0
            assert second.output == first.output
            assert store.count("provider_cache") == 1
            assert counter.read_text(encoding="utf-8") == "1"

        with Storage(database) as reopened:
            provider = LocalSubprocessProvider(_config(command), root=root, storage=reopened)
            third = provider.infer(_request())
            assert third.cached is True
            assert counter.read_text(encoding="utf-8") == "1"


def test_cache_key_covers_input_provider_model_prompt_and_schema() -> None:
    with Storage(":memory:") as store:
        base = LocalSubprocessProvider(
            _config((sys.executable, "-c", "pass")), root=Path.cwd(), storage=store
        )
        baseline = base.cache_key(_request())
        assert base.cache_key(_request(input_text="different")) != baseline
        assert base.cache_key(_request(prompt="Different prompt")) != baseline

        other_provider = LocalSubprocessProvider(
            _config((sys.executable, "-c", "pass"), provider_id="other-provider"),
            root=Path.cwd(),
            storage=store,
        )
        assert other_provider.cache_key(_request()) != baseline

        other_model = LocalSubprocessProvider(
            _config((sys.executable, "-c", "pass"), model="other-model"),
            root=Path.cwd(),
            storage=store,
        )
        assert other_model.cache_key(_request()) != baseline

        other_schema = LocalSubprocessProvider(
            _config((sys.executable, "-c", "pass"), schema_version=2),
            root=Path.cwd(),
            storage=store,
        )
        assert other_schema.cache_key(_request(schema_version=2)) != baseline


def test_provider_retries_only_when_explicitly_configured() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        counter = root / "attempts.txt"
        script = "\n".join(
            (
                "import json,sys",
                "from pathlib import Path",
                "counter = Path(sys.argv[1])",
                "count = int(counter.read_text()) if counter.exists() else 0",
                "counter.write_text(str(count + 1))",
                "if count == 0: print('{}')",
                "else: print(json.dumps({'schema_version': 1, 'result': {",
                "    'summary': 'bounded retry succeeded',",
                "}}))",
            )
        )
        with Storage(root / "feedback.db") as store:
            provider = LocalSubprocessProvider(
                _config((sys.executable, "-c", script, str(counter)), retries=1),
                root=root,
                storage=store,
            )
            response = provider.infer(_request())
            assert response.attempts == 2
            assert counter.read_text(encoding="utf-8") == "2"


def test_default_zero_retry_does_not_repeat_failure() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        counter = root / "attempts.txt"
        script = "\n".join(
            (
                "import sys",
                "from pathlib import Path",
                "counter = Path(sys.argv[1])",
                "count = int(counter.read_text()) if counter.exists() else 0",
                "counter.write_text(str(count + 1))",
                "raise SystemExit(9)",
            )
        )
        with Storage(root / "feedback.db") as store:
            provider = LocalSubprocessProvider(
                _config((sys.executable, "-c", script, str(counter))),
                root=root,
                storage=store,
            )
            with pytest.raises(ProviderError, match="process failed"):
                provider.infer(_request())
            assert counter.read_text(encoding="utf-8") == "1"
            assert store.count("provider_cache") == 0


@pytest.mark.parametrize(
    "output",
    [
        {"schema_version": 2, "result": {"summary": "wrong schema"}},
        {"schema_version": 1, "result": {"unknown": "field"}},
        {
            "schema_version": 1,
            "result": {"labels": [{"name": "bug", "confidence": 2}]},
        },
        {"schema_version": 1, "result": {"embedding": [float("nan")]}},
        {"schema_version": 1, "result": {}},
    ],
)
def test_structured_output_validation_fails_closed(output: dict[str, object]) -> None:
    with pytest.raises(ProviderError):
        validate_semantic_output(output)


def test_malformed_output_is_not_cached() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        with Storage(root / "feedback.db") as store:
            provider = LocalSubprocessProvider(
                _config((sys.executable, "-c", "print('not json')")),
                root=root,
                storage=store,
            )
            with pytest.raises(ProviderError, match="valid JSON"):
                provider.infer(_request())
            assert store.count("provider_cache") == 0


def test_version_two_database_migrates_provider_cache() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "feedback.db"
        with Storage(database):
            pass
        connection = sqlite3.connect(database)
        connection.execute("DROP TABLE analysis_state")
        connection.execute("DROP TABLE provider_cache")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
        connection.close()

        with Storage(database) as store:
            assert store.schema_version == DATABASE_SCHEMA_VERSION
            assert store.count("provider_cache") == 0


def test_malformed_versioned_database_is_rejected_without_promotion() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "feedback.db"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE important (value TEXT)")
        connection.execute("PRAGMA user_version = 2")
        connection.commit()
        connection.close()

        with pytest.raises(ConfigurationError, match="does not match"):
            Storage(database)

        connection = sqlite3.connect(database)
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table'"
        ).fetchall() == [("important",)]
        connection.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_unversioned_database_is_rejected_without_changing_its_mode() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "unrelated.db"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE important (value TEXT)")
        connection.commit()
        connection.close()
        database.chmod(0o644)

        with pytest.raises(ConfigurationError, match="unversioned non-empty"):
            Storage(database)

        assert stat.S_IMODE(database.stat().st_mode) == 0o644
        connection = sqlite3.connect(database)
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'").fetchall() == [
            ("important",)
        ]
        connection.close()


def test_provider_cache_is_cleared_during_source_purge() -> None:
    with Storage(":memory:") as store:
        inserted = store.save_provider_cache(
            cache_key="provider_cache_key",
            provider_id="local-semantic",
            provider_type="local_subprocess",
            model="fixture-model-v1",
            input_hash="provider_input_hash",
            prompt_hash="provider_prompt_hash",
            schema_version=1,
            output={"schema_version": 1, "result": {"summary": "derived text"}},
        )
        assert inserted is True
        assert store.count("provider_cache") == 1
        store.purge_source("missing-source")
        assert store.count("provider_cache") == 0


def test_provider_cache_is_cleared_when_source_text_is_edited() -> None:
    record = RawRecord(
        source_id="fixture",
        source_type="json",
        native_id="one",
        canonical_url="",
        text="Original text",
        created_at="2026-09-25T12:00:00Z",
        retrieved_at="2026-09-25T12:00:00Z",
    )
    with Storage(":memory:") as store:
        store.upsert_raw_record(record)
        store.save_provider_cache(
            cache_key="provider_cache_key",
            provider_id="local-semantic",
            provider_type="local_subprocess",
            model="fixture-model-v1",
            input_hash="provider_input_hash",
            prompt_hash="provider_prompt_hash",
            schema_version=1,
            output={"schema_version": 1, "result": {"summary": "derived text"}},
        )
        store.upsert_raw_record(replace(record, text="Original\ntext"))
        assert store.count("provider_cache") == 0
