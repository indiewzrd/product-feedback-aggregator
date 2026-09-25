"""Private, versioned SQLite storage for feedback runs and analysis.

All values are passed to SQLite as parameters.  The database is created with
owner-only permissions, foreign keys and secure deletion enabled, and a small
schema version stored in ``PRAGMA user_version``.  The class is intentionally
boring: callers can understand every persistence operation without an ORM.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

from .analysis import AnalysisResult
from .errors import ConfigurationError, NotFoundError, SecurityError
from .models import SCHEMA_VERSION, RawRecord, utc_now
from .util import canonical_json, safe_provenance_url, sanitize_text, stable_hash

DATABASE_SCHEMA_VERSION = 4
_MAX_IDENTIFIER_CHARS = 512
_MAX_URL_CHARS = 8_192
_MAX_QUERY_CHARS = 32_000
_MAX_JSON_BYTES = 2_000_000
_SECRET_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "bearer_token",
    "client_secret",
    "cookie",
    "password",
    "refresh_token",
    "secret",
    "token",
}

_SCHEMA_COLUMNS_V4: dict[str, tuple[str, ...]] = {
    "raw_records": (
        "record_id",
        "source_id",
        "source_type",
        "native_id",
        "canonical_url",
        "text",
        "created_at",
        "retrieved_at",
        "author_key",
        "engagement_json",
        "metadata_json",
        "query_text",
        "acquisition_mode",
        "policy_assurance",
        "expires_at",
        "record_schema_version",
        "content_hash",
        "analysis_hash",
    ),
    "cursors": ("source_id", "cursor_value", "metadata_json", "updated_at"),
    "runs": ("run_id", "status", "started_at", "finished_at", "manifest_json"),
    "assessments": (
        "record_id",
        "relevance",
        "noise",
        "spam",
        "automation",
        "confidence",
        "relevance_reasons_json",
        "noise_reasons_json",
        "spam_reasons_json",
        "automation_reasons_json",
        "disposition",
        "version",
    ),
    "signals": (
        "signal_id",
        "record_id",
        "signal_type",
        "normalized_statement",
        "evidence_start",
        "evidence_end",
        "exact_hash",
        "relevance",
        "confidence",
        "extraction_version",
    ),
    "duplicate_groups": (
        "group_id",
        "exact_hash",
        "representative_signal_id",
        "method_version",
    ),
    "duplicate_group_signals": ("group_id", "signal_id"),
    "clusters": (
        "cluster_id",
        "label",
        "summary",
        "representative_signal_id",
        "distinct_authors",
        "source_distribution_json",
        "time_start",
        "time_end",
        "clustering_version",
    ),
    "cluster_signals": ("cluster_id", "signal_id", "evidence_rank", "evidence_score"),
    "scores": (
        "cluster_id",
        "total",
        "rank",
        "components_json",
        "weights_json",
        "penalties_json",
        "formula_version",
        "configuration_hash",
    ),
    "analysis_state": (
        "state_id",
        "configuration_hash",
        "reference_time",
        "record_count",
        "signal_count",
        "cluster_count",
        "analyzed_at",
    ),
    "audit_events": ("event_id", "event_type", "occurred_at", "details_json"),
    "review_overrides": (
        "record_id",
        "action",
        "rationale",
        "created_at",
        "applicability_version",
    ),
    "provider_cache": (
        "cache_key",
        "provider_id",
        "provider_type",
        "model",
        "input_hash",
        "prompt_hash",
        "schema_version",
        "output_json",
        "created_at",
    ),
}


def _schema_for_version(version: int) -> dict[str, tuple[str, ...]]:
    schema = dict(_SCHEMA_COLUMNS_V4)
    if version <= 3:
        schema.pop("analysis_state")
    if version <= 2:
        schema.pop("provider_cache")
    if version <= 1:
        schema.pop("duplicate_groups")
        schema.pop("duplicate_group_signals")
        schema.pop("review_overrides")
        schema["cluster_signals"] = ("cluster_id", "signal_id")
    return schema


def _bounded_text(value: object, limit: int, field_name: str) -> str:
    text = sanitize_text(value, max_chars=limit + 1)
    if len(text) > limit:
        raise ValueError(f"{field_name} exceeds its storage limit")
    return text


def _json_text(value: Any, field_name: str) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field_name} must contain JSON-compatible values") from error
    if len(encoded.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError(f"{field_name} exceeds its storage limit")
    return encoded


def _read_json(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _redact_secrets(value: Any) -> Any:
    """Remove obvious credential values before a manifest reaches disk."""

    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            lowered = name.lower()
            if lowered in _SECRET_KEYS or lowered.endswith(("_password", "_secret", "_token")):
                redacted[name] = "[REDACTED]"
            else:
                redacted[name] = _redact_secrets(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact_secrets(item) for item in value]
    return value


def _record_analysis_hash(
    *,
    stored_text: str,
    created_at: str,
    author_key: str,
    engagement_json: str,
    metadata: Mapping[str, Any],
) -> str:
    analysis_metadata = {
        key: metadata[key]
        for key in (
            "is_bot",
            "automated",
            "automation_probability",
            "account_label",
            "username",
            "lang",
            "language",
        )
        if key in metadata
    }
    return stable_hash(
        # Signals carry offsets into the exact stored text. Even a visually
        # equivalent Unicode or whitespace edit can shift those offsets.
        stored_text,
        created_at,
        author_key,
        engagement_json,
        canonical_json(analysis_metadata),
        prefix="record_",
    )


def _timestamp(value: object, field_name: str) -> str:
    text = _bounded_text(value, 64, field_name)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _placeholders(count: int) -> str:
    if count < 1:
        raise ValueError("at least one SQL value is required")
    return ",".join("?" for _ in range(count))


def _parameter_batches(
    values: Sequence[str], connection: sqlite3.Connection
) -> Iterator[tuple[str, ...]]:
    """Yield batches below both old and runtime-lowered SQLite limits."""

    try:
        runtime_limit = connection.getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER)
    except (AttributeError, sqlite3.Error):  # pragma: no cover - Python/SQLite fallback
        runtime_limit = 999
    batch_size = max(1, min(500, runtime_limit))
    for start in range(0, len(values), batch_size):
        yield tuple(values[start : start + batch_size])


class Storage:
    """A small SQLite repository with explicit lifecycle operations.

    ``Storage`` opens and migrates the database immediately.  Use it as a
    context manager so the connection is always closed::

        with Storage(".feedback/data.sqlite3") as store:
            store.upsert_raw_records(records)
            result = analyze_records(store.list_raw_records())
            store.save_analysis(result)
    """

    def __init__(self, path: str | Path):
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        self._memory = str(path) == ":memory:"
        if not self._memory:
            self.path = self.path.expanduser().absolute()
            self._prepare_database_file()
        try:
            self._connection = sqlite3.connect(
                ":memory:" if self._memory else str(self.path),
                timeout=10.0,
            )
        except sqlite3.Error as error:
            raise ConfigurationError("could not open the local database") from error
        self._connection.row_factory = sqlite3.Row
        try:
            self._validate_database_identity()
            self._configure()
            self._migrate()
        except Exception:
            self._connection.close()
            raise
        self._enforce_file_mode()

    def _validate_database_identity(self) -> None:
        """Refuse to adopt unrelated or malformed SQLite files."""

        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if version > DATABASE_SCHEMA_VERSION:
            raise ConfigurationError("the database was created by a newer application version")
        objects = self._connection.execute(
            "SELECT type, name FROM sqlite_schema "
            "WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'view', 'trigger') "
            "ORDER BY type, name"
        ).fetchall()
        if version == 0:
            if objects:
                raise ConfigurationError(
                    "refusing to initialize an unversioned non-empty SQLite database"
                )
            return
        expected = _schema_for_version(version)
        actual_tables = {
            str(row["name"]) for row in objects if str(row["type"]) == "table"
        }
        non_table_objects = [row for row in objects if str(row["type"]) != "table"]
        if actual_tables != set(expected) or non_table_objects:
            raise ConfigurationError("database schema does not match its declared version")
        for table_name, expected_columns in expected.items():
            rows = self._connection.execute(
                f'PRAGMA table_info("{table_name}")'  # noqa: S608 - constant table names
            ).fetchall()
            actual_columns = tuple(str(row["name"]) for row in rows)
            if actual_columns != expected_columns:
                raise ConfigurationError("database schema does not match its declared version")

    def _prepare_database_file(self) -> None:
        parent_was_missing = not self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if parent_was_missing:
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
        if self.path.exists() or self.path.is_symlink():
            details = os.lstat(self.path)
            if stat.S_ISLNK(details.st_mode):
                raise SecurityError("database path must not be a symbolic link")
            if not stat.S_ISREG(details.st_mode):
                raise SecurityError("database path must be a regular file")
            return
        descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(descriptor)

    def _enforce_file_mode(self) -> None:
        if self._memory:
            return
        try:
            os.chmod(self.path, 0o600)
        except OSError as error:
            raise SecurityError("could not set private database permissions") from error

    def _configure(self) -> None:
        settings = (
            "PRAGMA foreign_keys = ON",
            "PRAGMA secure_delete = ON",
            "PRAGMA trusted_schema = OFF",
            "PRAGMA recursive_triggers = ON",
            "PRAGMA temp_store = MEMORY",
            "PRAGMA journal_mode = DELETE",
            "PRAGMA synchronous = FULL",
            "PRAGMA busy_timeout = 10000",
        )
        for statement in settings:
            self._connection.execute(statement)
        if self._connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise ConfigurationError("SQLite foreign key enforcement is unavailable")
        if self._connection.execute("PRAGMA secure_delete").fetchone()[0] != 1:
            raise ConfigurationError("SQLite secure deletion is unavailable")

    def _migrate(self) -> None:
        version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
        if version > DATABASE_SCHEMA_VERSION:
            raise ConfigurationError("the database was created by a newer application version")
        if version == 0:
            self._connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE raw_records (
                    record_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    native_id TEXT NOT NULL,
                    canonical_url TEXT NOT NULL,
                    text TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    retrieved_at TEXT NOT NULL,
                    author_key TEXT NOT NULL,
                    engagement_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    query_text TEXT NOT NULL,
                    acquisition_mode TEXT NOT NULL,
                    policy_assurance TEXT NOT NULL,
                    expires_at TEXT,
                    record_schema_version INTEGER NOT NULL,
                    content_hash TEXT NOT NULL,
                    analysis_hash TEXT NOT NULL,
                    UNIQUE (source_type, source_id, native_id)
                );
                CREATE INDEX raw_records_source_index
                    ON raw_records (source_id, source_type);
                CREATE INDEX raw_records_expiry_index
                    ON raw_records (expires_at) WHERE expires_at IS NOT NULL;

                CREATE TABLE cursors (
                    source_id TEXT PRIMARY KEY,
                    cursor_value TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE runs (
                    run_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    manifest_json TEXT NOT NULL
                );

                CREATE TABLE assessments (
                    record_id TEXT PRIMARY KEY
                        REFERENCES raw_records(record_id) ON DELETE CASCADE,
                    relevance REAL NOT NULL CHECK (relevance BETWEEN 0 AND 1),
                    noise REAL NOT NULL CHECK (noise BETWEEN 0 AND 1),
                    spam REAL NOT NULL CHECK (spam BETWEEN 0 AND 1),
                    automation REAL NOT NULL CHECK (automation BETWEEN 0 AND 1),
                    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
                    relevance_reasons_json TEXT NOT NULL,
                    noise_reasons_json TEXT NOT NULL,
                    spam_reasons_json TEXT NOT NULL,
                    automation_reasons_json TEXT NOT NULL,
                    disposition TEXT NOT NULL,
                    version TEXT NOT NULL
                );

                CREATE TABLE signals (
                    signal_id TEXT PRIMARY KEY,
                    record_id TEXT NOT NULL
                        REFERENCES raw_records(record_id) ON DELETE CASCADE,
                    signal_type TEXT NOT NULL,
                    normalized_statement TEXT NOT NULL,
                    evidence_start INTEGER NOT NULL CHECK (evidence_start >= 0),
                    evidence_end INTEGER NOT NULL CHECK (evidence_end >= evidence_start),
                    exact_hash TEXT NOT NULL,
                    relevance REAL NOT NULL CHECK (relevance BETWEEN 0 AND 1),
                    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
                    extraction_version TEXT NOT NULL
                );
                CREATE INDEX signals_record_index ON signals (record_id);
                CREATE INDEX signals_exact_hash_index ON signals (exact_hash);

                CREATE TABLE duplicate_groups (
                    group_id TEXT PRIMARY KEY,
                    exact_hash TEXT NOT NULL,
                    representative_signal_id TEXT NOT NULL
                        REFERENCES signals(signal_id) ON DELETE CASCADE,
                    method_version TEXT NOT NULL
                );

                CREATE TABLE duplicate_group_signals (
                    group_id TEXT NOT NULL
                        REFERENCES duplicate_groups(group_id) ON DELETE CASCADE,
                    signal_id TEXT NOT NULL
                        REFERENCES signals(signal_id) ON DELETE CASCADE,
                    PRIMARY KEY (group_id, signal_id)
                );
                CREATE INDEX duplicate_group_signals_signal_index
                    ON duplicate_group_signals (signal_id);

                CREATE TABLE clusters (
                    cluster_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    representative_signal_id TEXT NOT NULL,
                    distinct_authors INTEGER NOT NULL CHECK (distinct_authors >= 0),
                    source_distribution_json TEXT NOT NULL,
                    time_start TEXT NOT NULL,
                    time_end TEXT NOT NULL,
                    clustering_version TEXT NOT NULL
                );

                CREATE TABLE cluster_signals (
                    cluster_id TEXT NOT NULL
                        REFERENCES clusters(cluster_id) ON DELETE CASCADE,
                    signal_id TEXT NOT NULL
                        REFERENCES signals(signal_id) ON DELETE CASCADE,
                    evidence_rank INTEGER NOT NULL CHECK (evidence_rank >= 1),
                    evidence_score REAL NOT NULL CHECK (evidence_score BETWEEN 0 AND 1),
                    PRIMARY KEY (cluster_id, signal_id)
                );
                CREATE INDEX cluster_signals_signal_index
                    ON cluster_signals (signal_id);

                CREATE TABLE scores (
                    cluster_id TEXT PRIMARY KEY
                        REFERENCES clusters(cluster_id) ON DELETE CASCADE,
                    total REAL NOT NULL CHECK (total BETWEEN 0 AND 100),
                    rank INTEGER NOT NULL CHECK (rank >= 1),
                    components_json TEXT NOT NULL,
                    weights_json TEXT NOT NULL,
                    penalties_json TEXT NOT NULL,
                    formula_version TEXT NOT NULL,
                    configuration_hash TEXT NOT NULL
                );

                CREATE TABLE analysis_state (
                    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                    configuration_hash TEXT NOT NULL,
                    reference_time TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK (record_count >= 0),
                    signal_count INTEGER NOT NULL CHECK (signal_count >= 0),
                    cluster_count INTEGER NOT NULL CHECK (cluster_count >= 0),
                    analyzed_at TEXT NOT NULL
                );

                CREATE TABLE audit_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE TABLE review_overrides (
                    record_id TEXT PRIMARY KEY
                        REFERENCES raw_records(record_id) ON DELETE CASCADE,
                    action TEXT NOT NULL CHECK (action IN ('include', 'exclude')),
                    rationale TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    applicability_version TEXT NOT NULL
                );

                CREATE TABLE provider_cache (
                    cache_key TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    provider_type TEXT NOT NULL,
                    model TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    prompt_hash TEXT NOT NULL,
                    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
                    output_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX provider_cache_provider_index
                    ON provider_cache (provider_id, model, schema_version);

                PRAGMA user_version = 4;
                COMMIT;
                """
            )
        elif version == 1:
            self._connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE duplicate_groups (
                    group_id TEXT PRIMARY KEY,
                    exact_hash TEXT NOT NULL,
                    representative_signal_id TEXT NOT NULL
                        REFERENCES signals(signal_id) ON DELETE CASCADE,
                    method_version TEXT NOT NULL
                );
                CREATE TABLE duplicate_group_signals (
                    group_id TEXT NOT NULL
                        REFERENCES duplicate_groups(group_id) ON DELETE CASCADE,
                    signal_id TEXT NOT NULL
                        REFERENCES signals(signal_id) ON DELETE CASCADE,
                    PRIMARY KEY (group_id, signal_id)
                );
                CREATE INDEX duplicate_group_signals_signal_index
                    ON duplicate_group_signals (signal_id);
                ALTER TABLE cluster_signals ADD COLUMN evidence_rank INTEGER NOT NULL DEFAULT 1;
                ALTER TABLE cluster_signals ADD COLUMN evidence_score REAL NOT NULL DEFAULT 0;
                CREATE TABLE review_overrides (
                    record_id TEXT PRIMARY KEY
                        REFERENCES raw_records(record_id) ON DELETE CASCADE,
                    action TEXT NOT NULL CHECK (action IN ('include', 'exclude')),
                    rationale TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    applicability_version TEXT NOT NULL
                );

                CREATE TABLE provider_cache (
                    cache_key TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    provider_type TEXT NOT NULL,
                    model TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    prompt_hash TEXT NOT NULL,
                    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
                    output_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX provider_cache_provider_index
                    ON provider_cache (provider_id, model, schema_version);

                CREATE TABLE analysis_state (
                    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                    configuration_hash TEXT NOT NULL,
                    reference_time TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK (record_count >= 0),
                    signal_count INTEGER NOT NULL CHECK (signal_count >= 0),
                    cluster_count INTEGER NOT NULL CHECK (cluster_count >= 0),
                    analyzed_at TEXT NOT NULL
                );

                PRAGMA user_version = 4;
                COMMIT;
                """
            )
        elif version == 2:
            self._connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE provider_cache (
                    cache_key TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    provider_type TEXT NOT NULL,
                    model TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    prompt_hash TEXT NOT NULL,
                    schema_version INTEGER NOT NULL CHECK (schema_version >= 1),
                    output_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX provider_cache_provider_index
                    ON provider_cache (provider_id, model, schema_version);
                CREATE TABLE analysis_state (
                    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                    configuration_hash TEXT NOT NULL,
                    reference_time TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK (record_count >= 0),
                    signal_count INTEGER NOT NULL CHECK (signal_count >= 0),
                    cluster_count INTEGER NOT NULL CHECK (cluster_count >= 0),
                    analyzed_at TEXT NOT NULL
                );
                PRAGMA user_version = 4;
                COMMIT;
                """
            )
        elif version == 3:
            self._connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE analysis_state (
                    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                    configuration_hash TEXT NOT NULL,
                    reference_time TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK (record_count >= 0),
                    signal_count INTEGER NOT NULL CHECK (signal_count >= 0),
                    cluster_count INTEGER NOT NULL CHECK (cluster_count >= 0),
                    analyzed_at TEXT NOT NULL
                );
                PRAGMA user_version = 4;
                COMMIT;
                """
            )

    @property
    def schema_version(self) -> int:
        return int(self._connection.execute("PRAGMA user_version").fetchone()[0])

    @property
    def connection(self) -> sqlite3.Connection:
        """Expose the connection for read-only diagnostics and tests."""

        return self._connection

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a group of operations atomically, with rollback on failure."""

        if self._connection.in_transaction:
            savepoint = f"nested_{secrets.token_hex(6)}"
            self._connection.execute(f"SAVEPOINT {savepoint}")
            try:
                yield self._connection
            except Exception:
                self._connection.execute(f"ROLLBACK TO {savepoint}")
                self._connection.execute(f"RELEASE {savepoint}")
                raise
            else:
                self._connection.execute(f"RELEASE {savepoint}")
            return
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
        except Exception:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()
            self._enforce_file_mode()

    def upsert_raw_record(self, record: RawRecord) -> str:
        """Insert or refresh one record without duplicating its native identity.

        If analysis-relevant content changes, every affected cluster and score is
        invalidated before the old assessment/signals are removed.
        """

        return self.upsert_raw_records((record,))[0]

    def upsert_raw_records(self, records: Iterable[RawRecord]) -> tuple[str, ...]:
        prepared: list[tuple[RawRecord, tuple[Any, ...]]] = []
        for record in records:
            source_id = _bounded_text(record.source_id, _MAX_IDENTIFIER_CHARS, "source_id")
            source_type = _bounded_text(record.source_type, _MAX_IDENTIFIER_CHARS, "source_type")
            native_id = _bounded_text(record.native_id, _MAX_IDENTIFIER_CHARS, "native_id")
            if not source_id or not source_type or not native_id:
                raise ValueError("source_id, source_type, and native_id are required")
            stored_text = sanitize_text(record.text)
            engagement_json = _json_text(record.engagement, "engagement")
            metadata_json = _json_text(record.metadata, "metadata")
            created_at = _timestamp(record.created_at, "created_at")
            retrieved_at = _timestamp(record.retrieved_at, "retrieved_at")
            author_key = _bounded_text(record.author_key, _MAX_IDENTIFIER_CHARS, "author_key")
            expires_at = _timestamp(record.expires_at, "expires_at") if record.expires_at else None
            if int(record.schema_version) != SCHEMA_VERSION:
                raise ValueError("unsupported raw record schema version")
            record_id = stable_hash(source_type, source_id, native_id, prefix="item_")[:45]
            # Preserve exact sanitized-content identity separately for provider
            # cache invalidation. The analysis hash also includes exact text,
            # because signals persist character offsets into this value.
            content_hash = stable_hash(stored_text, prefix="content_")
            analysis_hash = _record_analysis_hash(
                stored_text=stored_text,
                created_at=created_at,
                author_key=author_key,
                engagement_json=engagement_json,
                metadata=record.metadata,
            )
            values = (
                record_id,
                source_id,
                source_type,
                native_id,
                _bounded_text(record.canonical_url, _MAX_URL_CHARS, "canonical_url"),
                stored_text,
                created_at,
                retrieved_at,
                author_key,
                engagement_json,
                metadata_json,
                _bounded_text(record.query, _MAX_QUERY_CHARS, "query"),
                _bounded_text(record.acquisition_mode, 128, "acquisition_mode"),
                _bounded_text(record.policy_assurance, 128, "policy_assurance"),
                expires_at,
                int(record.schema_version),
                content_hash,
                analysis_hash,
            )
            prepared.append((record, values))

        ids: list[str] = []
        with self.transaction() as connection:
            for _record, values in prepared:
                record_id, source_id, _source_type, native_id = values[:4]
                existing = connection.execute(
                    "SELECT record_id, content_hash, analysis_hash FROM raw_records "
                    "WHERE source_type = ? AND source_id = ? AND native_id = ?",
                    (_source_type, source_id, native_id),
                ).fetchone()
                if existing is None:
                    connection.execute("DELETE FROM analysis_state")
                if existing is not None and existing["content_hash"] != values[-2]:
                    # Cached provider output can contain derived text and must
                    # not outlive any source-text edit.
                    connection.execute("DELETE FROM provider_cache")
                if existing is not None and existing["analysis_hash"] != values[-1]:
                    self._invalidate_clusters_for_records((existing["record_id"],), connection)
                    connection.execute(
                        "DELETE FROM assessments WHERE record_id = ?", (existing["record_id"],)
                    )
                    connection.execute(
                        "DELETE FROM signals WHERE record_id = ?", (existing["record_id"],)
                    )
                connection.execute(
                    """
                    INSERT INTO raw_records (
                        record_id, source_id, source_type, native_id, canonical_url, text,
                        created_at, retrieved_at, author_key, engagement_json, metadata_json,
                        query_text, acquisition_mode, policy_assurance, expires_at,
                        record_schema_version, content_hash, analysis_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(source_type, source_id, native_id) DO UPDATE SET
                        canonical_url = excluded.canonical_url,
                        text = excluded.text,
                        created_at = excluded.created_at,
                        retrieved_at = excluded.retrieved_at,
                        author_key = excluded.author_key,
                        engagement_json = excluded.engagement_json,
                        metadata_json = excluded.metadata_json,
                        query_text = excluded.query_text,
                        acquisition_mode = excluded.acquisition_mode,
                        policy_assurance = excluded.policy_assurance,
                        expires_at = excluded.expires_at,
                        record_schema_version = excluded.record_schema_version,
                        content_hash = excluded.content_hash,
                        analysis_hash = excluded.analysis_hash
                    """,
                    values,
                )
                ids.append(str(record_id))
        return tuple(ids)

    def _row_to_raw_record(self, row: sqlite3.Row) -> RawRecord:
        engagement_value = _read_json(row["engagement_json"], {})
        metadata_value = _read_json(row["metadata_json"], {})
        engagement = engagement_value if isinstance(engagement_value, dict) else {}
        metadata = metadata_value if isinstance(metadata_value, dict) else {}
        return RawRecord(
            source_id=row["source_id"],
            source_type=row["source_type"],
            native_id=row["native_id"],
            canonical_url=row["canonical_url"],
            text=row["text"],
            created_at=row["created_at"],
            retrieved_at=row["retrieved_at"],
            author_key=row["author_key"],
            engagement=engagement,
            metadata=metadata,
            query=row["query_text"],
            acquisition_mode=row["acquisition_mode"],
            policy_assurance=row["policy_assurance"],
            expires_at=row["expires_at"],
            schema_version=int(row["record_schema_version"]),
        )

    def list_raw_records(
        self,
        *,
        source_id: str | None = None,
        include_expired: bool = False,
        as_of: str | None = None,
    ) -> tuple[RawRecord, ...]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if source_id is not None:
            clauses.append("source_id = ?")
            parameters.append(source_id)
        if not include_expired:
            clauses.append("(expires_at IS NULL OR datetime(expires_at) > datetime(?))")
            parameters.append(as_of or utc_now())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        # ``where`` is assembled only from the two fixed clauses above; all
        # values remain bound parameters.
        rows = self._connection.execute(
            "SELECT * FROM raw_records"  # noqa: S608
            + where
            + " ORDER BY source_type, source_id, native_id",
            tuple(parameters),
        ).fetchall()
        return tuple(self._row_to_raw_record(row) for row in rows)

    def get_raw_record(self, record_id: str) -> RawRecord:
        row = self._connection.execute(
            "SELECT * FROM raw_records WHERE record_id = ?", (record_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("feedback record was not found")
        return self._row_to_raw_record(row)

    def count(self, table: str) -> int:
        """Return a count for a known table (useful for diagnostics/tests)."""

        allowed = {
            "raw_records",
            "cursors",
            "runs",
            "assessments",
            "signals",
            "clusters",
            "cluster_signals",
            "duplicate_groups",
            "duplicate_group_signals",
            "scores",
            "review_overrides",
            "audit_events",
            "provider_cache",
            "analysis_state",
        }
        if table not in allowed:
            raise ValueError("unknown storage table")
        # ``table`` passed the exact allowlist above.
        statement = f"SELECT COUNT(*) FROM {table}"  # noqa: S608
        return int(self._connection.execute(statement).fetchone()[0])

    def save_cursor(
        self,
        source_id: str,
        cursor: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO cursors (source_id, cursor_value, metadata_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE SET
                    cursor_value = excluded.cursor_value,
                    metadata_json = excluded.metadata_json,
                    updated_at = excluded.updated_at
                """,
                (
                    _bounded_text(source_id, _MAX_IDENTIFIER_CHARS, "source_id"),
                    _bounded_text(cursor, _MAX_QUERY_CHARS, "cursor"),
                    _json_text(dict(metadata or {}), "cursor metadata"),
                    utc_now(),
                ),
            )

    def get_cursor(self, source_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT cursor_value, metadata_json, updated_at FROM cursors WHERE source_id = ?",
            (source_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "cursor": row["cursor_value"],
            "metadata": _read_json(row["metadata_json"], {}),
            "updated_at": row["updated_at"],
        }

    def get_provider_cache(self, cache_key: str) -> dict[str, Any] | None:
        """Return one structured provider result without exposing its input.

        Inputs and prompts are represented only by hashes in SQLite. A corrupt
        cache fails closed instead of being passed to the analysis pipeline.
        """

        row = self._connection.execute(
            "SELECT * FROM provider_cache WHERE cache_key = ?",
            (_bounded_text(cache_key, _MAX_IDENTIFIER_CHARS, "cache_key"),),
        ).fetchone()
        if row is None:
            return None
        try:
            output = json.loads(row["output_json"])
        except (TypeError, ValueError) as error:
            raise SecurityError("stored provider output is not valid JSON") from error
        if not isinstance(output, dict):
            raise SecurityError("stored provider output has an invalid shape")
        return {
            "cache_key": str(row["cache_key"]),
            "provider_id": str(row["provider_id"]),
            "provider_type": str(row["provider_type"]),
            "model": str(row["model"]),
            "input_hash": str(row["input_hash"]),
            "prompt_hash": str(row["prompt_hash"]),
            "schema_version": int(row["schema_version"]),
            "output": output,
            "created_at": str(row["created_at"]),
        }

    def save_provider_cache(
        self,
        *,
        cache_key: str,
        provider_id: str,
        provider_type: str,
        model: str,
        input_hash: str,
        prompt_hash: str,
        schema_version: int,
        output: Mapping[str, Any],
    ) -> bool:
        """Persist the first valid output for a semantic cache key atomically.

        Returns ``True`` for an insert and ``False`` when another process has
        already stored the same cache identity. Conflicting metadata is treated
        as cache corruption rather than overwritten.
        """

        if isinstance(schema_version, bool) or not isinstance(schema_version, int):
            raise ValueError("schema_version must be an integer")
        if schema_version < 1:
            raise ValueError("schema_version must be positive")
        values = (
            _bounded_text(cache_key, _MAX_IDENTIFIER_CHARS, "cache_key"),
            _bounded_text(provider_id, _MAX_IDENTIFIER_CHARS, "provider_id"),
            _bounded_text(provider_type, 128, "provider_type"),
            _bounded_text(model, 256, "model"),
            _bounded_text(input_hash, _MAX_IDENTIFIER_CHARS, "input_hash"),
            _bounded_text(prompt_hash, _MAX_IDENTIFIER_CHARS, "prompt_hash"),
            schema_version,
            _json_text(dict(output), "provider output"),
            utc_now(),
        )
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT provider_id, provider_type, model, input_hash, prompt_hash, "
                "schema_version FROM provider_cache WHERE cache_key = ?",
                (values[0],),
            ).fetchone()
            if existing is not None:
                expected = values[1:7]
                actual = tuple(existing)
                if actual != expected:
                    raise SecurityError("provider cache identity does not match its key")
                return False
            connection.execute(
                "INSERT INTO provider_cache "
                "(cache_key, provider_id, provider_type, model, input_hash, prompt_hash, "
                "schema_version, output_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )
        return True

    def clear_provider_cache(self) -> int:
        """Securely delete all optional semantic outputs."""

        with self.transaction() as connection:
            cursor = connection.execute("DELETE FROM provider_cache")
            return int(cursor.rowcount)

    def save_review_override(self, record_id: str, action: str, rationale: str = "") -> None:
        """Persist a human include/exclude decision and invalidate derived state."""

        if action not in {"include", "exclude"}:
            raise ValueError("review action must be include or exclude")
        with self.transaction() as connection:
            exists = connection.execute(
                "SELECT 1 FROM raw_records WHERE record_id = ?", (record_id,)
            ).fetchone()
            if exists is None:
                raise NotFoundError("feedback record was not found")
            self._invalidate_clusters_for_records((record_id,), connection)
            connection.execute("DELETE FROM assessments WHERE record_id = ?", (record_id,))
            connection.execute("DELETE FROM signals WHERE record_id = ?", (record_id,))
            connection.execute(
                "INSERT INTO review_overrides "
                "(record_id, action, rationale, created_at, applicability_version) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(record_id) DO UPDATE SET action = excluded.action, "
                "rationale = excluded.rationale, created_at = excluded.created_at, "
                "applicability_version = excluded.applicability_version",
                (
                    record_id,
                    action,
                    _bounded_text(rationale, 2_000, "rationale"),
                    utc_now(),
                    "record-disposition-v1",
                ),
            )
            self._write_audit(
                "review_override_saved",
                {
                    "record_reference_hash": stable_hash(record_id, prefix="record_")[:24],
                    "action": action,
                },
                connection,
            )

    def clear_review_override(self, record_id: str) -> bool:
        with self.transaction() as connection:
            exists = connection.execute(
                "SELECT 1 FROM review_overrides WHERE record_id = ?", (record_id,)
            ).fetchone()
            if exists is None:
                return False
            self._invalidate_clusters_for_records((record_id,), connection)
            connection.execute("DELETE FROM assessments WHERE record_id = ?", (record_id,))
            connection.execute("DELETE FROM signals WHERE record_id = ?", (record_id,))
            cursor = connection.execute(
                "DELETE FROM review_overrides WHERE record_id = ?", (record_id,)
            )
            return cursor.rowcount == 1

    def review_overrides(self) -> dict[str, str]:
        rows = self._connection.execute(
            "SELECT record_id, action FROM review_overrides ORDER BY record_id"
        ).fetchall()
        return {str(row["record_id"]): str(row["action"]) for row in rows}

    def start_run(
        self,
        manifest: Mapping[str, Any] | None = None,
        *,
        run_id: str | None = None,
    ) -> str:
        started_at = utc_now()
        identifier = run_id or stable_hash(started_at, secrets.token_hex(16), prefix="run_")[:44]
        safe_manifest = _redact_secrets(dict(manifest or {}))
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO runs (run_id, status, started_at, finished_at, manifest_json) "
                "VALUES (?, ?, ?, NULL, ?)",
                (
                    _bounded_text(identifier, _MAX_IDENTIFIER_CHARS, "run_id"),
                    "running",
                    started_at,
                    _json_text(safe_manifest, "run manifest"),
                ),
            )
        return identifier

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        manifest: Mapping[str, Any] | None = None,
    ) -> None:
        safe_manifest = _redact_secrets(dict(manifest or {}))
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE runs SET status = ?, finished_at = ?, manifest_json = ? WHERE run_id = ?",
                (
                    _bounded_text(status, 64, "status"),
                    utc_now(),
                    _json_text(safe_manifest, "run manifest"),
                    run_id,
                ),
            )
            if cursor.rowcount != 1:
                raise NotFoundError("run was not found")

    def get_run(self, run_id: str) -> dict[str, Any]:
        row = self._connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise NotFoundError("run was not found")
        return {
            "run_id": row["run_id"],
            "status": row["status"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "manifest": _read_json(row["manifest_json"], {}),
        }

    def save_analysis(self, result: AnalysisResult, *, replace: bool = True) -> None:
        """Persist one complete analysis snapshot in a single transaction."""

        with self.transaction() as connection:
            if replace:
                connection.execute("DELETE FROM assessments")
                connection.execute("DELETE FROM duplicate_groups")
                connection.execute("DELETE FROM signals")
                connection.execute("DELETE FROM clusters")

            for assessment in result.assessments:
                connection.execute(
                    """
                    INSERT INTO assessments (
                        record_id, relevance, noise, spam, automation, confidence,
                        relevance_reasons_json, noise_reasons_json, spam_reasons_json,
                        automation_reasons_json, disposition, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(record_id) DO UPDATE SET
                        relevance = excluded.relevance,
                        noise = excluded.noise,
                        spam = excluded.spam,
                        automation = excluded.automation,
                        confidence = excluded.confidence,
                        relevance_reasons_json = excluded.relevance_reasons_json,
                        noise_reasons_json = excluded.noise_reasons_json,
                        spam_reasons_json = excluded.spam_reasons_json,
                        automation_reasons_json = excluded.automation_reasons_json,
                        disposition = excluded.disposition,
                        version = excluded.version
                    """,
                    (
                        assessment.record_id,
                        assessment.relevance,
                        assessment.noise,
                        assessment.spam,
                        assessment.automation,
                        assessment.confidence,
                        _json_text(list(assessment.relevance_reasons), "relevance reasons"),
                        _json_text(list(assessment.noise_reasons), "noise reasons"),
                        _json_text(list(assessment.spam_reasons), "spam reasons"),
                        _json_text(list(assessment.automation_reasons), "automation reasons"),
                        assessment.disposition,
                        assessment.version,
                    ),
                )

            for signal in result.signals:
                connection.execute(
                    """
                    INSERT INTO signals (
                        signal_id, record_id, signal_type, normalized_statement,
                        evidence_start, evidence_end, exact_hash, relevance, confidence,
                        extraction_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(signal_id) DO UPDATE SET
                        record_id = excluded.record_id,
                        signal_type = excluded.signal_type,
                        normalized_statement = excluded.normalized_statement,
                        evidence_start = excluded.evidence_start,
                        evidence_end = excluded.evidence_end,
                        exact_hash = excluded.exact_hash,
                        relevance = excluded.relevance,
                        confidence = excluded.confidence,
                        extraction_version = excluded.extraction_version
                    """,
                    (
                        signal.signal_id,
                        signal.record_id,
                        signal.signal_type,
                        signal.normalized_statement,
                        signal.evidence_start,
                        signal.evidence_end,
                        signal.exact_hash,
                        signal.relevance,
                        signal.confidence,
                        signal.extraction_version,
                    ),
                )

            for group in result.duplicate_groups:
                connection.execute(
                    "INSERT INTO duplicate_groups "
                    "(group_id, exact_hash, representative_signal_id, method_version) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        group.group_id,
                        group.exact_hash,
                        group.representative_signal_id,
                        group.method_version,
                    ),
                )
                for signal_id in group.signal_ids:
                    connection.execute(
                        "INSERT INTO duplicate_group_signals (group_id, signal_id) VALUES (?, ?)",
                        (group.group_id, signal_id),
                    )

            for cluster in result.clusters:
                connection.execute(
                    """
                    INSERT INTO clusters (
                        cluster_id, label, summary, representative_signal_id,
                        distinct_authors, source_distribution_json, time_start, time_end,
                        clustering_version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cluster_id) DO UPDATE SET
                        label = excluded.label,
                        summary = excluded.summary,
                        representative_signal_id = excluded.representative_signal_id,
                        distinct_authors = excluded.distinct_authors,
                        source_distribution_json = excluded.source_distribution_json,
                        time_start = excluded.time_start,
                        time_end = excluded.time_end,
                        clustering_version = excluded.clustering_version
                    """,
                    (
                        cluster.cluster_id,
                        cluster.label,
                        cluster.summary,
                        cluster.representative_signal_id,
                        cluster.distinct_authors,
                        _json_text(dict(cluster.source_distribution), "source distribution"),
                        cluster.time_start,
                        cluster.time_end,
                        cluster.clustering_version,
                    ),
                )
                connection.execute(
                    "DELETE FROM cluster_signals WHERE cluster_id = ?",
                    (cluster.cluster_id,),
                )
                member_signals = sorted(
                    (signal for signal in result.signals if signal.signal_id in cluster.signal_ids),
                    key=lambda signal: (
                        -(signal.relevance * signal.confidence),
                        signal.signal_id,
                    ),
                )
                for evidence_rank, signal in enumerate(member_signals, start=1):
                    connection.execute(
                        "INSERT INTO cluster_signals "
                        "(cluster_id, signal_id, evidence_rank, evidence_score) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            cluster.cluster_id,
                            signal.signal_id,
                            evidence_rank,
                            round(signal.relevance * signal.confidence, 6),
                        ),
                    )

            for score in result.scores:
                connection.execute(
                    """
                    INSERT INTO scores (
                        cluster_id, total, rank, components_json, weights_json,
                        penalties_json, formula_version, configuration_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cluster_id) DO UPDATE SET
                        total = excluded.total,
                        rank = excluded.rank,
                        components_json = excluded.components_json,
                        weights_json = excluded.weights_json,
                        penalties_json = excluded.penalties_json,
                        formula_version = excluded.formula_version,
                        configuration_hash = excluded.configuration_hash
                    """,
                    (
                        score.cluster_id,
                        score.total,
                        score.rank,
                        _json_text(dict(score.components), "score components"),
                        _json_text(dict(score.weights), "score weights"),
                        _json_text(dict(score.penalties), "score penalties"),
                        score.formula_version,
                        score.configuration_hash,
                    ),
                )

            connection.execute(
                """
                INSERT INTO analysis_state (
                    state_id, configuration_hash, reference_time, record_count,
                    signal_count, cluster_count, analyzed_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(state_id) DO UPDATE SET
                    configuration_hash = excluded.configuration_hash,
                    reference_time = excluded.reference_time,
                    record_count = excluded.record_count,
                    signal_count = excluded.signal_count,
                    cluster_count = excluded.cluster_count,
                    analyzed_at = excluded.analyzed_at
                """,
                (
                    result.configuration_hash,
                    result.reference_time,
                    len(result.assessments),
                    len(result.signals),
                    len(result.clusters),
                    utc_now(),
                ),
            )

    def _invalidate_clusters_for_records(
        self,
        record_ids: Sequence[str],
        connection: sqlite3.Connection | None = None,
    ) -> int:
        if not record_ids:
            return 0
        database = connection or self._connection
        # Scores use global recency and engagement percentiles. Any record-level
        # invalidation makes the complete snapshot stale, even when the record's
        # own cluster is the only derived row removed below.
        database.execute("DELETE FROM analysis_state")
        cluster_ids: set[str] = set()
        for params in _parameter_batches(record_ids, database):
            cluster_rows = database.execute(  # noqa: S608 - placeholders only
                "SELECT DISTINCT cs.cluster_id FROM cluster_signals cs "  # noqa: S608
                "JOIN signals s ON s.signal_id = cs.signal_id "
                f"WHERE s.record_id IN ({_placeholders(len(params))})",  # noqa: S608
                params,
            ).fetchall()
            cluster_ids.update(str(row[0]) for row in cluster_rows)
        ordered_cluster_ids = tuple(sorted(cluster_ids))
        for identifiers in _parameter_batches(ordered_cluster_ids, database):
            database.execute(  # noqa: S608 - generated placeholders only
                f"DELETE FROM clusters WHERE cluster_id IN ({_placeholders(len(identifiers))})",  # noqa: S608
                identifiers,
            )
        return len(cluster_ids)

    def delete_raw_record(self, record_id: str, *, reason: str = "reconciled") -> bool:
        with self.transaction() as connection:
            self._invalidate_clusters_for_records((record_id,), connection)
            cursor = connection.execute("DELETE FROM raw_records WHERE record_id = ?", (record_id,))
            deleted = cursor.rowcount == 1
            if deleted:
                connection.execute("DELETE FROM provider_cache")
                self._write_audit(
                    "record_deleted",
                    {
                        "record_reference_hash": stable_hash(record_id, prefix="record_")[:24],
                        "reason": sanitize_text(reason, max_chars=128),
                    },
                    connection,
                )
        return deleted

    def expire_records(self, *, as_of: str | None = None) -> int:
        """Purge expired raw records and invalidate all dependent clusters."""

        cutoff = as_of or utc_now()
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT record_id FROM raw_records "
                "WHERE expires_at IS NOT NULL AND datetime(expires_at) <= datetime(?)",
                (cutoff,),
            ).fetchall()
            record_ids = tuple(row[0] for row in rows)
            if not record_ids:
                return 0
            self._invalidate_clusters_for_records(record_ids, connection)
            connection.execute("DELETE FROM provider_cache")
            for identifiers in _parameter_batches(record_ids, connection):
                connection.execute(  # noqa: S608 - generated placeholders only
                    f"DELETE FROM raw_records WHERE record_id IN ({_placeholders(len(identifiers))})",  # noqa: S608
                    identifiers,
                )
            self._write_audit(
                "records_expired",
                {"count": len(record_ids), "cutoff": cutoff},
                connection,
            )
            return len(record_ids)

    purge_expired = expire_records

    def purge_source(self, source_id: str) -> int:
        """Delete a source's raw and derived data, cursor, and only retain an audit hash."""

        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT record_id FROM raw_records WHERE source_id = ?", (source_id,)
            ).fetchall()
            record_ids = tuple(row[0] for row in rows)
            self._invalidate_clusters_for_records(record_ids, connection)
            cursor = connection.execute("DELETE FROM raw_records WHERE source_id = ?", (source_id,))
            connection.execute("DELETE FROM cursors WHERE source_id = ?", (source_id,))
            # Run manifests include source identifiers and source-level counts.
            # They cannot be selectively rewritten without changing their audit
            # meaning, so privacy purges remove run history as well.
            connection.execute("DELETE FROM runs")
            connection.execute("DELETE FROM provider_cache")
            self._write_audit(
                "source_purged",
                {
                    "source_reference_hash": stable_hash(source_id, prefix="source_")[:24],
                    "record_count": cursor.rowcount,
                },
                connection,
            )
            return int(cursor.rowcount)

    def _write_audit(
        self,
        event_type: str,
        details: Mapping[str, Any],
        connection: sqlite3.Connection,
    ) -> None:
        occurred_at = utc_now()
        event_id = stable_hash(event_type, occurred_at, secrets.token_hex(8), prefix="audit_")[:46]
        connection.execute(
            "INSERT INTO audit_events (event_id, event_type, occurred_at, details_json) "
            "VALUES (?, ?, ?, ?)",
            (event_id, event_type, occurred_at, _json_text(dict(details), "audit details")),
        )

    def explain(self, identifier: str) -> dict[str, Any]:
        """Return evidence and arithmetic for a record, signal, or cluster."""

        row = self._connection.execute(
            "SELECT record_id FROM raw_records WHERE record_id = ?", (identifier,)
        ).fetchone()
        if row is not None:
            return self._explain_record(identifier)
        row = self._connection.execute(
            "SELECT signal_id FROM signals WHERE signal_id = ?", (identifier,)
        ).fetchone()
        if row is not None:
            return self._explain_signal(identifier)
        row = self._connection.execute(
            "SELECT cluster_id FROM clusters WHERE cluster_id = ?", (identifier,)
        ).fetchone()
        if row is not None:
            return self._explain_cluster(identifier)
        raise NotFoundError("explanation target was not found")

    def _assessment_dict(self, record_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM assessments WHERE record_id = ?", (record_id,)
        ).fetchone()
        if row is None:
            return None
        return {
            "record_id": row["record_id"],
            "relevance": row["relevance"],
            "noise": row["noise"],
            "spam": row["spam"],
            "automation": row["automation"],
            "confidence": row["confidence"],
            "relevance_reasons": _read_json(row["relevance_reasons_json"], []),
            "noise_reasons": _read_json(row["noise_reasons_json"], []),
            "spam_reasons": _read_json(row["spam_reasons_json"], []),
            "automation_reasons": _read_json(row["automation_reasons_json"], []),
            "disposition": row["disposition"],
            "version": row["version"],
        }

    def _signal_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        text = row["text"]
        start, end = int(row["evidence_start"]), int(row["evidence_end"])
        value = {
            "signal_id": row["signal_id"],
            "record_id": row["record_id"],
            "signal_type": row["signal_type"],
            "normalized_statement": row["normalized_statement"],
            "evidence_start": start,
            "evidence_end": end,
            "evidence_text": text[start:end],
            "exact_hash": row["exact_hash"],
            "relevance": row["relevance"],
            "confidence": row["confidence"],
            "extraction_version": row["extraction_version"],
            "source": {
                "source_id": row["source_id"],
                "source_type": row["source_type"],
                "native_id": row["native_id"],
                "canonical_url": safe_provenance_url(row["canonical_url"]),
            },
        }
        keys = set(row.keys())
        if "evidence_rank" in keys:
            value["evidence_rank"] = int(row["evidence_rank"])
            value["evidence_score"] = float(row["evidence_score"])
        if "duplicate_group_id" in keys:
            value["duplicate_group_id"] = row["duplicate_group_id"]
        return value

    def _explain_record(self, record_id: str) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT * FROM raw_records WHERE record_id = ?", (record_id,)
        ).fetchone()
        signal_rows = self._connection.execute(
            "SELECT s.*, r.text, r.source_id, r.source_type, r.native_id, r.canonical_url, "
            "dg.group_id AS duplicate_group_id "
            "FROM signals s JOIN raw_records r ON r.record_id = s.record_id "
            "LEFT JOIN duplicate_group_signals dgs ON dgs.signal_id = s.signal_id "
            "LEFT JOIN duplicate_groups dg ON dg.group_id = dgs.group_id "
            "WHERE s.record_id = ? ORDER BY s.evidence_start, s.signal_id",
            (record_id,),
        ).fetchall()
        override = self._connection.execute(
            "SELECT action, rationale, created_at, applicability_version "
            "FROM review_overrides WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        return {
            "kind": "record",
            "record": {
                "record_id": row["record_id"],
                "source_id": row["source_id"],
                "source_type": row["source_type"],
                "native_id": row["native_id"],
                "canonical_url": safe_provenance_url(row["canonical_url"]),
                "created_at": row["created_at"],
                "retrieved_at": row["retrieved_at"],
                "content_hash": row["content_hash"],
            },
            "assessment": self._assessment_dict(record_id),
            "review_override": (
                {
                    "action": override["action"],
                    "rationale": override["rationale"],
                    "created_at": override["created_at"],
                    "applicability_version": override["applicability_version"],
                }
                if override is not None
                else None
            ),
            "signals": [self._signal_dict(signal_row) for signal_row in signal_rows],
        }

    def _explain_signal(self, signal_id: str) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT s.*, r.text, r.source_id, r.source_type, r.native_id, r.canonical_url, "
            "dg.group_id AS duplicate_group_id "
            "FROM signals s JOIN raw_records r ON r.record_id = s.record_id "
            "LEFT JOIN duplicate_group_signals dgs ON dgs.signal_id = s.signal_id "
            "LEFT JOIN duplicate_groups dg ON dg.group_id = dgs.group_id "
            "WHERE s.signal_id = ?",
            (signal_id,),
        ).fetchone()
        return {
            "kind": "signal",
            "signal": self._signal_dict(row),
            "assessment": self._assessment_dict(row["record_id"]),
        }

    def _explain_cluster(self, cluster_id: str) -> dict[str, Any]:
        cluster = self._connection.execute(
            "SELECT * FROM clusters WHERE cluster_id = ?", (cluster_id,)
        ).fetchone()
        score = self._connection.execute(
            "SELECT * FROM scores WHERE cluster_id = ?", (cluster_id,)
        ).fetchone()
        signal_rows = self._connection.execute(
            "SELECT s.*, r.text, r.source_id, r.source_type, r.native_id, r.canonical_url, "
            "cs.evidence_rank, cs.evidence_score, dg.group_id AS duplicate_group_id "
            "FROM cluster_signals cs "
            "JOIN signals s ON s.signal_id = cs.signal_id "
            "JOIN raw_records r ON r.record_id = s.record_id "
            "LEFT JOIN duplicate_group_signals dgs ON dgs.signal_id = s.signal_id "
            "LEFT JOIN duplicate_groups dg ON dg.group_id = dgs.group_id "
            "WHERE cs.cluster_id = ? ORDER BY cs.evidence_rank, s.signal_id",
            (cluster_id,),
        ).fetchall()
        score_value = None
        if score is not None:
            score_value = {
                "total": score["total"],
                "rank": score["rank"],
                "components": _read_json(score["components_json"], {}),
                "weights": _read_json(score["weights_json"], {}),
                "penalties": _read_json(score["penalties_json"], {}),
                "formula_version": score["formula_version"],
                "configuration_hash": score["configuration_hash"],
            }
        return {
            "kind": "cluster",
            "cluster": {
                "cluster_id": cluster["cluster_id"],
                "label": cluster["label"],
                "summary": cluster["summary"],
                "representative_signal_id": cluster["representative_signal_id"],
                "distinct_authors": cluster["distinct_authors"],
                "source_distribution": _read_json(cluster["source_distribution_json"], {}),
                "time_start": cluster["time_start"],
                "time_end": cluster["time_end"],
                "clustering_version": cluster["clustering_version"],
            },
            "score": score_value,
            "signals": [self._signal_dict(signal_row) for signal_row in signal_rows],
        }


SQLiteStorage = Storage
