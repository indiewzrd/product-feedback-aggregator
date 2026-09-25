"""Bounded JSON and NDJSON ingestion with strict parsing."""

from __future__ import annotations

import json
import math
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from ..errors import CollectionError, ConfigurationError
from ..models import (
    SCHEMA_VERSION,
    CheckItem,
    CollectionPlan,
    CollectionResult,
    RawRecord,
    utc_now,
)
from ..util import normalized_text, pseudonymize_author, sanitize_text, stable_hash
from .base import Connector, connector_note

MAX_JSON_DEPTH = 20
MAX_JSON_NODES = 100_000
MAX_TEXT_CHARS = 200_000
MAX_URL_CHARS = 4_096
MAX_ID_CHARS = 512
MAX_AUTHOR_CHARS = 4_096
MAX_METADATA_KEY_CHARS = 128
MAX_METADATA_VALUE_CHARS = 4_096
_MISSING = object()


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite number {value!r} is not allowed")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def strict_json_loads(value: str) -> Any:
    parsed = json.loads(value, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    _validate_json_shape(parsed)
    return parsed


def _validate_json_shape(value: Any, depth: int = 0, counter: list[int] | None = None) -> None:
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if counter[0] > MAX_JSON_NODES:
        raise ValueError("JSON contains too many values")
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON is nested too deeply")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            _validate_json_shape(child, depth + 1, counter)
    elif isinstance(value, list):
        for child in value:
            _validate_json_shape(child, depth + 1, counter)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError(f"Unsupported JSON value {type(value).__name__}")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError("Non-finite JSON numbers are not allowed")


def _regular_file(path: Path, maximum: int) -> int:
    try:
        status = path.stat()
    except OSError as exc:
        raise CollectionError(f"Cannot read input file: {path}") from exc
    if not stat.S_ISREG(status.st_mode):
        raise CollectionError(f"Input must be a regular file: {path}")
    if status.st_size > maximum:
        raise CollectionError(f"Input file exceeds the {maximum}-byte limit: {path}")
    return status.st_size


def iter_json_records(
    path: Path,
    *,
    max_file_bytes: int,
    max_line_bytes: int,
    permissive: bool = False,
) -> Iterable[tuple[dict[str, Any], str]]:
    _regular_file(path, max_file_bytes)
    suffix = path.suffix.lower()
    if suffix in {".ndjson", ".jsonl"}:
        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if len(raw_line) > max_line_bytes:
                    raise CollectionError(
                        f"{path}:{line_number}: line exceeds {max_line_bytes} bytes"
                    )
                if not raw_line.strip():
                    continue
                try:
                    item = strict_json_loads(raw_line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
                    if permissive:
                        continue
                    raise CollectionError(
                        f"{path}:{line_number}: invalid NDJSON record"
                    ) from exc
                if not isinstance(item, dict):
                    if permissive:
                        continue
                    raise CollectionError(f"{path}:{line_number}: each record must be an object")
                yield item, f"{path}:{line_number}"
        return
    try:
        text = path.read_text(encoding="utf-8")
        value = strict_json_loads(text)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise CollectionError(f"{path}: invalid JSON") from exc
    items = value if isinstance(value, list) else None
    if isinstance(value, dict):
        wrapper_keys = {"records", "schema_version"}
        if "records" in value and (set(value).issubset(wrapper_keys) or "text" not in value):
            if set(value) - wrapper_keys:
                raise CollectionError(f"{path}: records wrapper has unknown fields")
            declared = value.get("schema_version", SCHEMA_VERSION)
            if type(declared) is not int or declared != SCHEMA_VERSION:
                raise CollectionError(
                    f"{path}: records wrapper schema_version must be {SCHEMA_VERSION}"
                )
            wrapped = value.get("records")
            if not isinstance(wrapped, list):
                raise CollectionError(f"{path}: records wrapper must contain a list")
            items = wrapped
        else:
            items = [value]
    if not isinstance(items, list):
        raise CollectionError(
            f"{path}: JSON must be a record, a list, or an object with a records list"
        )
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            if permissive:
                continue
            raise CollectionError(f"{path}:records[{index}] must be an object")
        yield item, f"{path}:records[{index}]"


def iter_ndjson_bytes(
    data: bytes, *, label: str, max_line_bytes: int
) -> Iterable[tuple[dict[str, Any], str]]:
    for line_number, raw_line in enumerate(data.splitlines(), start=1):
        if len(raw_line) > max_line_bytes:
            raise CollectionError(f"{label}:{line_number}: line exceeds {max_line_bytes} bytes")
        if not raw_line.strip():
            continue
        try:
            value = strict_json_loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise CollectionError(f"{label}:{line_number}: invalid NDJSON record") from exc
        if not isinstance(value, dict):
            raise CollectionError(f"{label}:{line_number}: each record must be an object")
        yield value, f"{label}:{line_number}"


def _field(item: dict[str, Any], mapping: dict[str, str], name: str, default: Any = "") -> Any:
    return item.get(mapping.get(name, name), default)


def _finite_scalar(value: object, field_name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError(f"{field_name} must be a string or number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{field_name} must be finite")
    return str(value)


def record_from_mapping(
    item: dict[str, Any],
    *,
    source_id: str,
    source_type: str,
    location: str,
    mapping: dict[str, str],
    author_salt: str,
    acquisition_mode: str,
    policy_assurance: str,
    expires_at: str | None = None,
) -> RawRecord:
    declared_schema = item.get("schema_version", SCHEMA_VERSION)
    if (
        isinstance(declared_schema, bool)
        or not isinstance(declared_schema, int)
        or declared_schema != SCHEMA_VERSION
    ):
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    raw_text = _field(item, mapping, "text", _MISSING)
    if not isinstance(raw_text, str):
        raise ValueError("text must be a string")
    if len(raw_text) > MAX_TEXT_CHARS:
        raise ValueError(f"text exceeds {MAX_TEXT_CHARS} characters")
    text = sanitize_text(raw_text, max_chars=MAX_TEXT_CHARS)
    if not text:
        raise ValueError("text is required")
    raw_url = _field(item, mapping, "url", _MISSING)
    if raw_url is _MISSING:
        canonical_url = ""
    else:
        if not isinstance(raw_url, str):
            raise ValueError("url must be a string")
        if len(raw_url) > MAX_URL_CHARS:
            raise ValueError(f"url exceeds {MAX_URL_CHARS} characters")
        canonical_url = sanitize_text(raw_url, max_chars=MAX_URL_CHARS)

    native_value = _field(item, mapping, "id", _MISSING)
    if native_value is _MISSING:
        supplied_native_id = ""
    else:
        supplied_native_id = _finite_scalar(native_value, "id")
        if len(supplied_native_id) > MAX_ID_CHARS:
            raise ValueError(f"id exceeds {MAX_ID_CHARS} characters")
        supplied_native_id = sanitize_text(supplied_native_id, max_chars=MAX_ID_CHARS)
    native_id = supplied_native_id or stable_hash(
        canonical_url or normalized_text(text), prefix="local_"
    )[:38]

    raw_created_at = _field(item, mapping, "created_at", _MISSING)
    if raw_created_at is _MISSING:
        supplied_created_at = ""
        created_at = utc_now()
    else:
        if not isinstance(raw_created_at, str):
            raise ValueError("created_at must be a string")
        if not raw_created_at or len(raw_created_at) > 64:
            raise ValueError("created_at must be a non-empty timestamp of at most 64 characters")
        supplied_created_at = sanitize_text(raw_created_at, max_chars=64)
        if supplied_created_at != raw_created_at.strip():
            raise ValueError("created_at contains unsupported control or whitespace characters")
        created_at = supplied_created_at
    try:
        parsed_created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at must be an ISO 8601 timestamp with a timezone") from exc
    if parsed_created_at.tzinfo is None:
        raise ValueError("created_at must be an ISO 8601 timestamp with a timezone")
    author = _field(item, mapping, "author", _MISSING)
    if author is _MISSING or author is None:
        author = None
    else:
        author_text = _finite_scalar(author, "author")
        if len(author_text) > MAX_AUTHOR_CHARS:
            raise ValueError(f"author exceeds {MAX_AUTHOR_CHARS} characters")
        author = author_text
    author_key = pseudonymize_author(source_type, author, author_salt)
    engagement_raw = _field(item, mapping, "engagement", {})
    if engagement_raw is None:
        engagement_raw = {}
    if not isinstance(engagement_raw, dict):
        raise ValueError("engagement must be an object")
    engagement: dict[str, float] = {}
    for key, value in engagement_raw.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > MAX_METADATA_KEY_CHARS
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
        ):
            raise ValueError("engagement values must be finite numbers")
        number = float(value)
        if not math.isfinite(number) or number < 0 or number > 1_000_000_000:
            raise ValueError("engagement value is outside the supported range")
        engagement[key] = number
    allowed_metadata = _field(item, mapping, "metadata", {})
    if allowed_metadata is None:
        allowed_metadata = {}
    if not isinstance(allowed_metadata, dict):
        raise ValueError("metadata must be an object")
    metadata: dict[str, Any] = {}
    for key, value in allowed_metadata.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > MAX_METADATA_KEY_CHARS
            or key in {"created_at_inferred", "input_location"}
        ):
            raise ValueError("metadata contains an invalid or reserved key")
        if value is None or isinstance(value, bool):
            metadata[key] = value
        elif isinstance(value, str):
            if len(value) > MAX_METADATA_VALUE_CHARS:
                raise ValueError("metadata string exceeds the supported length")
            metadata[key] = sanitize_text(value, max_chars=MAX_METADATA_VALUE_CHARS)
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("metadata number must be finite")
            metadata[key] = value
        else:
            raise ValueError("metadata values must be scalar JSON values")
    metadata["input_location"] = location
    metadata["created_at_inferred"] = not bool(supplied_created_at)
    return RawRecord(
        source_id=source_id,
        source_type=source_type,
        native_id=native_id,
        canonical_url=canonical_url,
        text=text,
        created_at=created_at,
        retrieved_at=utc_now(),
        author_key=author_key,
        engagement=engagement,
        metadata=metadata,
        acquisition_mode=acquisition_mode,
        policy_assurance=policy_assurance,
        expires_at=expires_at,
    )


class JsonFileConnector(Connector):
    def _paths(self) -> tuple[Path, ...]:
        raw = self.source.options.get("paths", [])
        if not isinstance(raw, list) or not raw or not all(isinstance(value, str) for value in raw):
            raise ConfigurationError(f"Source {self.source.id} requires options.paths")
        return tuple(
            (self.config.root / value).resolve()
            if not Path(value).expanduser().is_absolute()
            else Path(value).expanduser().resolve()
            for value in raw
        )

    def check(self, *, probe: bool = False) -> list[CheckItem]:
        del probe
        results: list[CheckItem] = []
        try:
            paths = self._paths()
        except ConfigurationError as exc:
            return [connector_note(self.context, str(exc), "error")]
        for path in paths:
            try:
                size = _regular_file(path, self.config.limits.max_file_bytes)
                results.append(
                    CheckItem(
                        f"file:{path}",
                        "ok",
                        f"Readable regular file ({size} bytes)",
                        self.source.id,
                    )
                )
            except CollectionError as exc:
                results.append(CheckItem(f"file:{path}", "error", str(exc), self.source.id))
        return results

    def plan(self) -> CollectionPlan:
        paths = self._paths()
        return CollectionPlan(
            self.source.id,
            self.source.type,
            ", ".join(str(path) for path in paths),
            self.source.max_items,
            0,
            0.0,
            ("Local input; no network access",),
        )

    def collect(self, *, cursor: str | None = None) -> CollectionResult:
        del cursor
        records: list[RawRecord] = []
        permissive = self.source.options.get("permissive") is True
        mapping_raw = self.source.options.get("mapping", {})
        if not isinstance(mapping_raw, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in mapping_raw.items()
        ):
            raise ConfigurationError(
                "options.mapping must map canonical names to input field names"
            )
        skipped = 0
        for path in self._paths():
            for item, location in iter_json_records(
                path,
                max_file_bytes=self.config.limits.max_file_bytes,
                max_line_bytes=self.config.limits.max_line_bytes,
                permissive=permissive,
            ):
                if len(records) >= self.source.max_items:
                    return CollectionResult.from_records(
                        records, resources_read=len(records), stop_reason="item_cap"
                    )
                try:
                    records.append(
                        record_from_mapping(
                            item,
                            source_id=self.source.id,
                            source_type="json",
                            location=location,
                            mapping=mapping_raw,
                            author_salt=self.context.author_salt,
                            acquisition_mode="user_file",
                            policy_assurance="user",
                        )
                    )
                except ValueError as exc:
                    if permissive:
                        skipped += 1
                        continue
                    raise CollectionError(f"{location}: {exc}") from exc
        stop_reason = f"complete_with_{skipped}_skipped" if skipped else "complete"
        return CollectionResult.from_records(
            records, resources_read=len(records), stop_reason=stop_reason
        )
