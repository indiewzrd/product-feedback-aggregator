"""Shared, bounded Apify Actor orchestration for social feedback connectors.

Only fixed, reviewed Actors are exposed by the concrete connectors. This module
starts one asynchronous run, checkpoints its identifiers before polling, and
then imports the run's default dataset in bounded pages. Actor output is always
treated as untrusted JSON.
"""

from __future__ import annotations

import math
import os
import re
import time
from abc import abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Protocol, cast
from urllib.parse import urlencode, urlsplit, urlunsplit

from ..errors import BudgetError, CollectionError, ConfigurationError, PartialCollectionError
from ..models import CheckItem, CollectionPlan, CollectionResult, RawRecord
from ..util import canonical_json, sanitize_text
from .base import Connector, connector_note
from .json_file import strict_json_loads
from .social_state import checkpoint_scope

APIFY_ORIGIN = "https://api.apify.com"
APIFY_ACTORS: dict[str, str] = {
    "reddit_apify": "trudax/reddit-scraper-lite",
    "x_apify": "apidojo/twitter-scraper-lite",
}

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_BUILD_NUMBER = re.compile(r"^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,5}$")
_APIFY_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SCOPE = re.compile(r"^scope_[0-9a-f]{64}$")
_TRANSITIONAL_STATUSES = frozenset({"READY", "RUNNING", "ABORTING", "TIMING-OUT"})
_FAILED_STATUSES = frozenset({"FAILED", "TIMED-OUT", "ABORTED"})
_MAX_CHECKPOINT_BYTES = 8_192
_MAX_COST_USD = Decimal("1000")


class ApifyResponse(Protocol):
    status: int
    headers: Mapping[str, str]
    body: bytes


class ApifyHttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
        allow_redirects: bool = False,
    ) -> ApifyResponse: ...


@dataclass(frozen=True, slots=True)
class ApifySettings:
    token: str = field(repr=False)
    token_env: str
    actor_build: str
    max_cost: Decimal
    dataset_page_size: int
    poll_interval_seconds: float
    initial_lookback_days: int
    overlap_hours: int


@dataclass(frozen=True, slots=True)
class ApifyCheckpoint:
    """Completed high-water mark plus an optional in-progress paid run."""

    kind: str
    scope: str
    high_water_at: str | None = None
    run_id: str | None = None
    dataset_id: str | None = None
    offset: int = 0
    pending_high_water_at: str | None = None

    def encode(self) -> str:
        value = canonical_json(
            {
                "dataset_id": self.dataset_id,
                "high_water_at": self.high_water_at,
                "kind": self.kind,
                "offset": self.offset,
                "pending_high_water_at": self.pending_high_water_at,
                "run_id": self.run_id,
                "scope": self.scope,
                "version": 1,
            }
        )
        if len(value.encode("utf-8")) > _MAX_CHECKPOINT_BYTES:
            raise ConfigurationError("Apify checkpoint exceeds its size limit")
        return value

    @classmethod
    def decode(cls, value: str | None, *, kind: str, scope: str) -> "ApifyCheckpoint":
        if value is None:
            return cls(kind=kind, scope=scope)
        if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_CHECKPOINT_BYTES:
            raise ConfigurationError("Apify checkpoint is invalid")
        try:
            parsed = strict_json_loads(value)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ConfigurationError("Apify checkpoint is not valid JSON") from exc
        expected = {
            "dataset_id",
            "high_water_at",
            "kind",
            "offset",
            "pending_high_water_at",
            "run_id",
            "scope",
            "version",
        }
        if (
            not isinstance(parsed, dict)
            or set(parsed) != expected
            or parsed.get("version") != 1
            or parsed.get("kind") != kind
        ):
            raise ConfigurationError("Apify checkpoint has an unsupported shape or version")
        stored_scope = parsed.get("scope")
        if not isinstance(stored_scope, str) or _SCOPE.fullmatch(stored_scope) is None:
            raise ConfigurationError("Apify checkpoint scope is invalid")
        if stored_scope != scope:
            raise ConfigurationError(
                "Apify checkpoint belongs to different source settings; "
                "purge this source before collecting"
            )
        run_id = _optional_identifier(parsed.get("run_id"), "run ID")
        dataset_id = _optional_identifier(parsed.get("dataset_id"), "dataset ID")
        high_water_at = _optional_timestamp(parsed.get("high_water_at"), "high-water timestamp")
        pending = _optional_timestamp(
            parsed.get("pending_high_water_at"), "pending high-water timestamp"
        )
        offset = parsed.get("offset")
        if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 100_000:
            raise ConfigurationError("Apify checkpoint offset is invalid")
        active_values = (run_id, dataset_id, pending)
        if any(item is None for item in active_values) and any(
            item is not None for item in active_values
        ):
            raise ConfigurationError("Apify checkpoint has incomplete run state")
        if run_id is None and offset != 0:
            raise ConfigurationError("Apify checkpoint has an offset without an active run")
        return cls(
            kind=kind,
            scope=scope,
            high_water_at=high_water_at,
            run_id=run_id,
            dataset_id=dataset_id,
            offset=offset,
            pending_high_water_at=pending,
        )


@dataclass(frozen=True, slots=True)
class ApifyRun:
    run_id: str
    dataset_id: str
    status: str
    build_id: str
    build_number: str
    cost_usd: Decimal


@dataclass(frozen=True, slots=True)
class ApifyProvenance:
    actor_id: str
    requested_build: str
    build_id: str
    build_number: str
    run_id: str
    dataset_id: str


def _optional_identifier(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _APIFY_ID.fullmatch(value) is None:
        raise ConfigurationError(f"Apify checkpoint {label} is invalid")
    return value


def _optional_timestamp(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _parse_timestamp(value) is None:
        raise ConfigurationError(f"Apify checkpoint {label} is invalid")
    return value


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def bounded_integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def bounded_number(value: object, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return result


def bounded_string_list(
    value: object,
    name: str,
    *,
    maximum_items: int,
    maximum_chars: int,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > maximum_items
        or not all(isinstance(item, str) for item in value)
    ):
        raise ConfigurationError(f"{name} must be a non-empty bounded string list")
    result: list[str] = []
    for raw in value:
        cleaned = sanitize_text(raw, max_chars=maximum_chars + 1)
        if not cleaned or cleaned != raw.strip() or len(cleaned) > maximum_chars:
            raise ConfigurationError(f"{name} contains an invalid or oversized value")
        if cleaned not in result:
            result.append(cleaned)
    return tuple(result)


def social_url(
    value: object,
    *,
    allowed_hosts: frozenset[str],
    label: str,
    keep_query: bool = False,
) -> str:
    if not isinstance(value, str) or not value or len(value) > 4_096:
        raise CollectionError(f"{label} is invalid")
    cleaned = sanitize_text(value, max_chars=4_097)
    if cleaned != value.strip() or len(cleaned) > 4_096:
        raise CollectionError(f"{label} is invalid")
    try:
        parsed = urlsplit(cleaned)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        raise CollectionError(f"{label} is invalid") from exc
    if (
        parsed.scheme.lower() != "https"
        or not host
        or host not in allowed_hosts
        or port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise CollectionError(f"{label} is outside the permitted social origins")
    netloc = host if port is None else f"{host}:443"
    return urlunsplit(("https", netloc, parsed.path, parsed.query if keep_query else "", ""))


def scalar_metadata(value: object, *, maximum_chars: int = 512) -> str | bool | int | None:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and len(value) <= maximum_chars:
        return sanitize_text(value, max_chars=maximum_chars)
    return None


def finite_engagement(item: Mapping[str, Any], fields: Mapping[str, str]) -> dict[str, float]:
    result: dict[str, float] = {}
    for source_name, output_name in fields.items():
        raw = item.get(source_name)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            continue
        value = float(raw)
        if math.isfinite(value) and 0 <= value <= 1_000_000_000_000:
            result[output_name] = value
    return result


class ApifySocialConnector(Connector):
    """Base class for one fixed community Actor and one normalized platform."""

    actor_id: str

    def _transport(self) -> ApifyHttpTransport:
        transport = self.context.http
        if transport is None or not callable(getattr(transport, "request", None)):
            raise CollectionError("Apify HTTP transport is unavailable")
        return cast(ApifyHttpTransport, transport)

    def _common_settings(self, *, require_secret: bool) -> ApifySettings:
        if self.source.type not in APIFY_ACTORS or APIFY_ACTORS[self.source.type] != self.actor_id:
            raise ConfigurationError("Apify connector actor selection is invalid")
        options = self.source.options
        if options.get("approval_confirmed") is not True:
            raise ConfigurationError(
                "Apify options.approval_confirmed must be true after operator review"
            )
        if self.source.policy.acquisition_mode != "third_party_scraper":
            raise ConfigurationError(
                "Apify policy.acquisition_mode must be third_party_scraper"
            )
        if not self.source.policy.remote_processing_allowed:
            raise ConfigurationError(
                "Apify policy.remote_processing_allowed must be explicitly true"
            )
        token_env = options.get("token_env", "APIFY_TOKEN")
        if not isinstance(token_env, str) or _ENV_NAME.fullmatch(token_env) is None:
            raise ConfigurationError(
                "Apify options.token_env must name an uppercase environment variable"
            )
        token = os.environ.get(token_env, "") if require_secret else "placeholder"
        if require_secret and not token:
            raise ConfigurationError(f"Apify token environment variable {token_env} is not set")
        if len(token) > 8_192 or any(character in token for character in "\r\n\x00"):
            raise ConfigurationError(f"Apify token environment variable {token_env} is invalid")
        build = options.get("actor_build")
        if not isinstance(build, str) or _BUILD_NUMBER.fullmatch(build) is None:
            raise ConfigurationError(
                "Apify options.actor_build must be an exact build number such as 1.2.345"
            )
        try:
            max_cost = Decimal(str(self.source.policy.max_cost_usd))
        except (InvalidOperation, ValueError) as exc:
            raise ConfigurationError("Apify policy.max_cost_usd must be a decimal amount") from exc
        if not max_cost.is_finite() or not Decimal("0") < max_cost <= _MAX_COST_USD:
            raise ConfigurationError(
                f"Apify policy.max_cost_usd must be greater than zero and at most {_MAX_COST_USD}"
            )
        is_reddit = self.source.type == "reddit_apify"
        return ApifySettings(
            token=token,
            token_env=token_env,
            actor_build=build,
            max_cost=max_cost,
            dataset_page_size=bounded_integer(
                options.get("dataset_page_size", 100),
                "Apify options.dataset_page_size",
                1,
                500,
            ),
            poll_interval_seconds=bounded_number(
                options.get("poll_interval_seconds", 2),
                "Apify options.poll_interval_seconds",
                0.1,
                30,
            ),
            initial_lookback_days=bounded_integer(
                options.get("initial_lookback_days", 30 if is_reddit else 7),
                "Apify options.initial_lookback_days",
                1,
                365,
            ),
            overlap_hours=bounded_integer(
                options.get("overlap_hours", 48 if is_reddit else 24),
                "Apify options.overlap_hours",
                1,
                168,
            ),
        )

    @abstractmethod
    def _scope_options(self, settings: ApifySettings) -> Mapping[str, Any]:
        """Return validated, stream-defining platform options."""

    @abstractmethod
    def _actor_input(self, settings: ApifySettings, *, since: datetime) -> dict[str, Any]:
        """Build the fixed Actor input for one bounded run."""

    @abstractmethod
    def _query_label(self, settings: ApifySettings) -> str:
        """Return a safe human-readable description for the offline plan."""

    @abstractmethod
    def _normalize_item(
        self,
        item: Mapping[str, Any],
        *,
        provenance: ApifyProvenance,
        retrieved_at: str,
    ) -> RawRecord | None:
        """Map one strict Actor result to the minimal canonical record."""

    def _scope(self, settings: ApifySettings) -> str:
        return checkpoint_scope(
            self.source.type,
            {
                "actor_build": settings.actor_build,
                "actor_id": self.actor_id,
                "author_salt": self.context.author_salt,
                "dataset_page_size": settings.dataset_page_size,
                "initial_lookback_days": settings.initial_lookback_days,
                "max_items": self.source.max_items,
                "overlap_hours": settings.overlap_hours,
                "platform": dict(self._scope_options(settings)),
            },
        )

    def check(self, *, probe: bool = False) -> list[CheckItem]:
        del probe  # Probing could start or bill an Actor, so checks are local-only.
        try:
            settings = self._common_settings(require_secret=True)
            now = datetime.now(timezone.utc)
            self._actor_input(
                settings,
                since=now - timedelta(days=settings.initial_lookback_days),
            )
            self._scope(settings)
        except (CollectionError, ConfigurationError) as exc:
            return [connector_note(self.context, str(exc), "error")]
        return [
            connector_note(
                self.context,
                f"Apify Actor {self.actor_id} build {settings.actor_build} is configured "
                f"with a {settings.max_cost} USD run cap",
            )
        ]

    def plan(self) -> CollectionPlan:
        settings = self._common_settings(require_secret=False)
        now = datetime.now(timezone.utc)
        self._actor_input(
            settings,
            since=now - timedelta(days=settings.initial_lookback_days),
        )
        estimated_pages = max(1, math.ceil(self.source.max_items / settings.dataset_page_size))
        estimated_polls = max(
            1,
            math.ceil(
                self.config.limits.total_timeout_seconds / settings.poll_interval_seconds
            ),
        )
        return CollectionPlan(
            source_id=self.source.id,
            source_type=self.source.type,
            query=self._query_label(settings),
            max_items=self.source.max_items,
            estimated_requests=1 + estimated_polls + estimated_pages,
            upper_bound_cost_usd=float(settings.max_cost),
            notes=(
                f"Community Actor {self.actor_id}, exact build {settings.actor_build}",
                "Apify remotely processes and temporarily stores the requested social data",
                "Coverage is best-effort; overlapping windows are deduplicated locally",
            ),
        )

    def _headers(self, settings: ApifySettings) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {settings.token}",
            "Content-Type": "application/json",
        }

    def _response_json(self, response: object, *, operation: str) -> Any:
        body = getattr(response, "body", None)
        if not isinstance(body, (bytes, bytearray)):
            raise CollectionError(f"Apify {operation} returned an unreadable response")
        encoded = bytes(body)
        if len(encoded) > self.config.limits.max_decompressed_bytes:
            raise CollectionError(f"Apify {operation} response exceeded the size limit")
        try:
            return strict_json_loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CollectionError(f"Apify {operation} returned invalid JSON") from exc

    def _run_from_response(self, response: object, *, operation: str) -> ApifyRun:
        status_code = getattr(response, "status", 0)
        if not isinstance(status_code, int) or not 200 <= status_code < 300:
            raise CollectionError(f"Apify {operation} failed with HTTP status {status_code}")
        value = self._response_json(response, operation=operation)
        data = value.get("data") if isinstance(value, dict) else None
        if not isinstance(data, dict):
            raise CollectionError(f"Apify {operation} response has an invalid shape")
        run_id = data.get("id")
        dataset_id = data.get("defaultDatasetId")
        status = data.get("status")
        build_id = data.get("buildId")
        build_number = data.get("buildNumber")
        if (
            not isinstance(run_id, str)
            or _APIFY_ID.fullmatch(run_id) is None
            or not isinstance(dataset_id, str)
            or _APIFY_ID.fullmatch(dataset_id) is None
            or not isinstance(status, str)
            or status not in _TRANSITIONAL_STATUSES | _FAILED_STATUSES | {"SUCCEEDED"}
            or not isinstance(build_id, str)
            or _APIFY_ID.fullmatch(build_id) is None
            or not isinstance(build_number, str)
            or _BUILD_NUMBER.fullmatch(build_number) is None
        ):
            raise CollectionError(f"Apify {operation} response has invalid run metadata")
        raw_cost = data.get("usageTotalUsd", 0)
        if isinstance(raw_cost, bool) or not isinstance(raw_cost, (int, float)):
            raw_cost = 0
        cost = Decimal(str(raw_cost))
        if not cost.is_finite() or cost < 0:
            raise CollectionError(f"Apify {operation} response has invalid usage metadata")
        return ApifyRun(run_id, dataset_id, status, build_id, build_number, cost)

    def _start_run(
        self,
        settings: ApifySettings,
        *,
        actor_input: Mapping[str, Any],
    ) -> ApifyRun:
        actor_path = self.actor_id.replace("/", "~")
        query = urlencode(
            {
                "build": settings.actor_build,
                "forcePermissionLevel": "LIMITED_PERMISSIONS",
                "maxItems": str(self.source.max_items),
                "maxTotalChargeUsd": format(settings.max_cost, "f"),
                "restartOnError": "false",
                "timeout": str(max(1, math.ceil(self.config.limits.total_timeout_seconds))),
            }
        )
        body = canonical_json(dict(actor_input)).encode("utf-8")
        if len(body) > 65_536:
            raise ConfigurationError("Apify Actor input exceeds the request size limit")
        response = self._transport().request(
            "POST",
            f"{APIFY_ORIGIN}/v2/actors/{actor_path}/runs?{query}",
            headers=self._headers(settings),
            body=body,
            allow_redirects=False,
        )
        return self._run_from_response(response, operation="run start")

    def _get_run(self, settings: ApifySettings, run_id: str) -> ApifyRun:
        response = self._transport().request(
            "GET",
            f"{APIFY_ORIGIN}/v2/actor-runs/{run_id}",
            headers=self._headers(settings),
            allow_redirects=False,
        )
        run = self._run_from_response(response, operation="run status")
        if run.run_id != run_id:
            raise CollectionError("Apify run status returned a different run ID")
        return run

    def _dataset_page(
        self,
        settings: ApifySettings,
        *,
        dataset_id: str,
        offset: int,
        limit: int,
    ) -> tuple[list[dict[str, Any]], int | None]:
        query = urlencode(
            {"clean": "1", "format": "json", "limit": str(limit), "offset": str(offset)}
        )
        response = self._transport().request(
            "GET",
            f"{APIFY_ORIGIN}/v2/datasets/{dataset_id}/items?{query}",
            headers=self._headers(settings),
            allow_redirects=False,
        )
        status_code = getattr(response, "status", 0)
        if status_code != 200:
            raise CollectionError(
                f"Apify dataset retrieval failed with HTTP status {status_code}"
            )
        value = self._response_json(response, operation="dataset retrieval")
        if not isinstance(value, list) or len(value) > limit:
            raise CollectionError("Apify dataset response has an invalid page shape")
        items: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                raise CollectionError("Apify dataset contains a non-object item")
            items.append(item)
        total: int | None = None
        raw_headers = getattr(response, "headers", {})
        if isinstance(raw_headers, Mapping):
            for name, raw_value in raw_headers.items():
                if str(name).lower() != "x-apify-pagination-total":
                    continue
                try:
                    parsed_total = int(str(raw_value))
                except ValueError as exc:
                    raise CollectionError("Apify dataset pagination metadata is invalid") from exc
                if not 0 <= parsed_total <= 100_000_000:
                    raise CollectionError("Apify dataset pagination metadata is invalid")
                total = parsed_total
        return items, total

    def _progress(
        self,
        *,
        records: list[RawRecord],
        checkpoint: ApifyCheckpoint,
        requests_made: int,
        resources_read: int,
        cost: Decimal,
        stop_reason: str,
    ) -> CollectionResult:
        return CollectionResult.from_records(
            records,
            cursor=checkpoint.encode(),
            requests_made=requests_made,
            resources_read=resources_read,
            cost_usd=float(cost),
            stop_reason=stop_reason,
        )

    def _save_progress(self, result: CollectionResult) -> None:
        callback = self.context.checkpoint
        if callback is not None:
            callback(result)

    def collect(self, *, cursor: str | None = None) -> CollectionResult:
        settings = self._common_settings(require_secret=True)
        scope = self._scope(settings)
        checkpoint = ApifyCheckpoint.decode(cursor, kind=self.source.type, scope=scope)
        if checkpoint.offset > self.source.max_items:
            raise ConfigurationError("Apify checkpoint exceeds this source's item limit")

        records: list[RawRecord] = []
        resources_read = checkpoint.offset
        requests_made = 0
        run: ApifyRun
        deadline = time.monotonic() + self.config.limits.total_timeout_seconds

        try:
            if checkpoint.run_id is None:
                now = datetime.now(timezone.utc).replace(microsecond=0)
                if checkpoint.high_water_at is None:
                    since = now - timedelta(days=settings.initial_lookback_days)
                else:
                    high_water = _parse_timestamp(checkpoint.high_water_at)
                    if high_water is None:  # Defensive: decode already validates it.
                        raise ConfigurationError("Apify high-water timestamp is invalid")
                    since = high_water - timedelta(hours=settings.overlap_hours)
                actor_input = self._actor_input(settings, since=since)
                run = self._start_run(settings, actor_input=actor_input)
                requests_made += 1
                checkpoint = ApifyCheckpoint(
                    kind=self.source.type,
                    scope=scope,
                    high_water_at=checkpoint.high_water_at,
                    run_id=run.run_id,
                    dataset_id=run.dataset_id,
                    offset=0,
                    pending_high_water_at=utc_timestamp(now),
                )
                self._save_progress(
                    self._progress(
                        records=records,
                        checkpoint=checkpoint,
                        requests_made=requests_made,
                        resources_read=0,
                        cost=run.cost_usd,
                        stop_reason="actor_started",
                    )
                )
            else:
                run = self._get_run(settings, checkpoint.run_id)
                requests_made += 1
                if run.dataset_id != checkpoint.dataset_id:
                    raise CollectionError("Apify run status returned a different dataset ID")

            while run.status in _TRANSITIONAL_STATUSES:
                remaining = deadline - time.monotonic()
                if remaining <= settings.poll_interval_seconds:
                    return self._progress(
                        records=records,
                        checkpoint=checkpoint,
                        requests_made=requests_made,
                        resources_read=resources_read,
                        cost=run.cost_usd,
                        stop_reason="actor_running",
                    )
                time.sleep(settings.poll_interval_seconds)
                run = self._get_run(settings, run.run_id)
                requests_made += 1
                if run.dataset_id != checkpoint.dataset_id:
                    raise CollectionError("Apify run status returned a different dataset ID")

            if run.status in _FAILED_STATUSES:
                cleared = ApifyCheckpoint(
                    kind=self.source.type,
                    scope=scope,
                    high_water_at=checkpoint.high_water_at,
                )
                partial = self._progress(
                    records=records,
                    checkpoint=cleared,
                    requests_made=requests_made,
                    resources_read=resources_read,
                    cost=run.cost_usd,
                    stop_reason="actor_failed",
                )
                raise PartialCollectionError(
                    f"Apify Actor run {run.run_id} ended with status {run.status}", partial
                )
            if run.status != "SUCCEEDED":
                raise CollectionError("Apify Actor returned an unsupported terminal status")
            if run.cost_usd > settings.max_cost:
                raise BudgetError("Apify reported a run cost above the configured hard cap")

            provenance = ApifyProvenance(
                actor_id=self.actor_id,
                requested_build=settings.actor_build,
                build_id=run.build_id,
                build_number=run.build_number,
                run_id=run.run_id,
                dataset_id=run.dataset_id,
            )
            seen: set[str] = set()
            offset = checkpoint.offset
            while resources_read < self.source.max_items:
                limit = min(
                    settings.dataset_page_size,
                    self.source.max_items - resources_read,
                )
                items, total = self._dataset_page(
                    settings,
                    dataset_id=run.dataset_id,
                    offset=offset,
                    limit=limit,
                )
                requests_made += 1
                retrieved_at = utc_timestamp(datetime.now(timezone.utc))
                page_records: list[RawRecord] = []
                for item in items:
                    try:
                        record = self._normalize_item(
                            item,
                            provenance=provenance,
                            retrieved_at=retrieved_at,
                        )
                    except (CollectionError, ConfigurationError):
                        raise
                    except Exception as exc:
                        raise CollectionError(
                            "Apify dataset item failed strict normalization"
                        ) from exc
                    if record is not None and record.native_id not in seen:
                        seen.add(record.native_id)
                        page_records.append(record)
                records.extend(page_records)
                offset += len(items)
                resources_read += len(items)
                checkpoint = ApifyCheckpoint(
                    kind=self.source.type,
                    scope=scope,
                    high_water_at=checkpoint.high_water_at,
                    run_id=run.run_id,
                    dataset_id=run.dataset_id,
                    offset=offset,
                    pending_high_water_at=checkpoint.pending_high_water_at,
                )
                self._save_progress(
                    self._progress(
                        records=records,
                        checkpoint=checkpoint,
                        requests_made=requests_made,
                        resources_read=resources_read,
                        cost=run.cost_usd,
                        stop_reason="dataset_in_progress",
                    )
                )
                if not items or (total is not None and offset >= total) or len(items) < limit:
                    break

            if checkpoint.pending_high_water_at is None:
                raise ConfigurationError("Apify checkpoint lost its pending high-water mark")
            completed = ApifyCheckpoint(
                kind=self.source.type,
                scope=scope,
                high_water_at=checkpoint.pending_high_water_at,
            )
            return self._progress(
                records=records,
                checkpoint=completed,
                requests_made=requests_made,
                resources_read=resources_read,
                cost=run.cost_usd,
                stop_reason="complete",
            )
        except PartialCollectionError:
            raise
        except (BudgetError, CollectionError, ConfigurationError) as exc:
            if checkpoint.run_id is None:
                raise
            partial = self._progress(
                records=records,
                checkpoint=checkpoint,
                requests_made=requests_made,
                resources_read=resources_read,
                cost=run.cost_usd if "run" in locals() else Decimal("0"),
                stop_reason="partial_error",
            )
            raise PartialCollectionError(
                "Apify collection failed after a run was safely checkpointed", partial
            ) from exc


__all__ = [
    "APIFY_ACTORS",
    "APIFY_ORIGIN",
    "ApifyCheckpoint",
    "ApifyProvenance",
    "ApifySettings",
    "ApifySocialConnector",
    "bounded_integer",
    "bounded_string_list",
    "finite_engagement",
    "scalar_metadata",
    "social_url",
    "utc_timestamp",
]
