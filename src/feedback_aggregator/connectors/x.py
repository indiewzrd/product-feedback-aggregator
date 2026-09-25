"""Read-only collection from X through the official X API.

This connector intentionally has no scraping, browser, syndication-feed, or
guest-token fallback.  It uses the same injected transport contract documented
in :mod:`feedback_aggregator.connectors.reddit`: ``request(method, url,
headers=..., body=None, allow_redirects=False)`` returning an object with
``status``, ``headers`` and ``body``.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from urllib.parse import quote, urlencode

from ..errors import BudgetError, CollectionError, ConfigurationError, PartialCollectionError
from ..models import CheckItem, CollectionPlan, CollectionResult, RawRecord
from ..util import pseudonymize_author, sanitize_text
from .base import Connector, connector_note
from .json_file import strict_json_loads
from .social_state import (
    CURSOR_HISTORY_LIMIT,
    XCheckpoint,
    checkpoint_scope,
    cursor_fingerprint,
    newest_x_id,
)

API_ORIGIN = "https://api.x.com"
RECENT_SEARCH_PATH = "/2/tweets/search/recent"
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_POST_ID = re.compile(r"^[0-9]{1,19}$")
_CURSOR = re.compile(r"^[A-Za-z0-9._~-]{1,2048}$")


@dataclass(frozen=True, slots=True)
class _Settings:
    bearer_token: str
    mode: str
    query: str
    user_id: str
    minimum_page_size: int
    page_size: int
    max_pages: int
    max_cost: Decimal
    unit_cost: Decimal
    sort_order: str


@dataclass(frozen=True, slots=True)
class _Page:
    records: tuple[RawRecord, ...]
    resources_read: int
    cost: Decimal
    next_token: str | None


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{name} must be an integer")
    result = value
    if not minimum <= result <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return result


def _positive_decimal(value: object, name: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ConfigurationError(f"{name} must be a positive decimal amount") from exc
    if not result.is_finite() or result <= 0:
        raise ConfigurationError(f"{name} must be greater than zero")
    return result


def _env_name(options: Mapping[str, Any], key: str, default: str) -> str:
    value = options.get(key, default)
    if not isinstance(value, str) or not _ENV_NAME.fullmatch(value):
        raise ConfigurationError(f"X options.{key} must name an uppercase environment variable")
    return value


def _now_and_expiry(hours: int) -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return (
        now.isoformat().replace("+00:00", "Z"),
        (now + timedelta(hours=hours)).isoformat().replace("+00:00", "Z"),
    )


def _created_at(value: object, fallback: str) -> str:
    if not isinstance(value, str) or len(value) > 64:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    if parsed.tzinfo is None:
        return fallback
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _headers(response: object) -> dict[str, str]:
    raw = getattr(response, "headers", {})
    if not isinstance(raw, Mapping):
        return {}
    return {str(key).lower(): str(value) for key, value in raw.items()}


def _response_json(response: object, *, maximum: int) -> Any:
    body = getattr(response, "body", None)
    if body is not None:
        if isinstance(body, str):
            encoded = body.encode("utf-8")
        elif isinstance(body, (bytes, bytearray)):
            encoded = bytes(body)
        else:
            raise CollectionError("X returned an unreadable response")
        if len(encoded) > maximum:
            raise CollectionError("X response exceeded the configured size limit")
        try:
            return strict_json_loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CollectionError("X returned invalid JSON") from exc

    json_method = getattr(response, "json", None)
    if callable(json_method):
        try:
            return json_method()
        except Exception:
            raise CollectionError("X returned invalid JSON") from None
    text_method = getattr(response, "text", None)
    if callable(text_method):
        try:
            text = text_method()
        except Exception:
            raise CollectionError("X returned an unreadable response") from None
        if not isinstance(text, str) or len(text.encode("utf-8")) > maximum:
            raise CollectionError("X response exceeded the configured size limit")
        try:
            return strict_json_loads(text)
        except ValueError as exc:
            raise CollectionError("X returned invalid JSON") from exc
    raise CollectionError("X transport returned no response body")


def _status_error(status: int, headers: Mapping[str, str]) -> CollectionError:
    if status == 401:
        return CollectionError("X authentication failed (HTTP 401)")
    if status == 403:
        return CollectionError(
            "X denied API access; verify app approval and product access (HTTP 403)"
        )
    if status == 429:
        reset = headers.get("x-rate-limit-reset")
        suffix = f"; reset at Unix time {reset}" if reset and reset.isdigit() else ""
        return CollectionError(f"X rate limit reached (HTTP 429){suffix}")
    return CollectionError(f"X API request failed (HTTP {status})")


def _engagement(value: object) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}
    allowed = {
        "retweet_count": "reposts",
        "reply_count": "replies",
        "like_count": "likes",
        "quote_count": "quotes",
        "bookmark_count": "bookmarks",
        "impression_count": "impressions",
    }
    result: dict[str, float] = {}
    for source_name, output_name in allowed.items():
        raw = value.get(source_name)
        if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
            continue
        try:
            number = float(raw)
        except (TypeError, ValueError):
            continue
        if math.isfinite(number) and 0 <= number <= 1_000_000_000_000:
            result[output_name] = number
    return result


class XConnector(Connector):
    """Collect recent search results or a public mentions timeline from X."""

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        self.last_rate_limit: dict[str, int] = {}

    def _query(self, mode: str) -> str:
        if mode == "mentions":
            return ""
        raw = self.source.options.get("query")
        if raw is None:
            terms = (
                self.config.product.name,
                *self.config.product.aliases,
                *self.config.product.terms,
            )
            clean = [sanitize_text(term, max_chars=128).replace('"', "") for term in terms]
            raw = " OR ".join(f'"{term}"' for term in clean if term)
            exclusions = [
                sanitize_text(term, max_chars=64).replace('"', "")
                for term in self.config.product.exclusions
            ]
            if exclusions:
                raw += " " + " ".join(f'-"{term}"' for term in exclusions if term)
        if not isinstance(raw, str):
            raise ConfigurationError("X options.query must be a string")
        query = sanitize_text(raw, max_chars=513)
        if not query:
            raise ConfigurationError("X recent search query must not be empty")
        if query != raw.strip() or len(query) > 512:
            raise ConfigurationError(
                "X recent search query must be at most 512 characters and contain no controls"
            )
        return query

    def _settings(self, *, require_secret: bool = True) -> _Settings:
        options = self.source.options
        if options.get("approval_confirmed") is not True:
            raise ConfigurationError(
                "X options.approval_confirmed must be true for an approved developer app"
            )
        env_name = _env_name(options, "bearer_token_env", "X_BEARER_TOKEN")
        bearer_token = (
            os.environ.get(env_name, "")
            if require_secret
            else os.environ.get(env_name, "placeholder")
        )
        if require_secret:
            if not bearer_token:
                raise ConfigurationError(
                    f"X bearer-token environment variable {env_name} is not set"
                )
            if len(bearer_token) > 8192 or any(
                character in bearer_token for character in "\r\n\x00"
            ):
                raise ConfigurationError(
                    f"X bearer-token environment variable {env_name} is invalid"
                )

        raw_mode = options.get("mode", "recent_search")
        if raw_mode not in {"recent", "recent_search", "mentions"}:
            raise ConfigurationError("X options.mode must be recent_search or mentions")
        mode = "recent_search" if raw_mode in {"recent", "recent_search"} else "mentions"
        user_id = ""
        if mode == "mentions":
            user_id = str(options.get("user_id", ""))
            if not _POST_ID.fullmatch(user_id):
                raise ConfigurationError(
                    "X options.user_id must be a numeric user ID for mentions mode"
                )

        minimum_page_size = 10 if mode == "recent_search" else 5
        # A smaller record cap could only be honored by fetching and then
        # silently skipping paid rows from the platform's minimum-size page.
        if self.source.max_items < minimum_page_size:
            raise ConfigurationError(
                f"X max_items must be at least {minimum_page_size} for {mode} mode"
            )
        max_cost = _positive_decimal(self.source.policy.max_cost_usd, "X policy.max_cost_usd")
        # X prices may change.  Requiring an explicitly versioned policy value
        # avoids silently treating today's list price as a permanent constant.
        unit_cost = _positive_decimal(
            self.source.policy.cost_per_resource_usd,
            "X policy.cost_per_resource_usd",
        )
        sort_order = options.get("sort_order", "recency")
        if sort_order not in {"recency", "relevancy"}:
            raise ConfigurationError("X options.sort_order must be recency or relevancy")
        return _Settings(
            bearer_token=bearer_token,
            mode=str(mode),
            query=self._query(str(mode)),
            user_id=user_id,
            minimum_page_size=minimum_page_size,
            page_size=_integer(
                options.get("page_size", 100),
                "X options.page_size",
                minimum_page_size,
                100,
            ),
            max_pages=_integer(options.get("max_pages", 100), "X options.max_pages", 1, 1000),
            max_cost=max_cost,
            unit_cost=unit_cost,
            sort_order=str(sort_order),
        )

    def _checkpoint_scope(self, settings: _Settings) -> str:
        return checkpoint_scope(
            "x",
            {
                "author_salt": self.context.author_salt,
                "mode": settings.mode,
                "query": settings.query,
                "sort_order": settings.sort_order,
                "user_id": settings.user_id,
            },
        )

    def check(self, *, probe: bool = False) -> list[CheckItem]:
        del probe  # A probe could incur resource charges, so readiness is local-only.
        try:
            settings = self._settings(require_secret=True)
            minimum_page_cost = Decimal(settings.minimum_page_size) * settings.unit_cost
            if settings.max_cost < minimum_page_cost:
                raise ConfigurationError(
                    "X policy.max_cost_usd must cover one minimum-size page "
                    f"({minimum_page_cost} USD)"
                )
        except ConfigurationError as exc:
            return [connector_note(self.context, str(exc), "error")]
        return [
            connector_note(
                self.context,
                "Approved X API bearer token and explicit per-invocation spend limit are configured",
            )
        ]

    def plan(self) -> CollectionPlan:
        settings = self._settings(require_secret=False)
        estimated_pages = min(
            settings.max_pages,
            max(1, math.ceil(self.source.max_items / settings.page_size)),
        )
        worst_case = min(
            settings.max_cost, Decimal(estimated_pages * settings.page_size) * settings.unit_cost
        )
        query = (
            settings.query if settings.mode == "recent_search" else f"mentions:{settings.user_id}"
        )
        return CollectionPlan(
            self.source.id,
            self.source.type,
            query,
            self.source.max_items,
            estimated_pages,
            float(worst_case),
            (
                "Official X API only; no scraping fallback",
                f"Each page is budget-reserved at {settings.unit_cost} USD per returned Post",
                "max_cost_usd is enforced per collection invocation; monitor cumulative API spend",
                "No expansions are requested; raw records expire after at most 24 hours",
            ),
        )

    def _request(self, url: str, *, headers: Mapping[str, str]) -> object:
        transport = self.context.http
        if transport is None or not callable(getattr(transport, "request", None)):
            raise ConfigurationError("X requires an injected official-API HTTP transport")
        try:
            return transport.request(
                "GET",
                url,
                headers=headers,
                body=None,
                allow_redirects=False,
            )
        except (BudgetError, CollectionError, ConfigurationError):
            raise
        except Exception:
            raise CollectionError("X request could not be completed safely") from None

    def _observe_rate_limit(self, response: object) -> dict[str, int]:
        observed: dict[str, int] = {}
        headers = _headers(response)
        for header, name in (
            ("x-rate-limit-limit", "limit"),
            ("x-rate-limit-remaining", "remaining"),
            ("x-rate-limit-reset", "reset_unix"),
        ):
            try:
                value = int(headers[header])
            except (KeyError, TypeError, ValueError):
                continue
            if value >= 0:
                observed[name] = value
        if observed:
            self.last_rate_limit = observed
        return dict(self.last_rate_limit)

    def _record(
        self,
        item: Mapping[str, Any],
        *,
        settings: _Settings,
        retrieved_at: str,
        expires_at: str,
        rate_limit: Mapping[str, int],
    ) -> RawRecord:
        post_id = item.get("id")
        text = sanitize_text(item.get("text"), max_chars=200_000)
        if not isinstance(post_id, str) or not _POST_ID.fullmatch(post_id) or not text:
            raise CollectionError("X returned a Post with an invalid ID or empty text")
        metadata: dict[str, Any] = {
            "kind": "post",
            "mode": settings.mode,
            "rate_limit": dict(rate_limit),
        }
        created_at = _created_at(item.get("created_at"), retrieved_at)
        metadata["created_at_inferred"] = created_at == retrieved_at
        for key in ("conversation_id", "lang"):
            value = item.get(key)
            if isinstance(value, str) and len(value) <= 128:
                metadata[key] = sanitize_text(value, max_chars=128)
        return RawRecord(
            source_id=self.source.id,
            source_type="x",
            native_id=post_id,
            canonical_url=f"https://x.com/i/web/status/{quote(post_id, safe='')}",
            text=text,
            created_at=created_at,
            retrieved_at=retrieved_at,
            author_key=pseudonymize_author("x", item.get("author_id"), self.context.author_salt),
            engagement=_engagement(item.get("public_metrics")),
            metadata=metadata,
            query=settings.query,
            acquisition_mode="official_api",
            policy_assurance="approved_operator_app",
            expires_at=expires_at,
        )

    def _page(
        self,
        *,
        settings: _Settings,
        headers: Mapping[str, str],
        params: Mapping[str, str],
        path: str,
        requested: int,
        retrieved_at: str,
        expires_at: str,
    ) -> _Page:
        """Fetch and fully validate one page before the checkpoint can move."""

        response = self._request(f"{API_ORIGIN}{path}?{urlencode(params)}", headers=headers)
        status = int(getattr(response, "status", 0))
        response_headers = _headers(response)
        if not 200 <= status < 300:
            raise _status_error(status, response_headers)
        rate_limit = self._observe_rate_limit(response)
        value = _response_json(response, maximum=self.config.limits.max_decompressed_bytes)
        if not isinstance(value, dict):
            raise CollectionError("X response had an invalid shape")
        if value.get("errors") not in (None, []):
            raise CollectionError("X returned a partial response with unresolved errors")
        meta = value.get("meta")
        if not isinstance(meta, dict):
            raise CollectionError("X response metadata had an invalid shape")
        result_count = meta.get("result_count")
        if isinstance(result_count, bool) or not isinstance(result_count, int):
            raise CollectionError("X response metadata omitted a valid result count")
        if not 0 <= result_count <= requested:
            raise CollectionError("X response result count exceeded the requested page limit")
        raw_data = value.get("data")
        if raw_data is None and result_count == 0:
            raw_data = []
        if not isinstance(raw_data, list) or not all(
            isinstance(item, dict) for item in raw_data
        ):
            raise CollectionError("X response data had an invalid shape")
        if len(raw_data) != result_count:
            raise CollectionError("X response data did not match its result count")

        page_records = tuple(
            self._record(
                item,
                settings=settings,
                retrieved_at=retrieved_at,
                expires_at=expires_at,
                rate_limit=rate_limit,
            )
            for item in raw_data
        )
        raw_cursor = meta.get("next_token")
        if raw_cursor is None:
            next_token = None
        elif not isinstance(raw_cursor, str) or _CURSOR.fullmatch(raw_cursor) is None:
            raise CollectionError("X returned an invalid pagination cursor")
        else:
            next_token = raw_cursor
        return _Page(
            records=page_records,
            resources_read=result_count,
            cost=Decimal(result_count) * settings.unit_cost,
            next_token=next_token,
        )

    def collect(self, *, cursor: str | None = None) -> CollectionResult:
        settings = self._settings(require_secret=True)
        checkpoint = XCheckpoint.decode(cursor, scope=self._checkpoint_scope(settings))
        if checkpoint.halted_reason is not None:
            raise CollectionError(
                "X checkpoint is halted after unsafe pagination behavior; "
                "purge this source before collecting again"
            )
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {settings.bearer_token}",
            "User-Agent": "product-feedback-aggregator/0.1 (official X API client)",
        }
        retention_hours = min(
            24,
            self.source.policy.raw_ttl_hours,
            self.source.policy.deletion_reconcile_interval_hours,
        )
        retrieved_at, expires_at = _now_and_expiry(retention_hours)
        records: list[RawRecord] = []
        seen_ids: set[str] = set()
        cursor_fingerprints = list(checkpoint.cursor_fingerprints)
        seen_cursors = set(cursor_fingerprints)
        next_token = checkpoint.next_token
        pending_since_id = checkpoint.pending_since_id
        spent = Decimal("0")
        resources_read = 0
        requests_made = 0
        last_safe_result: CollectionResult | None = None

        def saved_checkpoint(
            *, complete: bool = False, halted_reason: str | None = None
        ) -> str:
            if complete:
                return XCheckpoint(
                    scope=checkpoint.scope,
                    since_id=newest_x_id(checkpoint.since_id, pending_since_id),
                ).encode()
            return XCheckpoint(
                scope=checkpoint.scope,
                since_id=checkpoint.since_id,
                next_token=next_token,
                pending_since_id=pending_since_id,
                cursor_fingerprints=tuple(cursor_fingerprints),
                halted_reason=halted_reason,
            ).encode()

        for _page_number in range(settings.max_pages):
            if resources_read >= self.source.max_items:
                return CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(),
                    requests_made=requests_made,
                    resources_read=resources_read,
                    cost_usd=float(spent),
                    stop_reason="item_cap",
                )

            remaining_items = self.source.max_items - resources_read
            # Never request the platform minimum when fewer resources remain:
            # its next_token would point beyond paid rows we had to drop.
            if remaining_items < settings.minimum_page_size:
                return CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(),
                    requests_made=requests_made,
                    resources_read=resources_read,
                    cost_usd=float(spent),
                    stop_reason="item_cap",
                )
            requested = min(settings.page_size, remaining_items)
            reservation = Decimal(requested) * settings.unit_cost
            if spent + reservation > settings.max_cost:
                if requests_made == 0:
                    raise BudgetError(
                        "X spend limit cannot reserve the first requested page; raise max_cost_usd or lower page_size"
                    )
                return CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(),
                    requests_made=requests_made,
                    resources_read=resources_read,
                    cost_usd=float(spent),
                    stop_reason="cost_cap",
                )

            params: dict[str, str] = {
                "max_results": str(requested),
                "post.fields": "author_id,conversation_id,created_at,lang,public_metrics",
            }
            if settings.mode == "recent_search":
                path = RECENT_SEARCH_PATH
                params["query"] = settings.query
                params["sort_order"] = settings.sort_order
            else:
                path = f"/2/users/{quote(settings.user_id, safe='')}/mentions"
            if checkpoint.since_id:
                params["since_id"] = checkpoint.since_id
            if next_token:
                params["pagination_token"] = next_token

            try:
                page = self._page(
                    settings=settings,
                    headers=headers,
                    params=params,
                    path=path,
                    requested=requested,
                    retrieved_at=retrieved_at,
                    expires_at=expires_at,
                )
            except (BudgetError, CollectionError) as error:
                if last_safe_result is None:
                    raise
                raise PartialCollectionError(
                    f"X collection stopped after safely checkpointed pages: {error}",
                    last_safe_result,
                ) from error
            requests_made += 1
            # X bills returned resources.  The reservation was checked before
            # network I/O; charge the actual page after its bounded response.
            spent += page.cost
            resources_read += page.resources_read
            for record in page.records:
                if record.native_id not in seen_ids:
                    records.append(record)
                    seen_ids.add(record.native_id)
                pending_since_id = newest_x_id(pending_since_id, record.native_id)
            next_token = page.next_token

            if next_token is None:
                return CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(complete=True),
                    requests_made=requests_made,
                    resources_read=resources_read,
                    cost_usd=float(spent),
                )
            fingerprint = cursor_fingerprint(next_token)
            if fingerprint in seen_cursors:
                blocked_result = CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(halted_reason="repeated_cursor"),
                    requests_made=requests_made,
                    resources_read=resources_read,
                    cost_usd=float(spent),
                    stop_reason="partial_error",
                )
                raise PartialCollectionError(
                    "X pagination repeated a cursor; the checkpoint was halted to prevent "
                    "another billable request",
                    blocked_result,
                )
            if len(cursor_fingerprints) >= CURSOR_HISTORY_LIMIT:
                blocked_result = CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(halted_reason="cursor_history_limit"),
                    requests_made=requests_made,
                    resources_read=resources_read,
                    cost_usd=float(spent),
                    stop_reason="partial_error",
                )
                raise PartialCollectionError(
                    "X pagination exceeded its bounded cursor history; the checkpoint "
                    "was halted to prevent an unverified request",
                    blocked_result,
                )
            cursor_fingerprints.append(fingerprint)
            seen_cursors.add(fingerprint)

            last_safe_result = CollectionResult.from_records(
                records,
                cursor=saved_checkpoint(),
                requests_made=requests_made,
                resources_read=resources_read,
                cost_usd=float(spent),
                stop_reason="partial_error",
            )
            if resources_read >= self.source.max_items:
                return CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(),
                    requests_made=requests_made,
                    resources_read=resources_read,
                    cost_usd=float(spent),
                    stop_reason="item_cap",
                )

        return CollectionResult.from_records(
            records,
            cursor=saved_checkpoint(),
            requests_made=requests_made,
            resources_read=resources_read,
            cost_usd=float(spent),
            stop_reason="page_cap",
        )


__all__ = ["XConnector"]
