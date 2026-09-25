"""Read-only Reddit collection through Reddit's approved OAuth API.

There is deliberately no HTML, RSS, browser, or unauthenticated fallback in
this module.  Operators must supply credentials for an approved Reddit app.

``ConnectorContext.http`` is a deliberately tiny injected transport.  It must
provide this method::

    request(method, url, *, headers, body=None, allow_redirects=False)

The returned object must expose ``status``, ``headers`` and ``body`` (bytes).
For simple test adapters, a ``json()`` or ``text()`` method is accepted in
place of ``body``.  The production transport is responsible for TLS, DNS and
bounded response reads; this connector fixes the destination origins and
forbids redirects so credentials cannot cross an origin boundary.
"""

from __future__ import annotations

import base64
import math
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol
from urllib.parse import quote, urlencode

from ..errors import CollectionError, ConfigurationError, PartialCollectionError
from ..models import CheckItem, CollectionPlan, CollectionResult, RawRecord
from ..util import pseudonymize_author, sanitize_text
from .base import Connector, connector_note
from .json_file import strict_json_loads
from .social_state import (
    CURSOR_HISTORY_LIMIT,
    REDDIT_COMMENT_BACKLOG_LIMIT,
    RedditCheckpoint,
    checkpoint_scope,
    cursor_fingerprint,
)

TOKEN_URL = "https://www.reddit.com/api/v1/access_token"  # noqa: S105 - public endpoint
API_ORIGIN = "https://oauth.reddit.com"
PUBLIC_ORIGIN = "https://www.reddit.com"

_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_SUBREDDIT = re.compile(r"^[A-Za-z0-9_]{2,21}$")
_REDDIT_ID = re.compile(r"^[A-Za-z0-9]{1,252}$")
_FULLNAME = re.compile(r"^t[13]_[A-Za-z0-9]{1,252}$")
_USER_AGENT = re.compile(
    r"^(?P<platform>[A-Za-z0-9._-]{1,32}):"
    r"(?P<app>[A-Za-z0-9._-]{2,128}):"
    r"(?P<version>[A-Za-z0-9._-]{1,32}) "
    r"\(by /u/(?P<user>[A-Za-z0-9_-]{3,20})\)$"
)


class SocialResponse(Protocol):
    """Minimum response surface accepted from an injected transport."""

    status: int
    headers: Mapping[str, str]
    body: bytes


class SocialHttpTransport(Protocol):
    """Transport boundary used by official social connectors."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
        allow_redirects: bool = False,
    ) -> SocialResponse: ...


@dataclass(frozen=True, slots=True)
class _Settings:
    client_id: str
    client_secret: str
    user_agent: str
    query: str
    subreddits: tuple[str, ...]
    page_size: int
    max_pages: int
    max_comments_per_post: int
    comment_depth: int
    sort: str
    time_filter: str


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{name} must be an integer")
    result = value
    if not minimum <= result <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return result


def _env_name(options: Mapping[str, Any], key: str, default: str) -> str:
    value = options.get(key, default)
    if not isinstance(value, str) or not _ENV_NAME.fullmatch(value):
        raise ConfigurationError(f"options.{key} must name an uppercase environment variable")
    return value


def _secret_from_env(options: Mapping[str, Any], key: str, default: str, label: str) -> str:
    name = _env_name(options, key, default)
    value = os.environ.get(name, "")
    if not value:
        raise ConfigurationError(f"{label} environment variable {name} is not set")
    if len(value) > 4096 or any(character in value for character in "\r\n\x00"):
        raise ConfigurationError(f"{label} environment variable {name} is invalid")
    return value


def _utc_timestamp(value: object, fallback: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return fallback
    try:
        moment = datetime.fromtimestamp(float(value), timezone.utc)
    except (OSError, OverflowError, TypeError, ValueError):
        return fallback
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _now_and_expiry(hours: int) -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    return (
        now.isoformat().replace("+00:00", "Z"),
        (now + timedelta(hours=hours)).isoformat().replace("+00:00", "Z"),
    )


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
            raise CollectionError("Reddit returned an unreadable response")
        if len(encoded) > maximum:
            raise CollectionError("Reddit response exceeded the configured size limit")
        try:
            return strict_json_loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise CollectionError("Reddit returned invalid JSON") from exc

    json_method = getattr(response, "json", None)
    if callable(json_method):
        try:
            return json_method()
        except Exception:
            raise CollectionError("Reddit returned invalid JSON") from None
    text_method = getattr(response, "text", None)
    if callable(text_method):
        try:
            text = text_method()
        except Exception:
            raise CollectionError("Reddit returned an unreadable response") from None
        if not isinstance(text, str) or len(text.encode("utf-8")) > maximum:
            raise CollectionError("Reddit response exceeded the configured size limit")
        try:
            return strict_json_loads(text)
        except ValueError as exc:
            raise CollectionError("Reddit returned invalid JSON") from exc
    raise CollectionError("Reddit transport returned no response body")


def _status_error(platform: str, status: int, headers: Mapping[str, str]) -> CollectionError:
    if status == 401:
        return CollectionError(f"{platform} authentication failed (HTTP 401)")
    if status == 403:
        return CollectionError(
            f"{platform} denied API access; verify app approval and scope (HTTP 403)"
        )
    if status == 429:
        retry = headers.get("retry-after") or headers.get("x-ratelimit-reset")
        suffix = f"; retry after {retry} seconds" if retry and retry.isdigit() else ""
        return CollectionError(f"{platform} rate limit reached (HTTP 429){suffix}")
    return CollectionError(f"{platform} API request failed (HTTP {status})")


def _safe_permalink(value: object, fallback: str) -> str:
    path = sanitize_text(value, max_chars=4096)
    if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
        path = fallback
    return f"{PUBLIC_ORIGIN}{path}"


def _engagement(**values: object) -> dict[str, float]:
    result: dict[str, float] = {}
    for key, value in values.items():
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(number) and 0 <= number <= 1_000_000_000:
            result[key] = number
    return result


class RedditConnector(Connector):
    """Collect Reddit posts and their bounded comment trees via OAuth."""

    def __init__(self, context: Any) -> None:
        super().__init__(context)
        self.last_rate_limit: dict[str, float] = {}

    def _query(self) -> str:
        raw = self.source.options.get("query")
        if raw is None:
            terms = (
                self.config.product.name,
                *self.config.product.aliases,
                *self.config.product.terms,
            )
            clean = [sanitize_text(term, max_chars=128) for term in terms]
            raw = " OR ".join(f'"{term.replace(chr(34), "")}"' for term in clean if term)
        if not isinstance(raw, str):
            raise ConfigurationError("Reddit options.query must be a string")
        query = sanitize_text(raw, max_chars=513)
        if not query:
            raise ConfigurationError("Reddit query must not be empty")
        if query != raw.strip() or len(query) > 512:
            raise ConfigurationError(
                "Reddit query must be at most 512 characters and contain no controls"
            )
        return query

    def _settings(self, *, require_secrets: bool = True) -> _Settings:
        options = self.source.options
        if options.get("approval_confirmed") is not True:
            raise ConfigurationError(
                "Reddit options.approval_confirmed must be true for an approved app"
            )

        client_id_name = _env_name(options, "client_id_env", "REDDIT_CLIENT_ID")
        client_secret_name = _env_name(options, "client_secret_env", "REDDIT_CLIENT_SECRET")
        client_id = (
            os.environ.get(client_id_name, "")
            if require_secrets
            else os.environ.get(client_id_name, "placeholder")
        )
        client_secret = (
            os.environ.get(client_secret_name, "")
            if require_secrets
            else os.environ.get(client_secret_name, "placeholder")
        )
        if require_secrets:
            client_id = _secret_from_env(
                options, "client_id_env", "REDDIT_CLIENT_ID", "Reddit client ID"
            )
            client_secret = _secret_from_env(
                options, "client_secret_env", "REDDIT_CLIENT_SECRET", "Reddit client secret"
            )
        if ":" in client_id or len(client_id) > 128:
            raise ConfigurationError("Reddit client ID is invalid")

        user_agent = options.get("user_agent")
        if not isinstance(user_agent, str):
            raise ConfigurationError("Reddit options.user_agent is required")
        match = _USER_AGENT.fullmatch(user_agent)
        if match is None:
            raise ConfigurationError(
                "Reddit user agent must use <platform>:<app-id>:<version> (by /u/<username>)"
            )
        # Reddit calls this component the app ID, but operator-facing examples
        # commonly use the registered app name rather than the OAuth client ID.
        # We can validate the required truthful shape; only Reddit can attest
        # that the registered label and username belong to the operator.

        raw_subreddits = options.get("subreddits")
        if not isinstance(raw_subreddits, list) or not raw_subreddits:
            raise ConfigurationError("Reddit options.subreddits must be a non-empty list")
        subreddits: list[str] = []
        for value in raw_subreddits:
            if not isinstance(value, str) or (value != "all" and not _SUBREDDIT.fullmatch(value)):
                raise ConfigurationError(
                    "Reddit subreddit names may contain only letters, digits, and underscores"
                )
            if value.lower() not in {item.lower() for item in subreddits}:
                subreddits.append(value)
        if len(subreddits) > 50:
            raise ConfigurationError("Reddit accepts at most 50 configured subreddits")

        sort = options.get("sort", "new")
        if sort != "new":
            raise ConfigurationError(
                "Reddit options.sort must be new so incremental checkpoints cannot miss posts"
            )
        time_filter = options.get("time_filter", "all")
        if time_filter not in {"hour", "day", "week", "month", "year", "all"}:
            raise ConfigurationError("Reddit options.time_filter is invalid")

        return _Settings(
            client_id=client_id,
            client_secret=client_secret,
            user_agent=user_agent,
            query=self._query(),
            subreddits=tuple(subreddits),
            page_size=_integer(options.get("page_size", 25), "Reddit options.page_size", 1, 100),
            max_pages=_integer(options.get("max_pages", 20), "Reddit options.max_pages", 1, 1000),
            max_comments_per_post=_integer(
                options.get("max_comments_per_post", 50),
                "Reddit options.max_comments_per_post",
                0,
                500,
            ),
            comment_depth=_integer(
                options.get("comment_depth", 8), "Reddit options.comment_depth", 1, 10
            ),
            sort=str(sort),
            time_filter=str(time_filter),
        )

    def _checkpoint_scope(self, settings: _Settings) -> str:
        return checkpoint_scope(
            "reddit",
            {
                "author_salt": self.context.author_salt,
                "comment_depth": settings.comment_depth,
                "max_comments_per_post": settings.max_comments_per_post,
                "query": settings.query,
                "sort": settings.sort,
                "subreddits": list(settings.subreddits),
                "time_filter": settings.time_filter,
            },
        )

    def check(self, *, probe: bool = False) -> list[CheckItem]:
        del probe  # A readiness check never creates a token or performs collection.
        try:
            self._settings(require_secrets=True)
        except ConfigurationError as exc:
            return [connector_note(self.context, str(exc), "error")]
        return [
            connector_note(
                self.context,
                "Approved Reddit OAuth app, scoped subreddits, and truthful user agent are configured",
            )
        ]

    def plan(self) -> CollectionPlan:
        settings = self._settings(require_secrets=False)
        requests = (
            1
            + settings.max_pages
            + min(
                self.source.max_items,
                settings.max_pages * settings.page_size,
            )
        )
        return CollectionPlan(
            self.source.id,
            self.source.type,
            settings.query,
            self.source.max_items,
            requests,
            0.0,
            (
                "Official approved Reddit OAuth API only; no scraping fallback",
                f"Subreddits: {', '.join(settings.subreddits)}",
                "Comments are a bounded snapshot when each matching post is processed",
                "Raw records expire after at most 48 hours",
            ),
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
    ) -> object:
        transport = self.context.http
        if transport is None or not callable(getattr(transport, "request", None)):
            raise ConfigurationError("Reddit requires an injected official-API HTTP transport")
        try:
            return transport.request(
                method,
                url,
                headers=headers,
                body=body,
                allow_redirects=False,
            )
        except (CollectionError, ConfigurationError):
            raise
        except Exception:
            raise CollectionError("Reddit request could not be completed safely") from None

    def _observe_rate_limit(self, response: object) -> dict[str, float]:
        observed: dict[str, float] = {}
        headers = _headers(response)
        for header, name in (
            ("x-ratelimit-used", "used"),
            ("x-ratelimit-remaining", "remaining"),
            ("x-ratelimit-reset", "reset_seconds"),
        ):
            try:
                value = float(headers[header])
            except (KeyError, TypeError, ValueError):
                continue
            if math.isfinite(value) and value >= 0:
                observed[name] = value
        if observed:
            self.last_rate_limit = observed
        return dict(self.last_rate_limit)

    def _token(self, settings: _Settings) -> tuple[str, int]:
        basic = base64.b64encode(
            f"{settings.client_id}:{settings.client_secret}".encode("utf-8")
        ).decode("ascii")
        response = self._request(
            "POST",
            TOKEN_URL,
            headers={
                "Accept": "application/json",
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": settings.user_agent,
            },
            body=urlencode({"grant_type": "client_credentials"}).encode("ascii"),
        )
        status = int(getattr(response, "status", 0))
        headers = _headers(response)
        if not 200 <= status < 300:
            raise _status_error("Reddit", status, headers)
        value = _response_json(response, maximum=self.config.limits.max_decompressed_bytes)
        if not isinstance(value, dict):
            raise CollectionError("Reddit token response had an invalid shape")
        token = value.get("access_token")
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 4096
            or any(c in token for c in "\r\n\x00")
        ):
            raise CollectionError("Reddit token response did not contain a valid access token")
        return token, 1

    @staticmethod
    def _listing(value: object) -> tuple[list[dict[str, Any]], str | None]:
        if (
            not isinstance(value, dict)
            or value.get("kind") != "Listing"
            or not isinstance(value.get("data"), dict)
        ):
            raise CollectionError("Reddit listing response had an invalid shape")
        data = value["data"]
        if "children" not in data or "after" not in data:
            raise CollectionError("Reddit listing response omitted required fields")
        raw_children = data["children"]
        if not isinstance(raw_children, list):
            raise CollectionError("Reddit listing children had an invalid shape")
        if not all(isinstance(child, dict) for child in raw_children):
            raise CollectionError("Reddit listing contained an invalid child")
        children = list(raw_children)
        after = data["after"]
        if after is not None and (
            not isinstance(after, str) or len(after) > 256 or not _FULLNAME.fullmatch(after)
        ):
            raise CollectionError("Reddit listing returned an invalid pagination cursor")
        return children, after

    @staticmethod
    def _post_fullname(child: Mapping[str, Any]) -> str | None:
        if child.get("kind") != "t3" or not isinstance(child.get("data"), dict):
            return None
        data = child["data"]
        reddit_id = data.get("id")
        if not isinstance(reddit_id, str) or not _REDDIT_ID.fullmatch(reddit_id):
            return None
        fullname = data.get("name", f"t3_{reddit_id}")
        if (
            not isinstance(fullname, str)
            or not _FULLNAME.fullmatch(fullname)
            or not fullname.startswith("t3_")
        ):
            return f"t3_{reddit_id}"
        return fullname

    def _post_record(
        self,
        child: Mapping[str, Any],
        *,
        settings: _Settings,
        retrieved_at: str,
        expires_at: str,
        rate_limit: Mapping[str, float],
    ) -> RawRecord | None:
        fullname = self._post_fullname(child)
        if fullname is None:
            return None
        data = child["data"]
        reddit_id = data["id"]
        title = sanitize_text(data.get("title"), max_chars=20_000)
        body = sanitize_text(data.get("selftext"), max_chars=180_000)
        text = "\n\n".join(part for part in (title, body) if part)
        if not text:
            return None
        fallback = f"/comments/{quote(reddit_id, safe='')}"
        metadata: dict[str, Any] = {
            "kind": "post",
            "fullname": fullname,
            "subreddit": sanitize_text(data.get("subreddit"), max_chars=64),
            "rate_limit": dict(rate_limit),
        }
        author_label = sanitize_text(data.get("author"), max_chars=128).lower()
        if author_label.endswith("bot") or author_label.endswith("_bot"):
            metadata["automated"] = True
        created_at = _utc_timestamp(data.get("created_utc"), retrieved_at)
        metadata["created_at_inferred"] = created_at == retrieved_at
        return RawRecord(
            source_id=self.source.id,
            source_type="reddit",
            native_id=fullname,
            canonical_url=_safe_permalink(data.get("permalink"), fallback),
            text=text,
            created_at=created_at,
            retrieved_at=retrieved_at,
            author_key=pseudonymize_author("reddit", data.get("author"), self.context.author_salt),
            engagement=_engagement(score=data.get("score"), comments=data.get("num_comments")),
            metadata=metadata,
            query=settings.query,
            acquisition_mode="official_api",
            policy_assurance="approved_operator_app",
            expires_at=expires_at,
        )

    @staticmethod
    def _flatten_comments(value: object, maximum: int) -> list[dict[str, Any]]:
        if not isinstance(value, list) or len(value) != 2:
            raise CollectionError("Reddit comment response had an invalid shape")
        RedditConnector._listing(value[0])
        root = value[1]
        children, _ = RedditConnector._listing(root)
        stack = list(reversed(children))
        comments: list[dict[str, Any]] = []
        traversed = 0
        traversal_limit = max(100, maximum * 20)
        while stack and len(comments) < maximum:
            child = stack.pop()
            traversed += 1
            if traversed > traversal_limit:
                raise CollectionError("Reddit comment tree exceeded its traversal limit")
            if child.get("kind") != "t1" or not isinstance(child.get("data"), dict):
                continue
            data = child["data"]
            comments.append(data)
            replies = data.get("replies")
            if isinstance(replies, dict):
                nested, _ = RedditConnector._listing(replies)
                stack.extend(reversed(nested))
        return comments

    def _comment_record(
        self,
        data: Mapping[str, Any],
        *,
        settings: _Settings,
        post_id: str,
        retrieved_at: str,
        expires_at: str,
        rate_limit: Mapping[str, float],
    ) -> RawRecord | None:
        reddit_id = data.get("id")
        if not isinstance(reddit_id, str) or not _REDDIT_ID.fullmatch(reddit_id):
            return None
        fullname = data.get("name", f"t1_{reddit_id}")
        if (
            not isinstance(fullname, str)
            or not _FULLNAME.fullmatch(fullname)
            or not fullname.startswith("t1_")
        ):
            fullname = f"t1_{reddit_id}"
        text = sanitize_text(data.get("body"), max_chars=200_000)
        if not text or text in {"[deleted]", "[removed]"}:
            return None
        fallback = f"/comments/{quote(post_id, safe='')}/_/{quote(reddit_id, safe='')}"
        metadata: dict[str, Any] = {
            "kind": "comment",
            "fullname": fullname,
            "link_id": sanitize_text(data.get("link_id"), max_chars=256),
            "parent_id": sanitize_text(data.get("parent_id"), max_chars=256),
            "subreddit": sanitize_text(data.get("subreddit"), max_chars=64),
            "rate_limit": dict(rate_limit),
        }
        author_label = sanitize_text(data.get("author"), max_chars=128).lower()
        if author_label.endswith("bot") or author_label.endswith("_bot"):
            metadata["automated"] = True
        created_at = _utc_timestamp(data.get("created_utc"), retrieved_at)
        metadata["created_at_inferred"] = created_at == retrieved_at
        return RawRecord(
            source_id=self.source.id,
            source_type="reddit",
            native_id=fullname,
            canonical_url=_safe_permalink(data.get("permalink"), fallback),
            text=text,
            created_at=created_at,
            retrieved_at=retrieved_at,
            author_key=pseudonymize_author("reddit", data.get("author"), self.context.author_salt),
            engagement=_engagement(score=data.get("score")),
            metadata=metadata,
            query=settings.query,
            acquisition_mode="official_api",
            policy_assurance="approved_operator_app",
            expires_at=expires_at,
        )

    def collect(self, *, cursor: str | None = None) -> CollectionResult:
        safe_results: list[CollectionResult] = []
        try:
            return self._collect(cursor=cursor, safe_results=safe_results)
        except CollectionError as error:
            if not safe_results:
                raise
            raise PartialCollectionError(
                f"Reddit collection stopped after safely checkpointed pages: {error}",
                safe_results[-1],
            ) from error

    def _collect(
        self,
        *,
        cursor: str | None,
        safe_results: list[CollectionResult],
    ) -> CollectionResult:
        settings = self._settings(require_secrets=True)
        checkpoint = RedditCheckpoint.decode(
            cursor,
            scope=self._checkpoint_scope(settings),
            subreddits=settings.subreddits,
        )
        if checkpoint.halted_reason is not None:
            raise CollectionError(
                "Reddit checkpoint is halted after unsafe pagination behavior; "
                "purge this source before collecting again"
            )
        token, requests_made = self._token(settings)
        auth_headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": settings.user_agent,
        }
        retention_hours = min(
            48,
            self.source.policy.raw_ttl_hours,
            self.source.policy.deletion_reconcile_interval_hours,
        )
        retrieved_at, expires_at = _now_and_expiry(retention_hours)
        records: list[RawRecord] = []
        seen_records: set[str] = set()
        pages = 0
        high_water = dict(checkpoint.high_water)
        subreddit_index = checkpoint.resume_subreddit
        after = checkpoint.after
        pending_high_water = checkpoint.pending_high_water
        comment_subreddit = checkpoint.comment_subreddit
        pending_comment_posts = list(checkpoint.pending_comment_posts)
        cursor_fingerprints = list(checkpoint.cursor_fingerprints)
        seen_cursors = set(cursor_fingerprints)
        halted_reason = checkpoint.halted_reason

        def saved_checkpoint() -> str:
            return RedditCheckpoint(
                scope=checkpoint.scope,
                high_water=dict(high_water),
                resume_subreddit=subreddit_index,
                after=after,
                pending_high_water=pending_high_water,
                comment_subreddit=comment_subreddit,
                pending_comment_posts=tuple(pending_comment_posts),
                cursor_fingerprints=tuple(cursor_fingerprints),
                halted_reason=halted_reason,
            ).encode()

        def mark_safe_page() -> None:
            safe_results[:] = [
                CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(),
                    requests_made=requests_made,
                    resources_read=len(records),
                    stop_reason="partial_error",
                )
            ]

        def process_comment_backlog() -> bool:
            nonlocal comment_subreddit, requests_made
            if not pending_comment_posts:
                return True
            backlog_subreddit = comment_subreddit
            if settings.max_comments_per_post == 0 or backlog_subreddit is None:
                raise CollectionError("Reddit checkpoint contains an invalid comment backlog")
            per_post_limit = min(settings.max_comments_per_post, self.source.max_items)
            while pending_comment_posts:
                if self.source.max_items - len(records) < per_post_limit:
                    return False
                fullname = pending_comment_posts[0]
                post_id = fullname.removeprefix("t3_")
                comment_params = {
                    "limit": str(per_post_limit),
                    "depth": str(settings.comment_depth),
                    "sort": "top",
                    "raw_json": "1",
                }
                comment_url = (
                    f"{API_ORIGIN}/comments/"
                    f"{quote(post_id, safe='')}?{urlencode(comment_params)}"
                )
                comments_response = self._request("GET", comment_url, headers=auth_headers)
                requests_made += 1
                comment_status = int(getattr(comments_response, "status", 0))
                comment_headers = _headers(comments_response)
                if not 200 <= comment_status < 300:
                    raise _status_error("Reddit", comment_status, comment_headers)
                comment_rate = self._observe_rate_limit(comments_response)
                comment_value = _response_json(
                    comments_response,
                    maximum=self.config.limits.max_decompressed_bytes,
                )
                for comment_data in self._flatten_comments(comment_value, per_post_limit):
                    comment = self._comment_record(
                        comment_data,
                        settings=settings,
                        post_id=post_id,
                        retrieved_at=retrieved_at,
                        expires_at=expires_at,
                        rate_limit=comment_rate,
                    )
                    if comment is not None and comment.native_id not in seen_records:
                        records.append(comment)
                        seen_records.add(comment.native_id)
                pending_comment_posts.pop(0)
                if not pending_comment_posts:
                    comment_subreddit = None
                mark_safe_page()
            return True

        if not process_comment_backlog() or len(records) >= self.source.max_items:
            return CollectionResult.from_records(
                records,
                cursor=saved_checkpoint(),
                requests_made=requests_made,
                resources_read=len(records),
                stop_reason="item_cap",
            )

        while subreddit_index < len(settings.subreddits):
            subreddit = settings.subreddits[subreddit_index]
            committed_high_water = high_water.get(subreddit)
            scan_started_at_head = after is None
            while pages < settings.max_pages and len(records) < self.source.max_items:
                requested_posts = min(
                    settings.page_size, max(1, self.source.max_items - len(records))
                )
                if settings.max_comments_per_post > 0:
                    requested_posts = min(requested_posts, REDDIT_COMMENT_BACKLOG_LIMIT)
                params = {
                    "q": settings.query,
                    "restrict_sr": "1",
                    "sort": settings.sort,
                    "t": settings.time_filter,
                    "limit": str(requested_posts),
                    "raw_json": "1",
                }
                if after:
                    params["after"] = after
                path = f"/r/{quote(subreddit, safe='')}/search"
                response = self._request(
                    "GET",
                    f"{API_ORIGIN}{path}?{urlencode(params)}",
                    headers=auth_headers,
                )
                requests_made += 1
                pages += 1
                status = int(getattr(response, "status", 0))
                response_headers = _headers(response)
                if not 200 <= status < 300:
                    raise _status_error("Reddit", status, response_headers)
                rate_limit = self._observe_rate_limit(response)
                value = _response_json(response, maximum=self.config.limits.max_decompressed_bytes)
                children, next_cursor = self._listing(value)
                if next_cursor is not None and not next_cursor.startswith("t3_"):
                    raise CollectionError("Reddit search returned a non-post pagination cursor")
                if len(children) > requested_posts:
                    raise CollectionError("Reddit returned more posts than the requested page limit")

                # Stop at the last completed run's newest post.  With sort=new,
                # every child before it is new and every child after it is old.
                fresh_children: list[dict[str, Any]] = []
                reached_high_water = False
                for child in children:
                    fullname = self._post_fullname(child)
                    if committed_high_water is not None and fullname == committed_high_water:
                        reached_high_water = True
                        break
                    if pending_high_water is None and fullname is not None:
                        pending_high_water = fullname
                    fresh_children.append(child)

                # Normalize every fetched listing child before comments consume
                # the shared item cap.  Advancing `after` is then always safe.
                new_posts: list[RawRecord] = []
                for child in fresh_children:
                    post = self._post_record(
                        child,
                        settings=settings,
                        retrieved_at=retrieved_at,
                        expires_at=expires_at,
                        rate_limit=rate_limit,
                    )
                    if post is None or post.native_id in seen_records:
                        continue
                    records.append(post)
                    seen_records.add(post.native_id)
                    new_posts.append(post)
                if settings.max_comments_per_post > 0 and new_posts:
                    if pending_comment_posts or comment_subreddit is not None:
                        raise CollectionError("Reddit comment backlog overlapped a listing page")
                    comment_subreddit = subreddit
                    pending_comment_posts.extend(post.native_id for post in new_posts)

                if (
                    next_cursor is None
                    and committed_high_water is not None
                    and not reached_high_water
                    and not scan_started_at_head
                ):
                    # A stale/deleted saved `after` token can produce a terminal
                    # page without proving that the gap back to the committed
                    # boundary was scanned.  Persist this page, but restart the
                    # next invocation from the head before moving high-water.
                    after = None
                    pending_high_water = None
                    cursor_fingerprints.clear()
                    seen_cursors.clear()
                    mark_safe_page()
                    raise CollectionError(
                        "Reddit pagination ended before its high-water boundary; "
                        "the checkpoint was reset to restart safely from the head"
                    )

                listing_complete = reached_high_water or next_cursor is None
                if listing_complete:
                    if pending_high_water is not None:
                        high_water[subreddit] = pending_high_water
                    subreddit_index += 1
                    after = None
                    pending_high_water = None
                    cursor_fingerprints.clear()
                    seen_cursors.clear()
                    final_subreddit = subreddit_index == len(settings.subreddits)
                    if final_subreddit:
                        # A complete checkpoint starts the next run at the first
                        # subreddit while retaining every high-water boundary.
                        subreddit_index = 0
                    mark_safe_page()
                    if not process_comment_backlog():
                        return CollectionResult.from_records(
                            records,
                            cursor=saved_checkpoint(),
                            requests_made=requests_made,
                            resources_read=len(records),
                            stop_reason="item_cap",
                        )
                    if final_subreddit:
                        return CollectionResult.from_records(
                            records,
                            cursor=saved_checkpoint(),
                            requests_made=requests_made,
                            resources_read=len(records),
                        )
                    if len(records) >= self.source.max_items:
                        return CollectionResult.from_records(
                            records,
                            cursor=saved_checkpoint(),
                            requests_made=requests_made,
                            resources_read=len(records),
                            stop_reason="item_cap",
                        )
                    if pages >= settings.max_pages:
                        return CollectionResult.from_records(
                            records,
                            cursor=saved_checkpoint(),
                            requests_made=requests_made,
                            resources_read=len(records),
                            stop_reason="page_cap",
                        )
                    break

                # The entire page was normalized, so its server cursor cannot
                # skip an unprocessed listing child even if comments filled the
                # remaining record budget.
                if next_cursor is None:
                    raise CollectionError("Reddit pagination ended without a safe checkpoint")
                after = next_cursor
                fingerprint = cursor_fingerprint(next_cursor)
                if fingerprint in seen_cursors:
                    halted_reason = "repeated_cursor"
                    mark_safe_page()
                    raise CollectionError(
                        "Reddit pagination repeated a cursor; the checkpoint was halted "
                        "to prevent another request"
                    )
                if len(cursor_fingerprints) >= CURSOR_HISTORY_LIMIT:
                    halted_reason = "cursor_history_limit"
                    mark_safe_page()
                    raise CollectionError(
                        "Reddit pagination exceeded its bounded cursor history; the checkpoint "
                        "was halted to prevent an unverified request"
                    )
                cursor_fingerprints.append(fingerprint)
                seen_cursors.add(fingerprint)
                mark_safe_page()
                if not process_comment_backlog() or len(records) >= self.source.max_items:
                    return CollectionResult.from_records(
                        records,
                        cursor=saved_checkpoint(),
                        requests_made=requests_made,
                        resources_read=len(records),
                        stop_reason="item_cap",
                    )
                if pages >= settings.max_pages:
                    return CollectionResult.from_records(
                        records,
                        cursor=saved_checkpoint(),
                        requests_made=requests_made,
                        resources_read=len(records),
                        stop_reason="page_cap",
                    )

            if pages >= settings.max_pages:
                return CollectionResult.from_records(
                    records,
                    cursor=saved_checkpoint(),
                    requests_made=requests_made,
                    resources_read=len(records),
                    stop_reason="page_cap",
                )

        # The loop returns whenever it completes the last subreddit.
        raise CollectionError("Reddit collection ended without a safe checkpoint")


__all__ = ["RedditConnector", "SocialHttpTransport", "SocialResponse"]
