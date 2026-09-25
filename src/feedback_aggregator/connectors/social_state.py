"""Small, strictly validated checkpoint helpers for social connectors.

The storage layer calls this value a cursor, but social collection needs a
little more state than one opaque page token.  These helpers keep that state
versioned, bounded, and JSON-only so it remains easy to inspect and migrate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from ..errors import ConfigurationError
from ..util import canonical_json, stable_hash
from .json_file import strict_json_loads

_MAX_STATE_BYTES = 32_000
REDDIT_COMMENT_BACKLOG_LIMIT = 50
CURSOR_HISTORY_LIMIT = 32
_POST_ID = re.compile(r"^[0-9]{1,19}$")
_X_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{1,2048}$")
_REDDIT_FULLNAME = re.compile(r"^t3_[A-Za-z0-9]{1,252}$")
_SCOPE = re.compile(r"^scope_[0-9a-f]{64}$")
_CURSOR_FINGERPRINT = re.compile(r"^cursor_[0-9a-f]{64}$")
_HALTED_REASONS = {"cursor_history_limit", "repeated_cursor"}


def checkpoint_scope(kind: str, values: Mapping[str, Any]) -> str:
    """Fingerprint the settings that define one incremental result stream."""

    return stable_hash(kind, canonical_json(dict(values)), prefix="scope_")


def cursor_fingerprint(value: str) -> str:
    """Remember an opaque page token without duplicating it in checkpoint JSON."""

    return stable_hash(value, prefix="cursor_")


def _load_state(cursor: str, *, kind: str) -> dict[str, Any] | None:
    if not cursor.startswith("{"):
        return None
    if len(cursor.encode("utf-8")) > _MAX_STATE_BYTES:
        raise ConfigurationError(f"{kind} checkpoint exceeds its size limit")
    try:
        value = strict_json_loads(cursor)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ConfigurationError(f"{kind} checkpoint is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"{kind} checkpoint must be a JSON object")
    return value


def _encode_state(value: Mapping[str, Any], *, kind: str) -> str:
    encoded = canonical_json(dict(value))
    if len(encoded.encode("utf-8")) > _MAX_STATE_BYTES:
        raise ConfigurationError(f"{kind} checkpoint exceeds its size limit")
    return encoded


def _optional_match(value: object, pattern: re.Pattern[str], label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ConfigurationError(f"{label} is invalid")
    return value


def _cursor_history(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > CURSOR_HISTORY_LIMIT:
        raise ConfigurationError(f"{label} cursor history is invalid")
    result: list[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or _CURSOR_FINGERPRINT.fullmatch(item) is None
            or item in result
        ):
            raise ConfigurationError(f"{label} cursor history is invalid")
        result.append(item)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class XCheckpoint:
    """Incremental boundary plus an optional safe page-resume token."""

    scope: str
    since_id: str | None = None
    next_token: str | None = None
    pending_since_id: str | None = None
    cursor_fingerprints: tuple[str, ...] = ()
    halted_reason: str | None = None

    def __post_init__(self) -> None:
        if self.next_token is not None and not self.cursor_fingerprints:
            object.__setattr__(
                self, "cursor_fingerprints", (cursor_fingerprint(self.next_token),)
            )

    def encode(self) -> str:
        fingerprints = self.cursor_fingerprints
        if self.next_token is not None and not fingerprints:
            fingerprints = (cursor_fingerprint(self.next_token),)
        return _encode_state(
            {
                "halted_reason": self.halted_reason,
                "kind": "x",
                "next_token": self.next_token,
                "pending_since_id": self.pending_since_id,
                "cursor_fingerprints": list(fingerprints),
                "scope": self.scope,
                "since_id": self.since_id,
                "version": 3,
            },
            kind="X",
        )

    @classmethod
    def decode(cls, cursor: str | None, *, scope: str) -> "XCheckpoint":
        if cursor is None:
            return cls(scope=scope)
        if not isinstance(cursor, str):
            raise ConfigurationError("X checkpoint must be text")
        value = _load_state(cursor, kind="X")
        if value is None:
            raise ConfigurationError(
                "Unversioned X cursors are unsafe; purge this source before collecting"
            )
        version = value.get("version")
        expected_v1 = {
            "kind",
            "version",
            "scope",
            "since_id",
            "next_token",
            "pending_since_id",
        }
        expected_v2 = expected_v1 | {"halted_reason"}
        expected_v3 = expected_v2 | {"cursor_fingerprints"}
        expected = {1: expected_v1, 2: expected_v2, 3: expected_v3}
        if (
            value.get("kind") != "x"
            or type(version) is not int
            or version not in expected
            or set(value) != expected[version]
        ):
            raise ConfigurationError("X checkpoint has an unsupported shape or version")
        stored_scope = value.get("scope")
        if not isinstance(stored_scope, str) or _SCOPE.fullmatch(stored_scope) is None:
            raise ConfigurationError("X checkpoint scope is invalid")
        if stored_scope != scope:
            raise ConfigurationError(
                "X checkpoint belongs to different query settings; purge this source before collecting"
            )
        halted_reason = value.get("halted_reason") if version in {2, 3} else None
        if halted_reason is not None and (
            not isinstance(halted_reason, str) or halted_reason not in _HALTED_REASONS
        ):
            raise ConfigurationError("X checkpoint halt reason is invalid")
        next_token = _optional_match(value.get("next_token"), _X_TOKEN, "X next_token")
        cursor_fingerprints = (
            _cursor_history(value.get("cursor_fingerprints"), label="X")
            if version == 3
            else ((cursor_fingerprint(next_token),) if next_token is not None else ())
        )
        result = cls(
            scope=stored_scope,
            since_id=_optional_match(value.get("since_id"), _POST_ID, "X since_id"),
            next_token=next_token,
            pending_since_id=_optional_match(
                value.get("pending_since_id"), _POST_ID, "X pending_since_id"
            ),
            cursor_fingerprints=cursor_fingerprints,
            halted_reason=halted_reason,
        )
        if result.pending_since_id is not None and result.next_token is None:
            raise ConfigurationError("X checkpoint has pending progress without a page token")
        if result.halted_reason is not None and result.next_token is None:
            raise ConfigurationError("X halted checkpoint has no page token")
        if result.next_token is None and result.cursor_fingerprints:
            raise ConfigurationError("X completed checkpoint has cursor history")
        if (
            result.next_token is not None
            and result.halted_reason != "cursor_history_limit"
            and cursor_fingerprint(result.next_token) not in result.cursor_fingerprints
        ):
            raise ConfigurationError("X checkpoint cursor history is incomplete")
        return result


@dataclass(frozen=True, slots=True)
class RedditCheckpoint:
    """Per-subreddit high-water marks plus one in-progress listing page."""

    scope: str
    high_water: dict[str, str]
    resume_subreddit: int = 0
    after: str | None = None
    pending_high_water: str | None = None
    comment_subreddit: str | None = None
    pending_comment_posts: tuple[str, ...] = ()
    cursor_fingerprints: tuple[str, ...] = ()
    halted_reason: str | None = None

    def __post_init__(self) -> None:
        if self.after is not None and not self.cursor_fingerprints:
            object.__setattr__(self, "cursor_fingerprints", (cursor_fingerprint(self.after),))

    def encode(self) -> str:
        fingerprints = self.cursor_fingerprints
        if self.after is not None and not fingerprints:
            fingerprints = (cursor_fingerprint(self.after),)
        return _encode_state(
            {
                "after": self.after,
                "comment_subreddit": self.comment_subreddit,
                "cursor_fingerprints": list(fingerprints),
                "halted_reason": self.halted_reason,
                "high_water": self.high_water,
                "kind": "reddit",
                "pending_comment_posts": list(self.pending_comment_posts),
                "pending_high_water": self.pending_high_water,
                "resume_subreddit": self.resume_subreddit,
                "scope": self.scope,
                "version": 3,
            },
            kind="Reddit",
        )

    @classmethod
    def decode(
        cls,
        cursor: str | None,
        *,
        scope: str,
        subreddits: tuple[str, ...],
    ) -> "RedditCheckpoint":
        if cursor is None:
            return cls(scope=scope, high_water={})
        if not isinstance(cursor, str):
            raise ConfigurationError("Reddit checkpoint must be text")
        value = _load_state(cursor, kind="Reddit")
        if value is None:
            raise ConfigurationError(
                "Unversioned Reddit cursors are unsafe; purge this source before collecting"
            )
        version = value.get("version")
        expected_v1 = {
            "after",
            "comment_subreddit",
            "high_water",
            "kind",
            "pending_comment_posts",
            "pending_high_water",
            "resume_subreddit",
            "scope",
            "version",
        }
        expected_v2 = expected_v1 | {"halted_reason"}
        expected_v3 = expected_v2 | {"cursor_fingerprints"}
        expected = {1: expected_v1, 2: expected_v2, 3: expected_v3}
        if (
            value.get("kind") != "reddit"
            or type(version) is not int
            or version not in expected
            or set(value) != expected[version]
        ):
            raise ConfigurationError("Reddit checkpoint has an unsupported shape or version")
        stored_scope = value.get("scope")
        if not isinstance(stored_scope, str) or _SCOPE.fullmatch(stored_scope) is None:
            raise ConfigurationError("Reddit checkpoint scope is invalid")
        if stored_scope != scope:
            raise ConfigurationError(
                "Reddit checkpoint belongs to different query settings; purge this source before collecting"
            )
        raw_index = value.get("resume_subreddit")
        if isinstance(raw_index, bool) or not isinstance(raw_index, int):
            raise ConfigurationError("Reddit checkpoint resume_subreddit is invalid")
        if not 0 <= raw_index < len(subreddits):
            raise ConfigurationError("Reddit checkpoint resume_subreddit is out of range")
        raw_high_water = value.get("high_water")
        if not isinstance(raw_high_water, dict):
            raise ConfigurationError("Reddit checkpoint high_water is invalid")
        if not set(raw_high_water).issubset(set(subreddits)):
            raise ConfigurationError("Reddit checkpoint names an unknown subreddit")
        high_water: dict[str, str] = {}
        for subreddit, marker in raw_high_water.items():
            if not isinstance(subreddit, str):
                raise ConfigurationError("Reddit checkpoint subreddit is invalid")
            checked = _optional_match(marker, _REDDIT_FULLNAME, "Reddit high-water mark")
            if checked is None:  # Kept explicit for type checkers; mapping values cannot be null.
                raise ConfigurationError("Reddit high-water mark is invalid")
            high_water[subreddit] = checked
        after = _optional_match(value.get("after"), _REDDIT_FULLNAME, "Reddit after cursor")
        pending = _optional_match(
            value.get("pending_high_water"),
            _REDDIT_FULLNAME,
            "Reddit pending high-water mark",
        )
        if pending is not None and after is None:
            raise ConfigurationError(
                "Reddit checkpoint has pending progress without a listing cursor"
            )
        comment_subreddit = value.get("comment_subreddit")
        if comment_subreddit is not None and (
            not isinstance(comment_subreddit, str) or comment_subreddit not in subreddits
        ):
            raise ConfigurationError("Reddit checkpoint comment subreddit is invalid")
        raw_comment_posts = value.get("pending_comment_posts")
        if (
            not isinstance(raw_comment_posts, list)
            or len(raw_comment_posts) > REDDIT_COMMENT_BACKLOG_LIMIT
        ):
            raise ConfigurationError("Reddit checkpoint comment backlog is invalid")
        comment_posts: list[str] = []
        for marker in raw_comment_posts:
            checked = _optional_match(marker, _REDDIT_FULLNAME, "Reddit comment post")
            if checked is None or checked in comment_posts:
                raise ConfigurationError("Reddit checkpoint comment backlog is invalid")
            comment_posts.append(checked)
        if bool(comment_posts) != (comment_subreddit is not None):
            raise ConfigurationError("Reddit checkpoint comment backlog is incomplete")
        halted_reason = value.get("halted_reason") if version in {2, 3} else None
        if halted_reason is not None and (
            not isinstance(halted_reason, str) or halted_reason not in _HALTED_REASONS
        ):
            raise ConfigurationError("Reddit checkpoint halt reason is invalid")
        if halted_reason is not None and after is None:
            raise ConfigurationError("Reddit halted checkpoint has no listing cursor")
        cursor_fingerprints = (
            _cursor_history(value.get("cursor_fingerprints"), label="Reddit")
            if version == 3
            else ((cursor_fingerprint(after),) if after is not None else ())
        )
        if after is None and cursor_fingerprints:
            raise ConfigurationError("Reddit completed checkpoint has cursor history")
        if (
            after is not None
            and halted_reason != "cursor_history_limit"
            and cursor_fingerprint(after) not in cursor_fingerprints
        ):
            raise ConfigurationError("Reddit checkpoint cursor history is incomplete")
        return cls(
            scope=stored_scope,
            high_water=high_water,
            resume_subreddit=raw_index,
            after=after,
            pending_high_water=pending,
            comment_subreddit=comment_subreddit,
            pending_comment_posts=tuple(comment_posts),
            cursor_fingerprints=cursor_fingerprints,
            halted_reason=halted_reason,
        )


def newest_x_id(*values: str | None) -> str | None:
    """Return the greatest validated X snowflake without integer-size ambiguity."""

    present = [value for value in values if value is not None]
    if not present:
        return None
    return max(present, key=lambda value: (len(value), value))


__all__ = [
    "CURSOR_HISTORY_LIMIT",
    "REDDIT_COMMENT_BACKLOG_LIMIT",
    "RedditCheckpoint",
    "XCheckpoint",
    "checkpoint_scope",
    "cursor_fingerprint",
    "newest_x_id",
]
