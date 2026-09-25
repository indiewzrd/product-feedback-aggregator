from __future__ import annotations

import json
import os
import unittest
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from feedback_aggregator.config import (
    AnalysisConfig,
    AppConfig,
    LimitsConfig,
    OutputConfig,
    PrivacyConfig,
    ProductConfig,
    SourceConfig,
    StorageConfig,
)
from feedback_aggregator.connectors.base import ConnectorContext
from feedback_aggregator.connectors.reddit import RedditConnector
from feedback_aggregator.connectors.social_state import RedditCheckpoint, checkpoint_scope
from feedback_aggregator.connectors.x import XConnector
from feedback_aggregator.errors import (
    BudgetError,
    CollectionError,
    ConfigurationError,
    PartialCollectionError,
)
from feedback_aggregator.models import PolicyCapabilities


@dataclass(slots=True)
class FakeResponse:
    status: int
    value: Any
    headers: Mapping[str, str] | None = None

    @property
    def body(self) -> bytes:
        return json.dumps(self.value).encode("utf-8")


class FakeTransport:
    """Strict synthetic transport: every call consumes one queued response."""

    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None = None,
        allow_redirects: bool = False,
    ) -> FakeResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "allow_redirects": allow_redirects,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected network request")
        response = self.responses.pop(0)
        response.headers = response.headers or {}
        return response


def app_config(source: SourceConfig) -> AppConfig:
    root = Path("/tmp/feedback-tests")
    return AppConfig(
        path=root / "feedback.yml",
        root=root,
        product=ProductConfig(
            name="Example Product",
            aliases=("ExampleApp",),
            terms=("example software",),
            exclusions=("hiring",),
        ),
        storage=StorageConfig(root / "feedback.db"),
        privacy=PrivacyConfig(root / "salt"),
        limits=LimitsConfig(max_items_per_source=1_000),
        analysis=AnalysisConfig(),
        outputs=OutputConfig(root / "reports"),
        sources=(source,),
        config_hash="cfg_test",
    )


def reddit_source(
    *,
    max_items: int = 20,
    max_comments: int = 0,
    max_pages: int = 10,
    subreddits: tuple[str, ...] = ("example",),
    user_agent: str = "linux:testclient:1.0 (by /u/testuser)",
) -> SourceConfig:
    return SourceConfig(
        id="reddit-test",
        type="reddit",
        enabled=True,
        max_items=max_items,
        options={
            "approval_confirmed": True,
            "client_id_env": "TEST_REDDIT_CLIENT_ID",
            "client_secret_env": "TEST_REDDIT_CLIENT_SECRET",
            "user_agent": user_agent,
            "subreddits": list(subreddits),
            "query": '"Example Product"',
            "page_size": 10,
            "max_pages": max_pages,
            "max_comments_per_post": max_comments,
        },
        policy=PolicyCapabilities(
            acquisition_mode="official_api",
            approval_required=True,
            approval_reference="Reddit Responsible Builder Policy",
            raw_ttl_hours=48,
            deletion_reconcile_interval_hours=48,
            policy_version="2026-06-05",
            policy_version_checked_at="2026-09-25",
        ),
    )


def x_source(
    *,
    max_items: int = 20,
    max_cost: float = 1.0,
    page_size: int = 10,
    max_pages: int = 10,
    mode: str = "recent",
) -> SourceConfig:
    options: dict[str, Any] = {
        "approval_confirmed": True,
        "bearer_token_env": "TEST_X_BEARER_TOKEN",
        "mode": mode,
        "query": '"Example Product" -is:retweet',
        "page_size": page_size,
        "max_pages": max_pages,
    }
    if mode == "mentions":
        options["user_id"] = "123456"
    return SourceConfig(
        id="x-test",
        type="x",
        enabled=True,
        max_items=max_items,
        options=options,
        policy=PolicyCapabilities(
            acquisition_mode="official_api",
            approval_required=True,
            approval_reference="X Developer Guidelines",
            raw_ttl_hours=24,
            cost_per_resource_usd=0.005,
            max_cost_usd=max_cost,
            policy_version="2026-09-25",
            policy_version_checked_at="2026-09-25",
        ),
    )


def reddit_post(post_id: str, *, title: str = "Feedback", author: str = "person") -> dict[str, Any]:
    return {
        "kind": "t3",
        "data": {
            "id": post_id,
            "name": f"t3_{post_id}",
            "title": title,
            "selftext": "The product should be easier to use.",
            "author": author,
            "subreddit": "example",
            "permalink": f"/r/example/comments/{post_id}/feedback/",
            "created_utc": 1_700_000_000,
            "score": 7,
            "num_comments": 2,
        },
    }


def reddit_listing(children: list[dict[str, Any]], after: str | None) -> dict[str, Any]:
    return {"kind": "Listing", "data": {"children": children, "after": after}}


def x_post(post_id: str, text: str = "Please improve onboarding") -> dict[str, Any]:
    return {
        "id": post_id,
        "text": text,
        "author_id": "99",
        "created_at": "2026-09-24T10:00:00Z",
        "conversation_id": post_id,
        "lang": "en",
        "public_metrics": {"like_count": 3, "reply_count": 1},
    }


def x_page(
    posts: list[dict[str, Any]],
    next_token: str | None = None,
) -> dict[str, Any]:
    meta: dict[str, Any] = {"result_count": len(posts)}
    if next_token is not None:
        meta["next_token"] = next_token
    return {"data": posts, "meta": meta}


class RedditConnectorTests(unittest.TestCase):
    env = {
        "TEST_REDDIT_CLIENT_ID": "testclient",
        "TEST_REDDIT_CLIENT_SECRET": "secret-value",
    }

    def connector(
        self, transport: FakeTransport, source: SourceConfig | None = None
    ) -> RedditConnector:
        selected = source or reddit_source()
        return RedditConnector(
            ConnectorContext(app_config(selected), selected, "author-salt", http=transport)
        )

    @patch.dict(os.environ, env, clear=False)
    def test_search_paginates_with_oauth_and_rate_metadata(self) -> None:
        transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token", "expires_in": 3600}),
            FakeResponse(
                200,
                reddit_listing([reddit_post("a1")], "t3_a1"),
                {"X-Ratelimit-Used": "2", "X-Ratelimit-Remaining": "98", "X-Ratelimit-Reset": "42"},
            ),
            FakeResponse(200, reddit_listing([reddit_post("b2")], None)),
        )
        result = self.connector(transport).collect()

        self.assertEqual([record.native_id for record in result.records], ["t3_a1", "t3_b2"])
        self.assertEqual(result.requests_made, 3)
        self.assertEqual(result.stop_reason, "complete")
        self.assertEqual(result.records[0].metadata["rate_limit"]["reset_seconds"], 42.0)
        self.assertTrue(all(record.expires_at for record in result.records))
        expiry = datetime.fromisoformat(result.records[0].expires_at.replace("Z", "+00:00"))
        retrieved = datetime.fromisoformat(result.records[0].retrieved_at.replace("Z", "+00:00"))
        self.assertEqual((expiry - retrieved).total_seconds(), 48 * 3600)

        token_call, first_page, second_page = transport.calls
        self.assertEqual(token_call["url"], "https://www.reddit.com/api/v1/access_token")
        self.assertEqual(token_call["method"], "POST")
        self.assertIn(b"grant_type=client_credentials", token_call["body"])
        self.assertTrue(token_call["headers"]["Authorization"].startswith("Basic "))
        self.assertEqual(first_page["headers"]["Authorization"], "Bearer oauth-token")
        self.assertEqual(parse_qs(urlsplit(second_page["url"]).query)["after"], ["t3_a1"])
        self.assertTrue(all(call["allow_redirects"] is False for call in transport.calls))
        self.assertEqual(
            {urlsplit(call["url"]).hostname for call in transport.calls},
            {"www.reddit.com", "oauth.reddit.com"},
        )

    @patch.dict(os.environ, env, clear=False)
    def test_comment_tree_is_flattened_and_bounded(self) -> None:
        nested_comment = {
            "kind": "t1",
            "data": {
                "id": "c2",
                "name": "t1_c2",
                "body": "Nested comment",
                "author": "second",
                "created_utc": 1_700_000_002,
                "score": 2,
                "link_id": "t3_a1",
                "parent_id": "t1_c1",
                "permalink": "/r/example/comments/a1/feedback/c2/",
                "replies": "",
            },
        }
        top_comment = {
            "kind": "t1",
            "data": {
                "id": "c1",
                "name": "t1_c1",
                "body": "Top comment",
                "author": "first",
                "created_utc": 1_700_000_001,
                "score": 4,
                "link_id": "t3_a1",
                "parent_id": "t3_a1",
                "permalink": "/r/example/comments/a1/feedback/c1/",
                "replies": reddit_listing([nested_comment], None),
            },
        }
        comment_payload = [
            reddit_listing([reddit_post("a1")], None),
            reddit_listing([top_comment], None),
        ]
        transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], None)),
            FakeResponse(200, comment_payload),
        )
        result = self.connector(transport, reddit_source(max_comments=2)).collect()

        self.assertEqual(
            [record.native_id for record in result.records], ["t3_a1", "t1_c1", "t1_c2"]
        )
        self.assertEqual(result.records[1].metadata["parent_id"], "t3_a1")
        self.assertEqual(urlsplit(transport.calls[2]["url"]).hostname, "oauth.reddit.com")
        self.assertIn("/comments/a1", urlsplit(transport.calls[2]["url"]).path)

    @patch.dict(os.environ, env, clear=False)
    def test_repeated_cursor_stops_without_looping(self) -> None:
        transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], "t3_repeat")),
            FakeResponse(200, reddit_listing([reddit_post("b2")], "t3_repeat")),
        )
        with self.assertRaises(PartialCollectionError) as raised:
            self.connector(transport).collect()

        result = raised.exception.result
        self.assertEqual(result.stop_reason, "partial_error")
        self.assertEqual(json.loads(result.cursor or "{}")["halted_reason"], "repeated_cursor")
        self.assertEqual(len(transport.calls), 3)

        blocked_transport = FakeTransport()
        with self.assertRaisesRegex(CollectionError, "purge this source"):
            self.connector(blocked_transport).collect(cursor=result.cursor)
        self.assertEqual(blocked_transport.calls, [])

    @patch.dict(os.environ, env, clear=False)
    def test_cursor_cycle_across_reddit_invocations_halts_before_reuse(self) -> None:
        source = reddit_source(max_pages=1)
        cursor: str | None = None
        for post_id, next_cursor in (("a1", "t3_A"), ("b2", "t3_B")):
            transport = FakeTransport(
                FakeResponse(200, {"access_token": "oauth-token"}),
                FakeResponse(200, reddit_listing([reddit_post(post_id)], next_cursor)),
            )
            cursor = self.connector(transport, source).collect(cursor=cursor).cursor

        cycle_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("c3")], "t3_A")),
        )
        with self.assertRaises(PartialCollectionError) as raised:
            self.connector(cycle_transport, source).collect(cursor=cursor)
        halted = raised.exception.result.cursor
        self.assertEqual(json.loads(halted or "{}")["halted_reason"], "repeated_cursor")

        blocked = FakeTransport()
        with self.assertRaisesRegex(CollectionError, "purge this source"):
            self.connector(blocked, source).collect(cursor=halted)
        self.assertEqual(blocked.calls, [])

    @patch.dict(os.environ, env, clear=False)
    def test_stale_resumed_cursor_cannot_advance_reddit_high_water(self) -> None:
        source = reddit_source()
        initial_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], None)),
        )
        initial = self.connector(initial_transport, source).collect()

        page_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("b2")], "t3_b2")),
        )
        page = self.connector(page_transport, reddit_source(max_pages=1)).collect(
            cursor=initial.cursor
        )
        self.assertEqual(page.stop_reason, "page_cap")

        stale_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([], None)),
        )
        with self.assertRaises(PartialCollectionError) as raised:
            self.connector(stale_transport, source).collect(cursor=page.cursor)
        recovery = json.loads(raised.exception.result.cursor or "{}")
        self.assertEqual(recovery["high_water"], {"example": "t3_a1"})
        self.assertIsNone(recovery["after"])
        self.assertIsNone(recovery["pending_high_water"])

        recovery_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("b2")], None)),
        )
        recovered = self.connector(recovery_transport, source).collect(
            cursor=raised.exception.result.cursor
        )
        self.assertEqual([record.native_id for record in recovered.records], ["t3_b2"])
        self.assertEqual(
            json.loads(recovered.cursor or "{}")["high_water"], {"example": "t3_b2"}
        )

    @patch.dict(os.environ, env, clear=False)
    def test_r_all_comments_use_prefixless_endpoint(self) -> None:
        comment = {
            "kind": "t1",
            "data": {
                "id": "c1",
                "name": "t1_c1",
                "body": "A useful reply",
                "author": "person",
                "link_id": "t3_a1",
                "parent_id": "t3_a1",
                "replies": "",
            },
        }
        transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], None)),
            FakeResponse(
                200,
                [
                    reddit_listing([reddit_post("a1")], None),
                    reddit_listing([comment], None),
                ],
            ),
        )
        self.connector(
            transport,
            reddit_source(max_comments=1, subreddits=("all",)),
        ).collect()

        self.assertEqual(urlsplit(transport.calls[2]["url"]).path, "/comments/a1")

    @patch.dict(os.environ, env, clear=False)
    def test_item_and_page_caps_are_hard(self) -> None:
        item_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], "t3_b2")),
        )
        item_result = self.connector(item_transport, reddit_source(max_items=1)).collect()
        self.assertEqual(len(item_result.records), 1)
        self.assertEqual(item_result.stop_reason, "item_cap")
        self.assertEqual(json.loads(item_result.cursor or "{}")["after"], "t3_b2")
        self.assertEqual(len(item_transport.calls), 2)

        page_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], "t3_a1")),
        )
        page_result = self.connector(page_transport, reddit_source(max_pages=1)).collect()
        self.assertEqual(page_result.stop_reason, "page_cap")
        self.assertEqual(json.loads(page_result.cursor or "{}")["after"], "t3_a1")
        self.assertEqual(len(page_transport.calls), 2)

    @patch.dict(os.environ, env, clear=False)
    def test_comments_cannot_make_listing_checkpoint_skip_fetched_posts(self) -> None:
        comment = {
            "kind": "t1",
            "data": {
                "id": "c1",
                "name": "t1_c1",
                "body": "One comment",
                "author": "person",
                "link_id": "t3_a1",
                "parent_id": "t3_a1",
                "replies": "",
            },
        }
        transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(
                200,
                reddit_listing([reddit_post("a1"), reddit_post("b2")], "t3_b2"),
            ),
        )
        result = self.connector(
            transport,
            reddit_source(max_items=3, max_comments=5),
        ).collect()

        self.assertEqual(
            [record.native_id for record in result.records],
            ["t3_a1", "t3_b2"],
        )
        self.assertEqual(result.stop_reason, "item_cap")
        first_state = json.loads(result.cursor or "{}")
        self.assertEqual(first_state["after"], "t3_b2")
        self.assertEqual(first_state["pending_comment_posts"], ["t3_a1", "t3_b2"])

        resume_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(
                200,
                [
                    reddit_listing([reddit_post("a1")], None),
                    reddit_listing([comment], None),
                ],
            ),
        )
        resumed = self.connector(
            resume_transport,
            reddit_source(max_items=3, max_comments=5),
        ).collect(cursor=result.cursor)
        self.assertEqual([record.native_id for record in resumed.records], ["t1_c1"])
        self.assertEqual(
            json.loads(resumed.cursor or "{}")["pending_comment_posts"],
            ["t3_b2"],
        )

    @patch.dict(os.environ, env, clear=False)
    def test_multi_subreddit_checkpoint_resumes_without_skipping_a_source(self) -> None:
        source = reddit_source(max_items=1, subreddits=("one", "two"))
        first_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], None)),
        )
        first = self.connector(first_transport, source).collect()
        first_state = json.loads(first.cursor or "{}")
        self.assertEqual(first.stop_reason, "item_cap")
        self.assertEqual(first_state["resume_subreddit"], 1)
        self.assertEqual(first_state["high_water"], {"one": "t3_a1"})

        second_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("b2")], None)),
        )
        second = self.connector(second_transport, source).collect(cursor=first.cursor)
        second_state = json.loads(second.cursor or "{}")
        self.assertEqual([record.native_id for record in second.records], ["t3_b2"])
        self.assertEqual(second_state["resume_subreddit"], 0)
        self.assertEqual(second_state["high_water"], {"one": "t3_a1", "two": "t3_b2"})
        self.assertIn("/r/two/search", second_transport.calls[1]["url"])

    @patch.dict(os.environ, env, clear=False)
    def test_complete_checkpoint_emits_only_new_reddit_posts(self) -> None:
        source = reddit_source()
        first_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], None)),
        )
        first = self.connector(first_transport, source).collect()

        unchanged_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], None)),
        )
        unchanged = self.connector(unchanged_transport, source).collect(cursor=first.cursor)
        self.assertEqual(unchanged.records, ())

        new_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(
                200,
                reddit_listing([reddit_post("b2"), reddit_post("a1")], None),
            ),
        )
        changed = self.connector(new_transport, source).collect(cursor=unchanged.cursor)
        self.assertEqual([record.native_id for record in changed.records], ["t3_b2"])
        self.assertEqual(json.loads(changed.cursor or "{}")["high_water"]["example"], "t3_b2")

    @patch.dict(os.environ, env, clear=False)
    def test_reddit_checkpoint_is_strict_and_scope_bound(self) -> None:
        transport = FakeTransport()
        with self.assertRaises(ConfigurationError):
            self.connector(transport).collect(cursor='{"kind":"reddit","version":1}')
        self.assertEqual(transport.calls, [])

        first_transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], None)),
        )
        first = self.connector(first_transport).collect()
        changed_query = reddit_source()
        changed_query.options["query"] = '"Different Product"'
        with self.assertRaisesRegex(ConfigurationError, "purge this source"):
            self.connector(FakeTransport(), changed_query).collect(cursor=first.cursor)

    def test_maximum_valid_reddit_checkpoint_round_trips_within_size_limit(self) -> None:
        subreddits = tuple(f"subreddit{index:02d}" for index in range(50))
        high_water = {
            subreddit: f"t3_h{index:02d}{'a' * 249}"
            for index, subreddit in enumerate(subreddits)
        }
        comment_posts = tuple(
            f"t3_c{index:02d}{'b' * 249}" for index in range(50)
        )
        checkpoint = RedditCheckpoint(
            scope=checkpoint_scope("reddit", {"fixture": "maximum"}),
            high_water=high_water,
            after=f"t3_{'z' * 252}",
            pending_high_water=f"t3_{'y' * 252}",
            comment_subreddit=subreddits[0],
            pending_comment_posts=comment_posts,
        )

        encoded = checkpoint.encode()
        self.assertLessEqual(len(encoded.encode("utf-8")), 32_000)
        self.assertEqual(
            RedditCheckpoint.decode(
                encoded,
                scope=checkpoint.scope,
                subreddits=subreddits,
            ),
            checkpoint,
        )

    @patch.dict(os.environ, env, clear=False)
    def test_401_403_and_429_are_safe_and_never_fall_back(self) -> None:
        for status in (401, 403, 429):
            with self.subTest(status=status):
                transport = FakeTransport(
                    FakeResponse(status, {"secret": "must-not-appear"}, {"Retry-After": "9"})
                )
                with self.assertRaises(CollectionError) as raised:
                    self.connector(transport).collect()
                message = str(raised.exception)
                self.assertIn(str(status), message)
                self.assertNotIn("must-not-appear", message)
                self.assertNotIn("secret-value", message)
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(urlsplit(transport.calls[0]["url"]).hostname, "www.reddit.com")

    @patch.dict(os.environ, env, clear=False)
    def test_later_reddit_failure_carries_only_completed_page_progress(self) -> None:
        transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], "t3_a1")),
            FakeResponse(429, {"detail": "do-not-leak"}, {"Retry-After": "9"}),
        )
        with self.assertRaises(PartialCollectionError) as raised:
            self.connector(transport).collect()

        partial = raised.exception.result
        self.assertEqual([record.native_id for record in partial.records], ["t3_a1"])
        self.assertEqual(partial.stop_reason, "partial_error")
        self.assertEqual(partial.requests_made, 2)  # OAuth token plus completed listing page.
        self.assertEqual(json.loads(partial.cursor or "{}")["after"], "t3_a1")
        self.assertNotIn("do-not-leak", str(raised.exception))

    @patch.dict(os.environ, env, clear=False)
    def test_reddit_missing_listing_fields_fail_closed(self) -> None:
        transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, {"kind": "Listing", "data": {}}),
        )
        with self.assertRaises(CollectionError):
            self.connector(transport).collect()

    @patch.dict(os.environ, env, clear=False)
    def test_truthful_user_agent_is_required_before_network(self) -> None:
        source = reddit_source(user_agent="generic-client")
        transport = FakeTransport()
        with self.assertRaises(ConfigurationError):
            self.connector(transport, source).collect()
        self.assertEqual(transport.calls, [])

    @patch.dict(os.environ, env, clear=False)
    def test_stricter_reconciliation_interval_caps_raw_ttl(self) -> None:
        source = reddit_source()
        source = replace(
            source,
            policy=replace(
                source.policy,
                raw_ttl_hours=12,
                deletion_reconcile_interval_hours=1,
            ),
        )
        transport = FakeTransport(
            FakeResponse(200, {"access_token": "oauth-token"}),
            FakeResponse(200, reddit_listing([reddit_post("a1")], None)),
        )
        result = self.connector(transport, source).collect()
        retrieved = datetime.fromisoformat(result.records[0].retrieved_at.replace("Z", "+00:00"))
        expiry = datetime.fromisoformat(result.records[0].expires_at.replace("Z", "+00:00"))
        self.assertEqual((expiry - retrieved).total_seconds(), 3600)


class XConnectorTests(unittest.TestCase):
    env = {"TEST_X_BEARER_TOKEN": "x-bearer-secret"}

    def connector(self, transport: FakeTransport, source: SourceConfig | None = None) -> XConnector:
        selected = source or x_source()
        return XConnector(
            ConnectorContext(app_config(selected), selected, "author-salt", http=transport)
        )

    @patch.dict(os.environ, env, clear=False)
    def test_recent_search_paginates_and_accounts_for_cost(self) -> None:
        transport = FakeTransport(
            FakeResponse(
                200,
                x_page([x_post("101")], "next-one"),
                {
                    "x-rate-limit-limit": "450",
                    "x-rate-limit-remaining": "449",
                    "x-rate-limit-reset": "1800000000",
                },
            ),
            FakeResponse(200, x_page([x_post("102")])),
        )
        result = self.connector(transport).collect()

        self.assertEqual([record.native_id for record in result.records], ["101", "102"])
        self.assertEqual(result.resources_read, 2)
        self.assertAlmostEqual(result.cost_usd, 0.01)
        self.assertEqual(result.records[0].metadata["rate_limit"]["remaining"], 449)
        expiry = datetime.fromisoformat(result.records[0].expires_at.replace("Z", "+00:00"))
        retrieved = datetime.fromisoformat(result.records[0].retrieved_at.replace("Z", "+00:00"))
        self.assertEqual((expiry - retrieved).total_seconds(), 24 * 3600)

        first_query = parse_qs(urlsplit(transport.calls[0]["url"]).query)
        second_query = parse_qs(urlsplit(transport.calls[1]["url"]).query)
        self.assertEqual(first_query["query"], ['"Example Product" -is:retweet'])
        self.assertNotIn("expansions", first_query)
        self.assertEqual(second_query["pagination_token"], ["next-one"])
        self.assertTrue(
            all(urlsplit(call["url"]).hostname == "api.x.com" for call in transport.calls)
        )
        self.assertTrue(all(call["allow_redirects"] is False for call in transport.calls))

    @patch.dict(os.environ, env, clear=False)
    def test_mentions_use_only_official_timeline_endpoint(self) -> None:
        transport = FakeTransport(FakeResponse(200, x_page([x_post("101")])))
        result = self.connector(
            transport,
            x_source(mode="mentions", max_items=5, page_size=5),
        ).collect()
        split = urlsplit(transport.calls[0]["url"])
        params = parse_qs(split.query)
        self.assertEqual(split.netloc, "api.x.com")
        self.assertEqual(split.path, "/2/users/123456/mentions")
        self.assertNotIn("query", params)
        self.assertNotIn("expansions", params)
        self.assertEqual(params["max_results"], ["5"])
        self.assertEqual(result.records[0].query, "")

    @patch.dict(os.environ, env, clear=False)
    def test_worst_case_page_cost_is_reserved_before_request(self) -> None:
        # First page actually returns one Post ($0.005), but the next 10-Post
        # page would reserve $0.05 and breach the $0.05 hard limit.
        transport = FakeTransport(
            FakeResponse(200, x_page([x_post("101")], "more"))
        )
        result = self.connector(transport, x_source(max_items=50, max_cost=0.05)).collect()
        self.assertEqual(result.stop_reason, "cost_cap")
        self.assertEqual(result.cost_usd, 0.005)
        self.assertEqual(len(transport.calls), 1)

        insufficient = FakeTransport()
        with self.assertRaises(BudgetError):
            self.connector(insufficient, x_source(max_items=50, max_cost=0.049)).collect()
        self.assertEqual(insufficient.calls, [])

    @patch.dict(os.environ, env, clear=False)
    def test_item_cap_never_fetches_a_page_that_cannot_fit(self) -> None:
        transport = FakeTransport(
            FakeResponse(
                200,
                x_page([x_post(str(post_id)) for post_id in range(101, 111)], "more"),
            )
        )
        result = self.connector(transport, x_source(max_items=11, max_cost=0.05)).collect()
        self.assertEqual(len(result.records), 10)
        self.assertEqual(result.resources_read, 10)
        self.assertAlmostEqual(result.cost_usd, 0.05)
        self.assertEqual(result.stop_reason, "item_cap")
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(json.loads(result.cursor or "{}")["next_token"], "more")

        resume_transport = FakeTransport(
            FakeResponse(200, x_page([x_post("111")]))
        )
        resumed = self.connector(
            resume_transport,
            x_source(max_items=11, max_cost=0.05),
        ).collect(cursor=result.cursor)
        resume_query = parse_qs(urlsplit(resume_transport.calls[0]["url"]).query)
        self.assertEqual(resume_query["pagination_token"], ["more"])
        self.assertEqual([record.native_id for record in resumed.records], ["111"])
        self.assertEqual(json.loads(resumed.cursor or "{}")["since_id"], "111")

        too_small = FakeTransport()
        with self.assertRaises(ConfigurationError):
            self.connector(too_small, x_source(max_items=9)).collect()
        self.assertEqual(too_small.calls, [])

    @patch.dict(os.environ, env, clear=False)
    def test_x_resource_cap_counts_duplicate_billed_rows(self) -> None:
        transport = FakeTransport(
            FakeResponse(200, x_page([x_post("101") for _ in range(10)], "more"))
        )
        result = self.connector(
            transport,
            x_source(max_items=10, max_cost=0.05),
        ).collect()

        self.assertEqual([record.native_id for record in result.records], ["101"])
        self.assertEqual(result.resources_read, 10)
        self.assertEqual(result.stop_reason, "item_cap")
        self.assertEqual(len(transport.calls), 1)

    @patch.dict(os.environ, env, clear=False)
    def test_repeated_cursor_stops_without_looping(self) -> None:
        transport = FakeTransport(
            FakeResponse(200, x_page([x_post("101")], "same")),
            FakeResponse(200, x_page([x_post("102")], "same")),
        )
        with self.assertRaises(PartialCollectionError) as raised:
            self.connector(transport).collect()

        result = raised.exception.result
        self.assertEqual(result.stop_reason, "partial_error")
        self.assertEqual(json.loads(result.cursor or "{}")["halted_reason"], "repeated_cursor")
        self.assertEqual(len(transport.calls), 2)

        blocked_transport = FakeTransport()
        with self.assertRaisesRegex(CollectionError, "purge this source"):
            self.connector(blocked_transport).collect(cursor=result.cursor)
        self.assertEqual(blocked_transport.calls, [])

    @patch.dict(os.environ, env, clear=False)
    def test_cursor_cycle_across_x_invocations_halts_before_reuse(self) -> None:
        source = x_source(max_pages=1)
        cursor: str | None = None
        for post_id, next_cursor in (("101", "token-A"), ("102", "token-B")):
            transport = FakeTransport(
                FakeResponse(200, x_page([x_post(post_id)], next_cursor))
            )
            cursor = self.connector(transport, source).collect(cursor=cursor).cursor

        cycle_transport = FakeTransport(
            FakeResponse(200, x_page([x_post("103")], "token-A"))
        )
        with self.assertRaises(PartialCollectionError) as raised:
            self.connector(cycle_transport, source).collect(cursor=cursor)
        halted = raised.exception.result.cursor
        self.assertEqual(json.loads(halted or "{}")["halted_reason"], "repeated_cursor")

        blocked = FakeTransport()
        with self.assertRaisesRegex(CollectionError, "purge this source"):
            self.connector(blocked, source).collect(cursor=halted)
        self.assertEqual(blocked.calls, [])

    @patch.dict(os.environ, env, clear=False)
    def test_later_x_failure_carries_only_completed_page_progress(self) -> None:
        transport = FakeTransport(
            FakeResponse(200, x_page([x_post("101")], "more")),
            FakeResponse(429, {"detail": "x-bearer-secret"}),
        )
        with self.assertRaises(PartialCollectionError) as raised:
            self.connector(transport).collect()

        partial = raised.exception.result
        self.assertEqual([record.native_id for record in partial.records], ["101"])
        self.assertEqual(partial.stop_reason, "partial_error")
        self.assertEqual(partial.requests_made, 1)
        self.assertEqual(partial.resources_read, 1)
        self.assertAlmostEqual(partial.cost_usd, 0.005)
        self.assertEqual(json.loads(partial.cursor or "{}")["next_token"], "more")
        self.assertNotIn("x-bearer-secret", str(raised.exception))

    @patch.dict(os.environ, env, clear=False)
    def test_x_missing_metadata_fails_closed(self) -> None:
        transport = FakeTransport(FakeResponse(200, {"data": [x_post("101")]}))
        with self.assertRaises(CollectionError):
            self.connector(transport).collect()

    @patch.dict(os.environ, env, clear=False)
    def test_page_cap_stops_with_resume_cursor(self) -> None:
        transport = FakeTransport(
            FakeResponse(200, x_page([x_post("101")], "more"))
        )
        result = self.connector(transport, x_source(max_pages=1)).collect()
        self.assertEqual(result.stop_reason, "page_cap")
        self.assertEqual(json.loads(result.cursor or "{}")["next_token"], "more")
        self.assertEqual(len(transport.calls), 1)

    @patch.dict(os.environ, env, clear=False)
    def test_complete_checkpoint_uses_since_id_and_discovers_only_new_posts(self) -> None:
        source = x_source()
        first_transport = FakeTransport(
            FakeResponse(200, x_page([x_post("101")]))
        )
        first = self.connector(first_transport, source).collect()
        self.assertEqual(json.loads(first.cursor or "{}")["since_id"], "101")

        second_transport = FakeTransport(
            FakeResponse(200, x_page([x_post("102")]))
        )
        second = self.connector(second_transport, source).collect(cursor=first.cursor)
        query = parse_qs(urlsplit(second_transport.calls[0]["url"]).query)
        self.assertEqual(query["since_id"], ["101"])
        self.assertEqual([record.native_id for record in second.records], ["102"])
        self.assertEqual(json.loads(second.cursor or "{}")["since_id"], "102")

    @patch.dict(os.environ, env, clear=False)
    def test_x_checkpoint_is_strict_and_scope_bound(self) -> None:
        transport = FakeTransport()
        with self.assertRaises(ConfigurationError):
            self.connector(transport).collect(cursor='{"kind":"x","version":1}')
        self.assertEqual(transport.calls, [])

        first_transport = FakeTransport(
            FakeResponse(200, x_page([x_post("101")]))
        )
        first = self.connector(first_transport).collect()
        changed_query = x_source()
        changed_query.options["query"] = '"Different Product"'
        with self.assertRaisesRegex(ConfigurationError, "purge this source"):
            self.connector(FakeTransport(), changed_query).collect(cursor=first.cursor)

    @patch.dict(os.environ, env, clear=False)
    def test_401_403_and_429_are_safe_and_never_fall_back(self) -> None:
        for status in (401, 403, 429):
            with self.subTest(status=status):
                transport = FakeTransport(
                    FakeResponse(
                        status, {"detail": "x-bearer-secret"}, {"x-rate-limit-reset": "1800000000"}
                    )
                )
                with self.assertRaises(CollectionError) as raised:
                    self.connector(transport).collect()
                message = str(raised.exception)
                self.assertIn(str(status), message)
                self.assertNotIn("x-bearer-secret", message)
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(urlsplit(transport.calls[0]["url"]).hostname, "api.x.com")

    @patch.dict(os.environ, env, clear=False)
    def test_query_limit_and_required_cost_fail_before_network(self) -> None:
        long_query_source = x_source()
        long_query_source.options["query"] = "q" * 513
        transport = FakeTransport()
        with self.assertRaises(ConfigurationError):
            self.connector(transport, long_query_source).collect()
        self.assertEqual(transport.calls, [])

        no_budget = x_source(max_cost=0.0)
        with self.assertRaises(ConfigurationError):
            self.connector(transport, no_budget).collect()
        self.assertEqual(transport.calls, [])

    @patch.dict(os.environ, env, clear=False)
    def test_stricter_raw_ttl_is_honored(self) -> None:
        source = x_source()
        source = replace(source, policy=replace(source.policy, raw_ttl_hours=2))
        transport = FakeTransport(FakeResponse(200, x_page([x_post("101")])))
        result = self.connector(transport, source).collect()
        retrieved = datetime.fromisoformat(result.records[0].retrieved_at.replace("Z", "+00:00"))
        expiry = datetime.fromisoformat(result.records[0].expires_at.replace("Z", "+00:00"))
        self.assertEqual((expiry - retrieved).total_seconds(), 2 * 3600)


if __name__ == "__main__":
    unittest.main()
