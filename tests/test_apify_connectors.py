from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

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
from feedback_aggregator.connectors.apify import ApifyCheckpoint
from feedback_aggregator.connectors.base import ConnectorContext
from feedback_aggregator.connectors.reddit_apify import RedditApifyConnector
from feedback_aggregator.connectors.x_apify import XApifyConnector
from feedback_aggregator.errors import CollectionError, ConfigurationError, PartialCollectionError
from feedback_aggregator.models import CollectionResult, PolicyCapabilities


@dataclass(slots=True)
class FakeResponse:
    status: int
    value: Any
    headers: Mapping[str, str] = field(default_factory=dict)

    @property
    def body(self) -> bytes:
        return json.dumps(self.value).encode("utf-8")


class FakeTransport:
    def __init__(self, *responses: FakeResponse | Exception) -> None:
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
                "allow_redirects": allow_redirects,
                "body": body,
                "headers": dict(headers),
                "method": method,
                "url": url,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected Apify request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def source(source_type: str, **option_overrides: Any) -> SourceConfig:
    options: dict[str, Any] = {
        "actor_build": "1.2.3",
        "approval_confirmed": True,
        "dataset_page_size": 10,
        "initial_lookback_days": 7,
        "overlap_hours": 24,
        "poll_interval_seconds": 1,
        "token_env": "TEST_APIFY_TOKEN",
    }
    if source_type == "reddit_apify":
        options.update({"max_comments": 10, "searches": ['"Example Product"']})
    else:
        options.update(
            {
                "exclude_retweets": True,
                "search_terms": ['"Example Product"'],
                "sort": "Latest",
                "tweet_language": "en",
            }
        )
    options.update(option_overrides)
    return SourceConfig(
        id=f"{source_type}-test",
        type=source_type,
        enabled=True,
        max_items=20,
        options=options,
        policy=PolicyCapabilities(
            acquisition_mode="third_party_scraper",
            approval_required=True,
            approval_reference="Operator-reviewed platform and Apify terms",
            remote_processing_allowed=True,
            raw_ttl_hours=48 if source_type == "reddit_apify" else 24,
            deletion_reconcile_interval_hours=(
                48 if source_type == "reddit_apify" else 24
            ),
            max_cost_usd=2.0,
            policy_version="apify-2026-09-25",
            policy_version_checked_at="2026-09-25",
        ),
    )


def app_config(selected: SourceConfig, *, total_timeout: float = 30) -> AppConfig:
    root = Path("/tmp/feedback-apify-tests")
    return AppConfig(
        path=root / "feedback.yml",
        root=root,
        product=ProductConfig(
            name="Example Product",
            aliases=("ExampleApp",),
            exclusions=("jobs",),
        ),
        storage=StorageConfig(root / "feedback.db"),
        privacy=PrivacyConfig(root / "salt"),
        limits=LimitsConfig(
            max_items_per_source=1_000,
            total_timeout_seconds=total_timeout,
        ),
        analysis=AnalysisConfig(),
        outputs=OutputConfig(root / "reports"),
        sources=(selected,),
        config_hash="cfg_apify_test",
    )


def run_response(
    *,
    status: str = "SUCCEEDED",
    run_id: str = "run123",
    dataset_id: str = "dataset123",
    cost: float = 0.02,
) -> FakeResponse:
    return FakeResponse(
        201 if status != "STATUS_GET" else 200,
        {
            "data": {
                "buildId": "build123",
                "buildNumber": "1.2.3",
                "defaultDatasetId": dataset_id,
                "id": run_id,
                "status": "SUCCEEDED" if status == "STATUS_GET" else status,
                "usageTotalUsd": cost,
            }
        },
    )


def reddit_item(item_id: str = "t3_abc") -> dict[str, Any]:
    return {
        "body": "Sync fails after reconnecting.",
        "communityName": "r/example",
        "createdAt": "2026-09-24T10:00:00.000Z",
        "dataType": "post",
        "id": item_id,
        "numberOfComments": 4,
        "title": "Example Product feedback",
        "upVotes": 8,
        "url": "https://www.reddit.com/r/example/comments/abc/feedback/",
        "username": "person-one",
    }


def x_item(item_id: str = "1728108619189874825") -> dict[str, Any]:
    return {
        "author": {
            "followers": 999,
            "id": "44196397",
            "name": "A Person",
            "profilePicture": "https://example.test/avatar.png",
            "userName": "person_one",
        },
        "createdAt": "Fri Nov 24 17:49:36 +0000 2023",
        "id": item_id,
        "isQuote": False,
        "isReply": False,
        "isRetweet": False,
        "lang": "en",
        "likeCount": 7,
        "replyCount": 2,
        "retweetCount": 1,
        "text": "Example Product should make sync easier.",
        "type": "tweet",
        "url": f"https://x.com/person_one/status/{item_id}",
    }


@patch.dict(os.environ, {"TEST_APIFY_TOKEN": "apify-test-token"}, clear=False)
def test_reddit_actor_run_is_bounded_checkpointed_and_normalized() -> None:
    selected = source("reddit_apify")
    transport = FakeTransport(
        run_response(),
        FakeResponse(200, [reddit_item()], {"X-Apify-Pagination-Total": "1"}),
    )
    progress: list[CollectionResult] = []
    connector = RedditApifyConnector(
        ConnectorContext(
            app_config(selected),
            selected,
            "author-salt",
            http=transport,
            checkpoint=progress.append,
        )
    )

    result = connector.collect()

    assert result.stop_reason == "complete"
    assert len(result.records) == 1
    assert len(progress) == 2
    assert progress[0].stop_reason == "actor_started"
    assert progress[1].stop_reason == "dataset_in_progress"
    record = result.records[0]
    assert record.source_type == "reddit_apify"
    assert record.native_id == "t3_abc"
    assert record.author_key and "person-one" not in record.author_key
    assert record.metadata["actor_run_id"] == "run123"
    assert record.metadata["actor_build_number"] == "1.2.3"
    assert "username" not in record.metadata

    start = transport.calls[0]
    assert start["method"] == "POST"
    assert urlsplit(start["url"]).hostname == "api.apify.com"
    assert "apify-test-token" not in start["url"]
    assert start["headers"]["Authorization"] == "Bearer apify-test-token"
    query = parse_qs(urlsplit(start["url"]).query)
    assert query["build"] == ["1.2.3"]
    assert query["forcePermissionLevel"] == ["LIMITED_PERMISSIONS"]
    assert query["maxItems"] == ["20"]
    assert query["maxTotalChargeUsd"] == ["2.0"]
    actor_input = json.loads(start["body"])
    assert actor_input["includeNSFW"] is False
    assert actor_input["searchCommunities"] is False
    assert actor_input["searchUsers"] is False
    assert actor_input["includeMediaLinks"] is False


@patch.dict(os.environ, {"TEST_APIFY_TOKEN": "apify-test-token"}, clear=False)
def test_x_actor_discards_profile_fields_and_deduplicates_results() -> None:
    selected = source("x_apify")
    transport = FakeTransport(
        run_response(),
        FakeResponse(200, [x_item(), x_item()], {"x-apify-pagination-total": "2"}),
    )
    connector = XApifyConnector(
        ConnectorContext(app_config(selected), selected, "author-salt", http=transport)
    )

    result = connector.collect()

    assert result.resources_read == 2
    assert len(result.records) == 1
    record = result.records[0]
    assert record.source_type == "x_apify"
    assert record.canonical_url.endswith("/1728108619189874825")
    assert record.created_at == "2023-11-24T17:49:36Z"
    assert record.metadata["language"] == "en"
    assert "followers" not in record.metadata
    assert "name" not in record.metadata
    actor_input = json.loads(transport.calls[0]["body"])
    assert actor_input["searchTerms"] == ['"Example Product" -filter:retweets']
    assert actor_input["tweetLanguage"] == "en"


@patch.dict(os.environ, {"TEST_APIFY_TOKEN": "apify-test-token"}, clear=False)
def test_active_run_is_resumed_without_starting_another_paid_actor() -> None:
    selected = source("x_apify")
    base_connector = XApifyConnector(
        ConnectorContext(app_config(selected), selected, "author-salt", http=FakeTransport())
    )
    settings = base_connector._common_settings(require_secret=True)
    checkpoint = ApifyCheckpoint(
        kind="x_apify",
        scope=base_connector._scope(settings),
        high_water_at="2026-09-20T00:00:00Z",
        run_id="run123",
        dataset_id="dataset123",
        offset=1,
        pending_high_water_at="2026-09-25T00:00:00Z",
    ).encode()
    transport = FakeTransport(
        run_response(status="STATUS_GET"),
        FakeResponse(200, [x_item("1728108619189874826")], {"x-apify-pagination-total": "2"}),
    )
    connector = XApifyConnector(
        ConnectorContext(app_config(selected), selected, "author-salt", http=transport)
    )

    result = connector.collect(cursor=checkpoint)

    assert result.stop_reason == "complete"
    assert transport.calls[0]["method"] == "GET"
    assert "/v2/actor-runs/run123" in transport.calls[0]["url"]
    assert all(call["method"] != "POST" for call in transport.calls)
    assert "offset=1" in transport.calls[1]["url"]


@patch.dict(os.environ, {"TEST_APIFY_TOKEN": "apify-test-token"}, clear=False)
def test_running_actor_returns_durable_resume_state_at_local_deadline() -> None:
    selected = source("reddit_apify")
    transport = FakeTransport(run_response(status="RUNNING"))
    connector = RedditApifyConnector(
        ConnectorContext(
            app_config(selected, total_timeout=0.1),
            selected,
            "author-salt",
            http=transport,
        )
    )

    result = connector.collect()

    assert result.stop_reason == "actor_running"
    assert result.cursor is not None
    assert len(transport.calls) == 1


@patch.dict(os.environ, {"TEST_APIFY_TOKEN": "apify-test-token"}, clear=False)
def test_dataset_failure_preserves_completed_page_and_offset() -> None:
    selected = source("reddit_apify", dataset_page_size=1)
    selected = SourceConfig(
        selected.id,
        selected.type,
        selected.enabled,
        2,
        selected.options,
        selected.policy,
    )
    transport = FakeTransport(
        run_response(),
        FakeResponse(200, [reddit_item()], {"x-apify-pagination-total": "2"}),
        CollectionError("synthetic dataset outage"),
    )
    connector = RedditApifyConnector(
        ConnectorContext(app_config(selected), selected, "author-salt", http=transport)
    )

    with pytest.raises(PartialCollectionError) as raised:
        connector.collect()

    partial = raised.value.result
    assert len(partial.records) == 1
    assert partial.resources_read == 1
    assert partial.cursor is not None
    state = json.loads(partial.cursor)
    assert state["run_id"] == "run123"
    assert state["offset"] == 1


def test_apify_check_is_local_and_requires_token() -> None:
    selected = source("x_apify")
    transport = FakeTransport()
    connector = XApifyConnector(
        ConnectorContext(app_config(selected), selected, "author-salt", http=transport)
    )

    with patch.dict(os.environ, {}, clear=True):
        result = connector.check(probe=True)

    assert result[0].status == "error"
    assert "TEST_APIFY_TOKEN" in result[0].message
    assert transport.calls == []


def test_apify_plan_rejects_arbitrary_actor_input_urls_without_network() -> None:
    selected = source(
        "x_apify",
        search_terms=None,
        start_urls=["https://internal.example.test/private"],
    )
    # Remove the explicit null search option; runtime configuration never
    # accepts both input modes, even if one is null.
    selected.options.pop("search_terms")
    connector = XApifyConnector(
        ConnectorContext(app_config(selected), selected, "author-salt", http=FakeTransport())
    )

    with pytest.raises(ConfigurationError, match="permitted social origins"):
        connector.plan()
