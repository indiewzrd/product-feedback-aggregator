from __future__ import annotations

from datetime import date, datetime, timezone

from feedback_aggregator.config import SourceConfig
from feedback_aggregator.models import PolicyCapabilities
from feedback_aggregator.policy import expiry_timestamp, policy_checks


def source(reviewed: str) -> SourceConfig:
    return SourceConfig(
        id="reddit-feedback",
        type="reddit",
        enabled=True,
        max_items=10,
        options={},
        policy=PolicyCapabilities(
            acquisition_mode="official_api",
            approval_required=True,
            approval_reference="Official policy",
            raw_ttl_hours=48,
            policy_version="reddit-test",
            policy_version_checked_at=reviewed,
        ),
    )


def test_policy_freshness_warns_after_ninety_days() -> None:
    checks = policy_checks(source("2026-01-01"), today=date(2026, 9, 25))
    assert any(item.status == "warning" and item.name == "policy-freshness" for item in checks)


def test_policy_review_date_rejects_suffixes_and_whitespace() -> None:
    for reviewed in ("2026-09-25junk", " 2026-09-25", "2026-09-25 "):
        checks = policy_checks(source(reviewed), today=date(2026, 9, 25))
        assert any(item.status == "error" and item.name == "policy-freshness" for item in checks)


def test_expiry_uses_connector_ttl() -> None:
    result = expiry_timestamp(
        source("2026-09-25").policy,
        now=datetime(2026, 9, 25, tzinfo=timezone.utc),
    )
    assert result == "2026-09-27T00:00:00Z"


def test_apify_policy_requires_remote_processing_and_scraper_mode() -> None:
    base = source("2026-09-25")
    apify = SourceConfig(
        id="reddit-apify",
        type="reddit_apify",
        enabled=True,
        max_items=10,
        options={},
        policy=PolicyCapabilities(
            acquisition_mode="official_api",
            approval_required=True,
            approval_reference="Test reference",
            remote_processing_allowed=False,
            raw_ttl_hours=48,
            policy_version=base.policy.policy_version,
            policy_version_checked_at=base.policy.policy_version_checked_at,
        ),
    )

    checks = policy_checks(apify, today=date(2026, 9, 25))

    assert any(item.name == "acquisition-mode" and item.status == "error" for item in checks)
    assert any(item.name == "remote-processing" and item.status == "error" for item in checks)
