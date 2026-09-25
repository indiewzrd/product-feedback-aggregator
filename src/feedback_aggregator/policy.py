"""Policy freshness, retention, and capability checks.

Platform policy is deliberately data, not scattered constants. The defaults in
the configuration are conservative and every public release must recheck them.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone

from .config import SourceConfig
from .models import CheckItem, PolicyCapabilities

POLICY_STALE_AFTER_DAYS = 90
_REVIEW_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def parse_review_date(value: str) -> date | None:
    if not isinstance(value, str) or _REVIEW_DATE.fullmatch(value) is None:
        return None
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def policy_checks(source: SourceConfig, *, today: date | None = None) -> list[CheckItem]:
    today = today or datetime.now(timezone.utc).date()
    policy = source.policy
    results: list[CheckItem] = []
    if not policy.policy_version:
        results.append(CheckItem("policy-version", "error", "Policy version is missing", source.id))
    if not policy.approval_reference:
        results.append(
            CheckItem("policy-reference", "error", "Policy reference is missing", source.id)
        )
    reviewed = parse_review_date(policy.policy_version_checked_at)
    if reviewed is None:
        results.append(
            CheckItem(
                "policy-freshness", "error", "Policy review date must use YYYY-MM-DD", source.id
            )
        )
    elif reviewed > today:
        results.append(
            CheckItem("policy-freshness", "error", "Policy review date is in the future", source.id)
        )
    else:
        age = (today - reviewed).days
        status = "warning" if age > POLICY_STALE_AFTER_DAYS else "ok"
        results.append(
            CheckItem(
                "policy-freshness",
                status,
                f"Policy metadata was reviewed {age} days ago",
                source.id,
            )
        )
    if source.type in {"reddit", "x"} and policy.acquisition_mode != "official_api":
        results.append(
            CheckItem(
                "acquisition-mode",
                "error",
                "Social connectors require official_api acquisition",
                source.id,
            )
        )
    if source.type in {"reddit_apify", "x_apify"}:
        if policy.acquisition_mode != "third_party_scraper":
            results.append(
                CheckItem(
                    "acquisition-mode",
                    "error",
                    "Apify social connectors require third_party_scraper acquisition",
                    source.id,
                )
            )
        if not policy.remote_processing_allowed:
            results.append(
                CheckItem(
                    "remote-processing",
                    "error",
                    "Apify collection requires explicit remote-processing approval",
                    source.id,
                )
            )
    if policy.raw_ttl_hours < 0:
        results.append(
            CheckItem("retention", "error", "Raw retention cannot be negative", source.id)
        )
    return results


def expiry_timestamp(policy: PolicyCapabilities, *, now: datetime | None = None) -> str | None:
    if policy.raw_ttl_hours <= 0:
        return None
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return (
        (moment + timedelta(hours=policy.raw_ttl_hours))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def can_export_verbatim(policy: PolicyCapabilities) -> bool:
    return policy.redistribution_mode in {"verbatim", "user_asserted", "local_only"}


def requires_local_processing(policy: PolicyCapabilities) -> bool:
    return not policy.remote_processing_allowed
