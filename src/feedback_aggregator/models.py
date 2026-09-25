"""Versioned domain objects shared by connectors, storage, and analysis."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

SCHEMA_VERSION = 1


def utc_now() -> str:
    """Return an RFC 3339 UTC timestamp with second precision."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class PolicyCapabilities:
    """The policy assumptions that constrain one connector."""

    acquisition_mode: str
    approval_required: bool
    approval_reference: str
    credential_owner: str = "operator"
    commercial_use_allowed: bool | None = None
    remote_processing_allowed: bool = False
    raw_ttl_hours: int = 0
    deletion_reconcile_interval_hours: int = 24
    redistribution_mode: str = "ids_links_aggregates"
    cost_per_resource_usd: float = 0.0
    max_cost_usd: float = 0.0
    policy_version: str = ""
    policy_version_checked_at: str = ""

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "PolicyCapabilities":
        def boolean(name: str, default: bool) -> bool:
            raw = value.get(name, default)
            if not isinstance(raw, bool):
                raise ValueError(f"policy.{name} must be true or false")
            return raw

        def optional_boolean(name: str) -> bool | None:
            raw = value.get(name)
            if raw is not None and not isinstance(raw, bool):
                raise ValueError(f"policy.{name} must be true, false, or null")
            return raw

        def nonnegative_integer(name: str, default: int) -> int:
            raw = value.get(name, default)
            if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                raise ValueError(f"policy.{name} must be a non-negative integer")
            return raw

        def nonnegative_number(name: str, default: float) -> float:
            raw = value.get(name, default)
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise ValueError(f"policy.{name} must be a non-negative number")
            result = float(raw)
            if not math.isfinite(result) or result < 0:
                raise ValueError(f"policy.{name} must be a non-negative number")
            return result

        def text(name: str, default: str) -> str:
            raw = value.get(name, default)
            if not isinstance(raw, str):
                raise ValueError(f"policy.{name} must be a string")
            return raw

        reconcile_interval = nonnegative_integer("deletion_reconcile_interval_hours", 24)
        if reconcile_interval < 1:
            raise ValueError("policy.deletion_reconcile_interval_hours must be at least 1")

        return cls(
            acquisition_mode=text("acquisition_mode", "official_api"),
            approval_required=boolean("approval_required", False),
            approval_reference=text("approval_reference", ""),
            credential_owner=text("credential_owner", "operator"),
            commercial_use_allowed=optional_boolean("commercial_use_allowed"),
            remote_processing_allowed=boolean("remote_processing_allowed", False),
            raw_ttl_hours=nonnegative_integer("raw_ttl_hours", 0),
            deletion_reconcile_interval_hours=reconcile_interval,
            redistribution_mode=text("redistribution_mode", "ids_links_aggregates"),
            cost_per_resource_usd=nonnegative_number("cost_per_resource_usd", 0.0),
            max_cost_usd=nonnegative_number("max_cost_usd", 0.0),
            policy_version=text("policy_version", ""),
            policy_version_checked_at=text("policy_version_checked_at", ""),
        )


@dataclass(frozen=True, slots=True)
class CollectionPlan:
    """A non-mutating description of a connector run."""

    source_id: str
    source_type: str
    query: str
    max_items: int
    estimated_requests: int
    upper_bound_cost_usd: float
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["notes"] = list(self.notes)
        return data


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One normalized, minimally retained source record."""

    source_id: str
    source_type: str
    native_id: str
    canonical_url: str
    text: str
    created_at: str
    retrieved_at: str
    author_key: str = ""
    engagement: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    query: str = ""
    acquisition_mode: str = "user_file"
    policy_assurance: str = "connector"
    expires_at: str | None = None
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CheckItem:
    """One readiness result."""

    name: str
    status: str
    message: str
    source_id: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CollectionResult:
    """Connector output plus cursor and usage metadata."""

    records: tuple[RawRecord, ...]
    cursor: str | None = None
    requests_made: int = 0
    resources_read: int = 0
    cost_usd: float = 0.0
    stop_reason: str = "complete"

    @classmethod
    def from_records(
        cls,
        records: Iterable[RawRecord],
        **kwargs: Any,
    ) -> "CollectionResult":
        return cls(records=tuple(records), **kwargs)
