"""Connector contract used by every acquisition path."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable

from ..config import AppConfig, SourceConfig
from ..models import CheckItem, CollectionPlan, CollectionResult

CONNECTOR_CONTRACT_VERSION = 2


@dataclass(slots=True)
class ConnectorContext:
    config: AppConfig
    source: SourceConfig
    author_salt: str
    http: Any | None = None
    stdin_bytes: bytes | None = None
    checkpoint: Callable[[CollectionResult], None] | None = None


class Connector(ABC):
    """Small interface that keeps platform transports replaceable."""

    contract_version = CONNECTOR_CONTRACT_VERSION

    def __init__(self, context: ConnectorContext) -> None:
        self.context = context
        self.config = context.config
        self.source = context.source

    @abstractmethod
    def check(self, *, probe: bool = False) -> list[CheckItem]:
        """Return readiness results. Network access is forbidden unless probe is true."""

    @abstractmethod
    def plan(self) -> CollectionPlan:
        """Describe a bounded collection without accessing the source."""

    @abstractmethod
    def collect(self, *, cursor: str | None = None) -> CollectionResult:
        """Collect at most the configured hard limit."""

    def reconcile(self, native_ids: tuple[str, ...]) -> set[str]:
        """Return native IDs that must be removed. Default connectors have no remote state."""

        del native_ids
        return set()

    def purge(self, native_ids: tuple[str, ...]) -> None:
        """Forget connector-owned local state; built-ins keep none outside SQLite."""

        del native_ids


def connector_note(context: ConnectorContext, message: str, status: str = "ok") -> CheckItem:
    return CheckItem(
        message=message,
        name=f"connector:{context.source.id}",
        status=status,
        source_id=context.source.id,
    )


__all__ = [
    "CONNECTOR_CONTRACT_VERSION",
    "Connector",
    "ConnectorContext",
    "connector_note",
]
