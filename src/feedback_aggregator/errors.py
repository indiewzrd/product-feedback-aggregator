"""Small, user-facing exception hierarchy.

Exceptions intentionally carry safe messages. Callers should never include source
text, credentials, response bodies, or full environment values in these messages.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import CollectionResult


class FeedbackError(Exception):
    """Base class for an expected application failure."""

    exit_code = 1


class ConfigurationError(FeedbackError):
    """The local configuration is invalid."""

    exit_code = 2


class ReadinessError(FeedbackError):
    """A configured connector is not ready to run."""

    exit_code = 3


class CollectionError(FeedbackError):
    """A source failed during collection."""

    exit_code = 4


class PartialCollectionError(CollectionError):
    """A source failed after producing safely checkpointed collection pages.

    ``result`` contains only fully validated pages and a cursor that resumes at
    the first unfinished page.  Callers may persist it atomically while still
    recording this exception as a source failure; it must never be presented
    as a normal successful collection.
    """

    def __init__(self, message: str, result: CollectionResult) -> None:
        super().__init__(message)
        self.result = result


class SecurityError(FeedbackError):
    """A security boundary rejected an operation."""

    exit_code = 5


class BudgetError(FeedbackError):
    """A paid or bounded operation would exceed a hard limit."""

    exit_code = 6


class NotFoundError(FeedbackError):
    """A requested stored entity does not exist."""

    exit_code = 7


class ProviderError(FeedbackError):
    """An optional semantic provider failed or returned invalid data."""

    exit_code = 8
