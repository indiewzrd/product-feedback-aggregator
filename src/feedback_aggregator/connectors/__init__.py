"""Built-in connector registry."""

from __future__ import annotations

from typing import Type

from .base import Connector, ConnectorContext
from .external import ExternalConnector
from .json_file import JsonFileConnector


def connector_for(context: ConnectorContext) -> Connector:
    """Construct a built-in connector without loading arbitrary plugins."""

    from .reddit import RedditConnector
    from .reddit_apify import RedditApifyConnector
    from .url import UrlConnector
    from .x import XConnector
    from .x_apify import XApifyConnector

    registry: dict[str, Type[Connector]] = {
        "json": JsonFileConnector,
        "url": UrlConnector,
        "external": ExternalConnector,
        "reddit": RedditConnector,
        "x": XConnector,
        "reddit_apify": RedditApifyConnector,
        "x_apify": XApifyConnector,
    }
    return registry[context.source.type](context)


__all__ = ["Connector", "ConnectorContext", "connector_for"]
