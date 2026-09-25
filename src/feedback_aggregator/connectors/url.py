"""Exact public-page connector with no crawling or ambient browser state."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from typing import Any

from ..errors import CollectionError, ConfigurationError
from ..http_client import SafeHttpClient
from ..models import CheckItem, CollectionPlan, CollectionResult, RawRecord, utc_now
from ..policy import expiry_timestamp
from ..security import safe_display_url, validate_url
from ..util import sanitize_text, stable_hash
from .base import Connector, connector_note
from .json_file import strict_json_loads


class _VisibleTextParser(HTMLParser):
    """Extract readable text without executing or interpreting page content."""

    _SKIPPED = {"script", "style", "noscript", "template", "svg", "canvas"}
    _BREAKS = {
        "p",
        "div",
        "br",
        "li",
        "article",
        "section",
        "header",
        "footer",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self._parts: list[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        lowered = tag.lower()
        if lowered in self._SKIPPED:
            self._skip_depth += 1
        elif lowered == "title":
            self._in_title = True
        elif lowered in self._BREAKS and self._parts:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in self._SKIPPED and self._skip_depth:
            self._skip_depth -= 1
        elif lowered == "title":
            self._in_title = False
        elif lowered in self._BREAKS and self._parts:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        cleaned = sanitize_text(data, max_chars=20_000)
        if not cleaned:
            return
        if self._in_title and not self.title:
            self.title = cleaned[:500]
        self._parts.append(cleaned)

    def text(self) -> str:
        return sanitize_text(" ".join(self._parts))


def extract_response_text(body: bytes, content_type: str) -> tuple[str, dict[str, Any]]:
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError:
        decoded = body.decode("utf-8", errors="replace")
    if content_type == "text/html":
        parser = _VisibleTextParser()
        try:
            parser.feed(decoded)
            parser.close()
        except Exception as exc:
            raise CollectionError("The HTML response could not be parsed safely") from exc
        return parser.text(), {"title": parser.title}
    if content_type == "application/json" or content_type.endswith("+json"):
        try:
            value = strict_json_loads(decoded)
        except (ValueError, json.JSONDecodeError) as exc:
            raise CollectionError("The URL returned invalid JSON") from exc
        if isinstance(value, dict):
            for key in ("text", "body", "content", "description", "title"):
                if isinstance(value.get(key), str) and value[key].strip():
                    return sanitize_text(value[key]), {"json_field": key}
        return sanitize_text(json.dumps(value, ensure_ascii=False, sort_keys=True)), {
            "json_field": "document"
        }
    return sanitize_text(decoded), {}


class UrlConnector(Connector):
    def _urls(self) -> tuple[str, ...]:
        raw = self.source.options.get("urls", [])
        if not isinstance(raw, list) or not raw or not all(isinstance(value, str) for value in raw):
            raise ConfigurationError(f"Source {self.source.id} requires options.urls")
        return tuple(raw)

    def _client(self) -> SafeHttpClient:
        if not isinstance(self.context.http, SafeHttpClient):
            raise CollectionError("The safe URL transport is not configured")
        return self.context.http

    def check(self, *, probe: bool = False) -> list[CheckItem]:
        results: list[CheckItem] = []
        try:
            urls = self._urls()
        except ConfigurationError as exc:
            return [connector_note(self.context, str(exc), "error")]
        for raw_url in urls:
            try:
                target = validate_url(
                    raw_url, allow_http=self.source.options.get("allow_http") is True
                )
                message = f"Valid exact URL: {safe_display_url(target.url)}"
                if probe:
                    response = self._client().request("HEAD", target.url)
                    if response.status >= 400:
                        raise CollectionError(f"Probe returned HTTP {response.status}")
                    message = f"Read-only probe returned HTTP {response.status}"
                results.append(
                    CheckItem(f"url:{safe_display_url(target.url)}", "ok", message, self.source.id)
                )
            except Exception as exc:
                results.append(
                    CheckItem(
                        "url", "error", sanitize_text(str(exc), max_chars=500), self.source.id
                    )
                )
        return results

    def plan(self) -> CollectionPlan:
        urls = self._urls()
        return CollectionPlan(
            self.source.id,
            self.source.type,
            "\n".join(
                safe_display_url(
                    validate_url(url, allow_http=self.source.options.get("allow_http") is True).url
                )
                for url in urls
            ),
            min(self.source.max_items, len(urls)),
            min(self.source.max_items, len(urls)),
            0.0,
            ("Exact URLs only; no recursive crawling", "Every redirect is revalidated"),
        )

    def collect(self, *, cursor: str | None = None) -> CollectionResult:
        del cursor
        records: list[RawRecord] = []
        client = self._client()
        for raw_url in self._urls():
            if len(records) >= self.source.max_items:
                return CollectionResult.from_records(
                    records,
                    requests_made=len(records),
                    resources_read=len(records),
                    stop_reason="item_cap",
                )
            response = client.get(raw_url)
            if response.status < 200 or response.status >= 300:
                raise CollectionError(
                    f"URL request returned HTTP {response.status}: {safe_display_url(raw_url)}"
                )
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            text, metadata = extract_response_text(response.body, content_type)
            if not text:
                raise CollectionError(
                    f"URL contained no extractable text: {safe_display_url(raw_url)}"
                )
            now = utc_now()
            metadata.update(
                {
                    "content_type": content_type,
                    "http_status": response.status,
                    "input_url": safe_display_url(raw_url),
                    "created_at_inferred": True,
                }
            )
            native_id = stable_hash(response.url, prefix="url_")[:44]
            records.append(
                RawRecord(
                    source_id=self.source.id,
                    source_type="url",
                    native_id=native_id,
                    canonical_url=response.url,
                    text=text,
                    created_at=now,
                    retrieved_at=now,
                    metadata=metadata,
                    query=safe_display_url(raw_url),
                    acquisition_mode="exact_url",
                    policy_assurance="user",
                    expires_at=expiry_timestamp(self.source.policy),
                )
            )
        return CollectionResult.from_records(
            records, requests_made=len(records), resources_read=len(records)
        )
