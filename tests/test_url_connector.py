from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from feedback_aggregator.config import load_config
from feedback_aggregator.connectors.base import ConnectorContext
from feedback_aggregator.connectors.url import UrlConnector, extract_response_text
from feedback_aggregator.http_client import HttpResponse


class _SequenceClient:
    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = list(bodies)

    def get(self, url: str) -> HttpResponse:
        return HttpResponse(
            url=url,
            status=200,
            reason="OK",
            headers={"content-type": "text/plain"},
            body=self.bodies.pop(0),
        )


def test_html_extraction_ignores_active_content() -> None:
    text, metadata = extract_response_text(
        b"<html><head><title>Feedback</title><script>steal()</script></head><body><p>Search is slow.</p><style>bad</style></body></html>",
        "text/html",
    )
    assert text == "Feedback\nSearch is slow."
    assert "steal" not in text
    assert metadata["title"] == "Feedback"


def test_json_extraction_prefers_named_text_field() -> None:
    text, metadata = extract_response_text(
        b'{"text":"Please add export","secret":"ignored"}', "application/json"
    )
    assert text == "Please add export"
    assert metadata["json_field"] == "text"


def test_terminal_controls_are_removed_from_page_text() -> None:
    text, _ = extract_response_text(
        "normal\x1b[31mevil\x1b[0m \u009b31mC1 \u009dtitle\u009c \u202etxt.exe".encode(),
        "text/plain",
    )
    assert text == "normalevil 31mC1 title txt.exe"


def test_url_record_identity_is_stable_when_page_content_changes() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        config_path = root / "feedback.yml"
        config_path.write_text(
            """
version: 1
product: {name: Example}
sources:
  - id: pages
    type: url
    options: {urls: [https://example.com/feedback]}
    policy: {policy_version: local-v1, policy_version_checked_at: 2026-09-25}
""",
            encoding="utf-8",
        )
        config = load_config(config_path)
        client = _SequenceClient([b"Example crashes", b"Example now works"])
        connector = UrlConnector(
            ConnectorContext(
                config,
                config.sources[0],
                "salt",
                http=None,
            )
        )
        with patch.object(connector, "_client", return_value=client):
            first = connector.collect().records[0]
            second = connector.collect().records[0]
        assert first.native_id == second.native_id
        assert first.text != second.text
