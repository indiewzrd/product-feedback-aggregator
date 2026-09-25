from __future__ import annotations

import gzip
import socket
import threading
import time
from collections.abc import Mapping

import pytest

from feedback_aggregator.errors import CollectionError
from feedback_aggregator.http_client import (
    ApiHttpClient,
    HttpResponse,
    HttpTimeoutError,
    PinnedHTTPSConnection,
    SafeHttpClient,
    UnsafeResponseError,
)
from feedback_aggregator.security import (
    UnsafeUrlError,
    is_public_ip,
    is_social_domain,
    redact_secrets,
    resolve_public_addresses,
    safe_display_url,
    validate_url,
)

PUBLIC_V4 = "93.184.216.34"


def resolver_for(mapping: Mapping[str, list[str]]):
    def resolve(host: str, port: int, **_: object):
        if host not in mapping:
            raise socket.gaierror("not found")
        records = []
        for address in mapping[host]:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
            records.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
        return records

    return resolve


class FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        reason: str = "OK",
        headers: Mapping[str, str] | None = None,
        chunks: list[bytes] | None = None,
        on_read=None,
    ) -> None:
        self.status = status
        self.reason = reason
        self._headers = {key.lower(): value for key, value in (headers or {}).items()}
        self._chunks = list(chunks or [])
        self._on_read = on_read
        self.closed = False

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self._headers.get(name.lower(), default)

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers.items())

    def read(self, amount: int | None = None) -> bytes:
        if self._on_read is not None:
            self._on_read()
        return self._chunks.pop(0) if self._chunks else b""

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, str, object, dict[str, str]]] = []
        self.sock = None
        self.closed = False

    def request(self, method: str, url: str, body=None, headers=None) -> None:
        self.requests.append((method, url, body, dict(headers or {})))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class RecordingFactory:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, int, str, float]] = []
        self.connections: list[FakeConnection] = []

    def __call__(self, scheme, host, port, address, timeout, context):
        self.calls.append((scheme, host, port, address, timeout))
        connection = FakeConnection(self.responses.pop(0))
        self.connections.append(connection)
        return connection


def make_client(factory: RecordingFactory, **kwargs) -> SafeHttpClient:
    return SafeHttpClient(
        resolver=resolver_for(
            {
                "example.com": [PUBLIC_V4],
                "other.example": ["142.250.74.14"],
                "internal.example": ["10.0.0.8"],
            }
        ),
        connection_factory=factory,
        **kwargs,
    )


def test_validate_url_normalizes_idna_and_request_target() -> None:
    target = validate_url("https://b\N{LATIN SMALL LETTER U WITH DIAERESIS}cher.example:8443/a?q=1")

    assert target.host == "xn--bcher-kva.example"
    assert target.port == 8443
    assert target.request_target == "/a?q=1"
    assert target.url == "https://xn--bcher-kva.example:8443/a?q=1"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "file:///etc/passwd",
        "https://user:password@example.com/",
        "https://example.com/#fragment",
        "https://example.com\\@127.0.0.1/",
        "https://example.com/\r\nX-Evil: yes",
        " https://example.com/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://[fec0::1]/",
        "https://[::ffff:127.0.0.1]/",
    ],
)
def test_validate_url_rejects_ambiguous_or_non_public_targets(url: str) -> None:
    with pytest.raises(UnsafeUrlError):
        validate_url(url)


@pytest.mark.parametrize(
    "host",
    ["reddit.com", "old.reddit.com", "x.com", "api.x.com", "twitter.com", "t.co"],
)
def test_social_domain_and_subdomains_are_blocked(host: str) -> None:
    assert is_social_domain(host)
    with pytest.raises(UnsafeUrlError, match="dedicated"):
        validate_url(f"https://{host}/some/path")


def test_social_domain_suffix_check_does_not_overmatch() -> None:
    assert not is_social_domain("notreddit.com")
    assert validate_url("https://notreddit.com/").host == "notreddit.com"


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("::ffff:8.8.8.8", True),
        ("127.0.0.1", False),
        ("10.0.0.1", False),
        ("169.254.169.254", False),
        ("100.64.0.1", False),
        ("224.0.0.1", False),
        ("0.0.0.0", False),
        ("::1", False),
        ("fe80::1", False),
        ("fec0::", False),
        ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", False),
        ("::ffff:127.0.0.1", False),
    ],
)
def test_public_ip_policy_including_ipv4_mapped(address: str, expected: bool) -> None:
    assert is_public_ip(address) is expected


def test_dns_rejects_entire_answer_set_if_one_address_is_private() -> None:
    target = validate_url("https://example.com/")
    resolver = resolver_for({"example.com": [PUBLIC_V4, "127.0.0.1"]})

    with pytest.raises(UnsafeUrlError, match="non-public"):
        resolve_public_addresses(target, resolver=resolver)


def test_dns_rejects_deprecated_ipv6_site_local_space() -> None:
    target = validate_url("https://example.com/")
    with pytest.raises(UnsafeUrlError, match="non-public"):
        resolve_public_addresses(
            target,
            resolver=resolver_for({"example.com": ["fec0::1"]}),
        )


def test_client_connects_to_validated_ip_but_uses_original_host() -> None:
    factory = RecordingFactory(
        [FakeResponse(headers={"Content-Type": "text/plain"}, chunks=[b"hello"])]
    )
    client = make_client(factory)

    response = client.get("https://example.com/path?q=feedback")

    assert response.body == b"hello"
    assert factory.calls[0][:4] == ("https", "example.com", 443, PUBLIC_V4)
    assert factory.connections[0].requests[0][1] == "/path?q=feedback"


def test_ambient_proxy_environment_is_ignored(monkeypatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9999")
    factory = RecordingFactory(
        [FakeResponse(headers={"Content-Type": "text/plain"}, chunks=[b"direct"])]
    )

    response = make_client(factory).get("https://example.com/")

    assert response.body == b"direct"
    assert factory.calls[0][:4] == ("https", "example.com", 443, PUBLIC_V4)


def test_https_connection_pins_ip_and_preserves_sni(monkeypatch) -> None:
    raw_socket = object()
    calls: dict[str, object] = {}

    def create_connection(address, timeout, source_address):
        calls["address"] = address
        calls["timeout"] = timeout
        calls["source_address"] = source_address
        return raw_socket

    class Context:
        def wrap_socket(self, sock, *, server_hostname):
            calls["wrapped"] = sock
            calls["server_hostname"] = server_hostname
            return "tls-socket"

    monkeypatch.setattr(socket, "create_connection", create_connection)
    connection = PinnedHTTPSConnection(
        "example.com",
        443,
        PUBLIC_V4,
        timeout=4.0,
        context=Context(),  # type: ignore[arg-type]
    )

    connection.connect()

    assert calls["address"] == (PUBLIC_V4, 443)
    assert calls["server_hostname"] == "example.com"
    assert connection.sock == "tls-socket"


def test_redirect_is_revalidated_and_private_destination_is_never_connected() -> None:
    factory = RecordingFactory(
        [FakeResponse(status=302, headers={"Location": "https://internal.example/private"})]
    )
    client = make_client(factory)

    with pytest.raises(UnsafeUrlError, match="non-public"):
        client.get("https://example.com/start")

    assert len(factory.calls) == 1
    assert factory.connections[0].closed


def test_https_redirect_cannot_downgrade_to_http() -> None:
    factory = RecordingFactory(
        [FakeResponse(status=302, headers={"Location": "http://example.com/plain"})]
    )

    with pytest.raises(UnsafeUrlError, match="downgrade"):
        make_client(factory, allow_http=True).get("https://example.com/start")

    assert len(factory.calls) == 1


def test_cross_origin_redirect_drops_authorization_and_does_not_replay_cookie() -> None:
    factory = RecordingFactory(
        [
            FakeResponse(
                status=302,
                headers={
                    "Location": "https://other.example/final",
                    "Set-Cookie": "session=evil",
                },
            ),
            FakeResponse(headers={"Content-Type": "application/json"}, chunks=[b"{}"]),
        ]
    )
    client = make_client(factory, allow_authorization=True)

    client.get("https://example.com/start", headers={"Authorization": "Bearer secret"})

    first_headers = factory.connections[0].requests[0][3]
    second_headers = factory.connections[1].requests[0][3]
    assert first_headers["Authorization"] == "Bearer secret"
    assert "Authorization" not in second_headers
    assert all(name.lower() != "cookie" for name in second_headers)


def test_cookie_and_transport_headers_cannot_be_supplied() -> None:
    factory = RecordingFactory([])
    client = make_client(factory)

    with pytest.raises(UnsafeUrlError, match="Cookie"):
        client.get("https://example.com/", headers={"Cookie": "session=secret"})


def test_authorization_requires_explicit_opt_in() -> None:
    factory = RecordingFactory([])

    with pytest.raises(UnsafeUrlError, match="explicitly authorized"):
        make_client(factory).get("https://example.com/", headers={"Authorization": "Bearer secret"})


def test_api_client_allows_only_bounded_post_to_explicit_host_and_path() -> None:
    factory = RecordingFactory(
        [FakeResponse(headers={"Content-Type": "application/json"}, chunks=[b'{"ok": true}'])]
    )
    client = ApiHttpClient(
        ["example.com"],
        allowed_post_paths=["/oauth/token"],
        resolver=resolver_for({"example.com": [PUBLIC_V4]}),
        connection_factory=factory,
    )
    body = b"grant_type=client_credentials"

    response = client.request(
        "POST",
        "https://example.com/oauth/token",
        headers={
            "Authorization": "Basic canary",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body=body,
    )

    sent = factory.connections[0].requests[0]
    assert sent[:3] == ("POST", "/oauth/token", body)
    assert response.json() == {"ok": True}


def test_api_client_does_not_follow_redirect_by_default() -> None:
    factory = RecordingFactory(
        [
            FakeResponse(
                status=302,
                reason="Found",
                headers={
                    "Location": "https://other.example/",
                    "Set-Cookie": "secret=value",
                },
                chunks=[b"redirect body is intentionally ignored"],
            )
        ]
    )
    client = ApiHttpClient(
        ["example.com"],
        resolver=resolver_for({"example.com": [PUBLIC_V4]}),
        connection_factory=factory,
    )

    response = client.request("GET", "https://example.com/api", allow_redirects=False)

    assert response.status == 302
    assert response.body == b""
    assert response.headers["location"] == "https://other.example/"
    assert "set-cookie" not in response.headers
    assert len(factory.calls) == 1


def test_api_client_rejects_unlisted_host_path_and_oversized_body() -> None:
    factory = RecordingFactory([])
    client = ApiHttpClient(
        ["example.com"],
        allowed_post_paths=["/oauth/token"],
        max_request_bytes=4,
        resolver=resolver_for({"example.com": [PUBLIC_V4]}),
        connection_factory=factory,
    )
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    with pytest.raises(UnsafeUrlError, match="host allowlist"):
        client.request("GET", "https://other.example/api")
    with pytest.raises(UnsafeUrlError, match="API path"):
        client.request("POST", "https://example.com/not-oauth", headers=headers, body=b"x=1")
    with pytest.raises(UnsafeUrlError, match="size limit"):
        client.request("POST", "https://example.com/oauth/token", headers=headers, body=b"12345")
    assert not factory.calls


def test_api_client_revalidates_opted_in_get_redirect_against_host_allowlist() -> None:
    factory = RecordingFactory(
        [FakeResponse(status=302, headers={"Location": "https://other.example/api"})]
    )
    client = ApiHttpClient(
        ["example.com"],
        resolver=resolver_for({"example.com": [PUBLIC_V4]}),
        connection_factory=factory,
    )

    with pytest.raises(UnsafeUrlError, match="host allowlist"):
        client.request("GET", "https://example.com/api", allow_redirects=True)
    assert len(factory.calls) == 1


def test_api_client_never_follows_post_redirects() -> None:
    client = ApiHttpClient(
        ["example.com"],
        allowed_post_paths=["/oauth/token"],
        resolver=resolver_for({"example.com": [PUBLIC_V4]}),
        connection_factory=RecordingFactory([]),
    )

    with pytest.raises(UnsafeUrlError, match="credential replay"):
        client.request(
            "POST",
            "https://example.com/oauth/token",
            headers={"Content-Type": "application/json"},
            body=b"{}",
            allow_redirects=True,
        )


def test_api_client_does_not_retry_an_uncertain_request_on_another_address() -> None:
    class FailingConnection(FakeConnection):
        def getresponse(self) -> FakeResponse:
            raise OSError("response was lost after request transmission")

    class FailingFactory(RecordingFactory):
        def __call__(self, scheme, host, port, address, timeout, context):
            self.calls.append((scheme, host, port, address, timeout))
            connection = FailingConnection(FakeResponse())
            self.connections.append(connection)
            return connection

    factory = FailingFactory([])
    client = ApiHttpClient(
        ["example.com"],
        resolver=resolver_for({"example.com": [PUBLIC_V4, "142.250.74.14"]}),
        connection_factory=factory,
    )

    with pytest.raises(CollectionError):
        client.request("GET", "https://example.com/api")

    assert len(factory.calls) == 1
    assert len(factory.connections[0].requests) == 1


def test_response_json_rejects_duplicate_keys_and_nonstandard_constants() -> None:
    duplicate = HttpResponse("https://example.com/", 200, "OK", {}, b'{"a": 1, "a": 2}')
    nonstandard = HttpResponse("https://example.com/", 200, "OK", {}, b'{"a": NaN}')

    with pytest.raises(ValueError, match="Duplicate JSON key"):
        duplicate.json()
    with pytest.raises(ValueError, match="Non-standard JSON constant"):
        nonstandard.json()


def test_client_rejects_disallowed_content_type_before_reading_body() -> None:
    response = FakeResponse(headers={"Content-Type": "image/png"}, chunks=[b"not really a png"])
    factory = RecordingFactory([response])

    with pytest.raises(UnsafeResponseError, match="Content-Type"):
        make_client(factory).get("https://example.com/image")

    assert response._chunks == [b"not really a png"]


def test_content_length_and_streamed_size_limits_are_both_enforced() -> None:
    declared = RecordingFactory(
        [
            FakeResponse(
                headers={"Content-Type": "text/plain", "Content-Length": "11"},
                chunks=[b"hello world"],
            )
        ]
    )
    with pytest.raises(UnsafeResponseError, match="download size"):
        make_client(declared, max_download_bytes=10).get("https://example.com/")

    streamed = RecordingFactory(
        [FakeResponse(headers={"Content-Type": "text/plain"}, chunks=[b"123456", b"789012"])]
    )
    with pytest.raises(UnsafeResponseError, match="download size"):
        make_client(streamed, max_download_bytes=10).get("https://example.com/")


def test_gzip_is_decoded_with_a_separate_output_limit() -> None:
    compressed = gzip.compress(b"a" * 2_000)
    factory = RecordingFactory(
        [
            FakeResponse(
                headers={"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                chunks=[compressed],
            )
        ]
    )

    with pytest.raises(UnsafeResponseError, match="decoded size"):
        make_client(factory, max_download_bytes=1_000, max_response_bytes=1_000).get(
            "https://example.com/"
        )


def test_valid_gzip_is_decoded() -> None:
    compressed = gzip.compress(b"safe feedback")
    factory = RecordingFactory(
        [
            FakeResponse(
                headers={"Content-Type": "text/plain", "Content-Encoding": "gzip"},
                chunks=[compressed],
            )
        ]
    )

    assert make_client(factory).get("https://example.com/").body == b"safe feedback"


def test_overall_deadline_applies_while_streaming() -> None:
    class Clock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()

    def advance() -> None:
        clock.value += 0.6

    factory = RecordingFactory(
        [
            FakeResponse(
                headers={"Content-Type": "text/plain"},
                chunks=[b"one", b"two"],
                on_read=advance,
            )
        ]
    )

    with pytest.raises(HttpTimeoutError):
        make_client(factory, total_timeout=1.0, clock=clock).get("https://example.com/")


def test_overall_deadline_is_shared_across_sequential_requests() -> None:
    class Clock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()
    factory = RecordingFactory(
        [FakeResponse(headers={"Content-Type": "text/plain"}, chunks=[b"first"])]
    )
    client = make_client(factory, total_timeout=1.0, clock=clock)

    assert client.get("https://example.com/first").body == b"first"
    clock.value = 1.1

    with pytest.raises(HttpTimeoutError):
        client.get("https://example.com/second")
    assert len(factory.calls) == 1


def test_source_deadline_interrupts_a_trickled_or_stalled_header_read() -> None:
    release = threading.Event()

    class StalledConnection(FakeConnection):
        def getresponse(self) -> FakeResponse:
            release.wait()
            return self.response

    class StalledFactory(RecordingFactory):
        def __call__(self, scheme, host, port, address, timeout, context):
            self.calls.append((scheme, host, port, address, timeout))
            connection = StalledConnection(
                FakeResponse(headers={"Content-Type": "text/plain"}, chunks=[b"late"])
            )
            self.connections.append(connection)
            return connection

    factory = StalledFactory([])
    client = make_client(factory, total_timeout=0.02)
    started = time.monotonic()
    try:
        with pytest.raises(HttpTimeoutError, match="source-wide"):
            client.get("https://example.com/slow-headers")
    finally:
        release.set()

    assert time.monotonic() - started < 0.5
    assert factory.connections[0].closed


def test_dns_resolution_obeys_total_deadline() -> None:
    release = threading.Event()

    def stuck_resolver(host: str, port: int, **kwargs):
        release.wait()
        return []

    client = SafeHttpClient(
        resolver=stuck_resolver,
        connection_factory=RecordingFactory([]),
        total_timeout=0.01,
    )
    try:
        with pytest.raises(HttpTimeoutError):
            client.get("https://example.com/")
    finally:
        release.set()


def test_secret_redaction_and_safe_url_display() -> None:
    secret = "canary-super-secret"
    message = (
        f"Authorization: Bearer {secret}; client_secret={secret}; "
        f"url=https://example.com/path?access_token={secret}"
    )

    redacted = redact_secrets(message, [secret])

    assert secret not in redacted
    assert redacted.count("[REDACTED]") >= 3
    assert safe_display_url(f"https://user:{secret}@example.com/path?token={secret}") == (
        "https://example.com/...?\u005bREDACTED\u005d"
    )


def test_header_newline_is_rejected_before_connection() -> None:
    factory = RecordingFactory([])

    with pytest.raises(UnsafeUrlError, match="control character"):
        make_client(factory).get("https://example.com/", headers={"X-Test": "ok\r\nevil: yes"})

    assert not factory.calls
