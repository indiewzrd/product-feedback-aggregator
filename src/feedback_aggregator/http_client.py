"""A small, SSRF-resistant HTTP client built only on the Python standard library.

The client intentionally implements a narrow feature set: read-only requests,
direct sockets (no ambient proxy or cookie jar), bounded redirects, and bounded
streaming response decompression.  DNS results are validated and the socket is
connected to the validated IP, while TLS still verifies the original hostname.
"""

from __future__ import annotations

import http.client
import json as json_module
import queue
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Protocol, cast
from urllib.parse import urljoin

from .errors import CollectionError, SecurityError
from .security import (
    SOCIAL_DOMAINS,
    ResolvedUrl,
    Resolver,
    UnsafeUrlError,
    ValidatedUrl,
    normalize_hostname,
    resolve_public_addresses,
    safe_display_url,
    validate_url,
)


class SafeHttpError(CollectionError):
    """A bounded HTTP operation failed without exposing response content."""


class HttpTimeoutError(SafeHttpError):
    """The total request deadline was exceeded."""


class UnsafeResponseError(SecurityError):
    """A response violated a content or resource security limit."""


class ResponseLike(Protocol):
    status: int
    reason: str

    def getheader(self, name: str, default: str | None = None) -> str | None: ...

    def getheaders(self) -> list[tuple[str, str]]: ...

    def read(self, amount: int | None = None) -> bytes: ...

    def close(self) -> None: ...


class ConnectionLike(Protocol):
    sock: socket.socket | None

    def request(
        self,
        method: str,
        url: str,
        body: object = None,
        headers: Mapping[str, str] = ...,
    ) -> None: ...

    def getresponse(self) -> ResponseLike: ...

    def close(self) -> None: ...


class DecompressorLike(Protocol):
    eof: bool
    unconsumed_tail: bytes
    unused_data: bytes

    def decompress(self, data: bytes, max_length: int = 0) -> bytes: ...

    def flush(self, length: int = ...) -> bytes: ...


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose socket target is a pre-validated IP address."""

    def __init__(self, host: str, port: int, pinned_ip: str, *, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self.pinned_ip, self.port),
            self.timeout,
            None,
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an IP while retaining hostname TLS checks."""

    def __init__(
        self,
        host: str,
        port: int,
        pinned_ip: str,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self.pinned_ip = pinned_ip
        self.ssl_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self.pinned_ip, self.port),
            self.timeout,
            None,
        )
        try:
            self.sock = self.ssl_context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """A fully bounded response returned by ``SafeHttpClient``."""

    url: str
    status: int
    reason: str
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)

    def text(self) -> str:
        """Decode response bytes as UTF-8, replacing invalid source bytes."""

        return self.body.decode("utf-8", errors="replace")

    def json(self) -> object:
        """Decode a size-bounded JSON response."""

        return json_module.loads(
            self.body,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )


ConnectionFactory = Callable[[str, str, int, str, float, ssl.SSLContext], ConnectionLike]


def _default_connection_factory(
    scheme: str,
    host: str,
    port: int,
    address: str,
    timeout: float,
    context: ssl.SSLContext,
) -> ConnectionLike:
    if scheme == "https":
        return cast(
            ConnectionLike,
            PinnedHTTPSConnection(host, port, address, timeout=timeout, context=context),
        )
    return cast(
        ConnectionLike,
        PinnedHTTPConnection(host, port, address, timeout=timeout),
    )


def _default_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class SafeHttpClient:
    """Fetch bounded public HTTP resources without implicit ambient authority."""

    REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
    FORBIDDEN_REQUEST_HEADERS = frozenset(
        {
            "connection",
            "content-length",
            "cookie",
            "host",
            "proxy-authorization",
            "proxy-connection",
            "transfer-encoding",
        }
    )

    def __init__(
        self,
        *,
        allow_http: bool = False,
        block_social_domains: bool = True,
        allow_authorization: bool = False,
        blocked_domains: Iterable[str] = SOCIAL_DOMAINS,
        max_redirects: int = 3,
        max_download_bytes: int = 5_000_000,
        max_response_bytes: int = 10_000_000,
        connect_timeout: float = 5.0,
        read_timeout: float = 15.0,
        total_timeout: float = 30.0,
        allowed_content_types: Iterable[str] = (
            "text/html",
            "text/plain",
            "application/json",
        ),
        resolver: Resolver = socket.getaddrinfo,
        connection_factory: ConnectionFactory = _default_connection_factory,
        tls_context: ssl.SSLContext | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_redirects < 0:
            raise ValueError("max_redirects must not be negative")
        if max_download_bytes <= 0 or max_response_bytes <= 0:
            raise ValueError("response limits must be positive")
        if min(connect_timeout, read_timeout, total_timeout) <= 0:
            raise ValueError("timeouts must be positive")

        self.allow_http = allow_http
        self.block_social_domains = block_social_domains
        self.allow_authorization = allow_authorization
        self.blocked_domains = tuple(blocked_domains)
        self.max_redirects = max_redirects
        self.max_download_bytes = max_download_bytes
        self.max_response_bytes = max_response_bytes
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        self.allowed_content_types = frozenset(item.lower() for item in allowed_content_types)
        self.resolver = resolver
        self.connection_factory = connection_factory
        self.tls_context = tls_context or _default_tls_context()
        self.clock = clock
        # One client instance belongs to one connector invocation.  Sharing a
        # single deadline across all of its requests prevents a high page cap
        # from multiplying the configured timeout into hours of runtime.
        self.deadline = self.clock() + self.total_timeout
        self.retry_resolved_addresses = True
        self._cancelled = threading.Event()
        self._connection_lock = threading.Lock()
        self._active_connections: list[ConnectionLike] = []

    def get(self, url: str, *, headers: Mapping[str, str] | None = None) -> HttpResponse:
        return self.request("GET", url, headers=headers)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        """Perform a safe GET or HEAD request and return its bounded body."""

        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise UnsafeUrlError("The safe HTTP client only supports GET and HEAD.")
        return self._request_bounded(
            method,
            url,
            headers=headers,
            body=None,
            follow_redirects=True,
            allowed_hosts=None,
        )

    def _request_bounded(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None,
        body: bytes | None,
        follow_redirects: bool,
        allowed_hosts: frozenset[str] | None,
    ) -> HttpResponse:
        # Socket inactivity timeouts are not absolute deadlines: a hostile
        # server can trickle TLS, headers, or body bytes forever. Run the whole
        # transaction behind one wall-clock wait and close its registered
        # connection when that source-wide deadline expires.
        remaining = self._remaining(self.deadline)
        results: queue.Queue[tuple[bool, HttpResponse | Exception]] = queue.Queue(maxsize=1)

        def perform() -> None:
            try:
                response = self._request_bounded_inner(
                    method,
                    url,
                    headers=headers,
                    body=body,
                    follow_redirects=follow_redirects,
                    allowed_hosts=allowed_hosts,
                )
            except Exception as error:
                results.put((False, error))
            else:
                results.put((True, response))

        worker = threading.Thread(target=perform, name="safe-http-request", daemon=True)
        worker.start()
        try:
            succeeded, value = results.get(timeout=remaining)
        except queue.Empty as error:
            self._cancelled.set()
            self._close_active_connections()
            raise HttpTimeoutError(
                "The HTTP source exceeded its source-wide total timeout."
            ) from error
        if succeeded and isinstance(value, HttpResponse):
            return value
        if isinstance(value, Exception):
            raise value
        raise SafeHttpError("The HTTP operation returned an invalid result.")

    def _request_bounded_inner(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None,
        body: bytes | None,
        follow_redirects: bool,
        allowed_hosts: frozenset[str] | None,
    ) -> HttpResponse:
        request_headers = self._prepare_headers(headers)
        deadline = self.deadline
        current_url = url
        previous_origin: tuple[str, str, int] | None = None

        for redirect_number in range(self.max_redirects + 1):
            target = validate_url(
                current_url,
                allow_http=self.allow_http,
                block_social_domains=self.block_social_domains,
                blocked_domains=self.blocked_domains,
            )
            if allowed_hosts is not None and (
                target.host not in allowed_hosts or target.port != 443
            ):
                raise UnsafeUrlError("The API URL is outside the configured HTTPS host allowlist.")
            if "Authorization" in request_headers and target.scheme != "https":
                raise UnsafeUrlError("Authorization is only allowed over HTTPS.")
            if (
                previous_origin is not None
                and previous_origin[0] == "https"
                and target.scheme == "http"
            ):
                raise UnsafeUrlError("A redirect may not downgrade HTTPS to HTTP.")
            if previous_origin is not None and target.origin != previous_origin:
                request_headers.pop("Authorization", None)
            resolved = self._resolve_before_deadline(target, deadline)
            response, connection = self._open(resolved, method, request_headers, body, deadline)
            try:
                if response.status in self.REDIRECT_STATUSES:
                    if not follow_redirects:
                        return self._response_without_body(target.url, response)
                    location = response.getheader("Location")
                    if not location:
                        raise UnsafeResponseError(
                            "The server returned a redirect without a Location header."
                        )
                    if redirect_number >= self.max_redirects:
                        raise UnsafeResponseError("The response exceeded the redirect limit.")
                    previous_origin = target.origin
                    current_url = urljoin(target.url, location)
                    continue

                content_type = self._validate_content_type(response, method)
                body = b"" if method == "HEAD" else self._read_body(response, connection, deadline)
                response_headers = self._safe_response_headers(response)
                if content_type:
                    declared_type = response.getheader("Content-Type", content_type) or content_type
                    response_headers["content-type"] = _clean_metadata(
                        declared_type, max_chars=4_096
                    )
                reason = _clean_metadata(str(response.reason or ""), max_chars=200)
                return HttpResponse(target.url, response.status, reason, response_headers, body)
            finally:
                try:
                    response.close()
                finally:
                    try:
                        connection.close()
                    finally:
                        self._release_connection(connection)

        raise UnsafeResponseError("The response exceeded the redirect limit.")

    def _response_without_body(self, url: str, response: ResponseLike) -> HttpResponse:
        reason = _clean_metadata(str(response.reason or ""), max_chars=200)
        return HttpResponse(
            url, response.status, reason, self._safe_response_headers(response), b""
        )

    @staticmethod
    def _safe_response_headers(response: ResponseLike) -> dict[str, str]:
        return {
            name.lower(): _clean_metadata(value, max_chars=4_096)
            for name, value in response.getheaders()
            if name.lower() != "set-cookie"
        }

    def _prepare_headers(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        prepared = {
            "Accept": "text/html, text/plain, application/json, application/*+json",
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "product-feedback-aggregator/0.1 (+bounded local client)",
        }
        for name, value in (headers or {}).items():
            normalized_name = name.strip()
            if not normalized_name or not _is_http_token(normalized_name):
                raise UnsafeUrlError("A request header name is invalid.")
            if normalized_name.lower() in self.FORBIDDEN_REQUEST_HEADERS:
                raise UnsafeUrlError(f"The request header {normalized_name} is not allowed.")
            if normalized_name.lower() == "authorization" and not self.allow_authorization:
                raise UnsafeUrlError("Authorization requires an explicitly authorized client.")
            text_value = str(value)
            if any(ord(character) < 32 or ord(character) == 127 for character in text_value):
                raise UnsafeUrlError("A request header value contains a control character.")
            # Canonicalizing Authorization makes cross-origin stripping simple.
            key = "Authorization" if normalized_name.lower() == "authorization" else normalized_name
            for existing in tuple(prepared):
                if existing.lower() == key.lower():
                    prepared.pop(existing)
            prepared[key] = text_value
        return prepared

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise HttpTimeoutError("The HTTP operation exceeded its total timeout.")
        return remaining

    def _resolve_before_deadline(self, target: ValidatedUrl, deadline: float) -> ResolvedUrl:
        # getaddrinfo has no portable timeout argument.  A daemon thread lets the
        # caller retain a hard deadline without allowing a stuck resolver to
        # block process shutdown.
        results: queue.Queue[tuple[bool, ResolvedUrl | Exception]] = queue.Queue(maxsize=1)

        def resolve() -> None:
            try:
                results.put((True, resolve_public_addresses(target, resolver=self.resolver)))
            except Exception as exc:
                results.put((False, exc))

        worker = threading.Thread(target=resolve, name="safe-http-dns", daemon=True)
        worker.start()
        try:
            succeeded, value = results.get(timeout=self._remaining(deadline))
        except queue.Empty as exc:
            raise HttpTimeoutError("DNS resolution exceeded the total HTTP timeout.") from exc
        if succeeded and isinstance(value, ResolvedUrl):
            return value
        if isinstance(value, Exception):
            if isinstance(value, (UnsafeUrlError, SecurityError)):
                raise value
            raise SafeHttpError("DNS resolution failed safely.") from value
        raise SafeHttpError("DNS resolution returned an invalid result.")

    def _open(
        self,
        resolved: ResolvedUrl,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        deadline: float,
    ) -> tuple[ResponseLike, ConnectionLike]:
        addresses = (
            resolved.addresses
            if self.retry_resolved_addresses
            else resolved.addresses[:1]
        )
        last_error: Exception | None = None
        for address in addresses:
            connection: ConnectionLike | None = None
            try:
                timeout = min(self.connect_timeout, self._remaining(deadline))
                connection = self.connection_factory(
                    resolved.target.scheme,
                    resolved.target.host,
                    resolved.target.port,
                    address,
                    timeout,
                    self.tls_context,
                )
                self._register_connection(connection)
                connection.request(
                    method, resolved.target.request_target, body=body, headers=headers
                )
                if connection.sock is not None:
                    connection.sock.settimeout(min(self.read_timeout, self._remaining(deadline)))
                return connection.getresponse(), connection
            except (
                OSError,
                ssl.SSLError,
                socket.timeout,
                http.client.HTTPException,
            ) as exc:
                if connection is not None:
                    try:
                        connection.close()
                    finally:
                        self._release_connection(connection)
                last_error = exc
        display_url = safe_display_url(resolved.target.url)
        raise SafeHttpError(f"The request to {display_url} could not be completed.") from last_error

    def _register_connection(self, connection: ConnectionLike) -> None:
        with self._connection_lock:
            if self._cancelled.is_set():
                connection.close()
                raise HttpTimeoutError("The HTTP source deadline has already expired.")
            self._active_connections.append(connection)

    def _release_connection(self, connection: ConnectionLike) -> None:
        with self._connection_lock:
            self._active_connections = [
                active for active in self._active_connections if active is not connection
            ]

    def _close_active_connections(self) -> None:
        with self._connection_lock:
            active = tuple(self._active_connections)
            self._active_connections.clear()
        for connection in active:
            try:
                connection.close()
            except OSError:
                pass

    def _validate_content_type(self, response: ResponseLike, method: str) -> str:
        raw_content_type = response.getheader("Content-Type")
        if method == "HEAD" or response.status in {204, 304}:
            return (raw_content_type or "").split(";", 1)[0].strip().lower()
        if not raw_content_type:
            raise UnsafeResponseError("The response did not declare a Content-Type.")
        content_type = raw_content_type.split(";", 1)[0].strip().lower()
        allowed = content_type in self.allowed_content_types
        if content_type.startswith("application/") and content_type.endswith("+json"):
            allowed = allowed or "application/json" in self.allowed_content_types
        if not allowed:
            raise UnsafeResponseError("The response Content-Type is not allowed.")
        return content_type

    def _read_body(
        self, response: ResponseLike, connection: ConnectionLike, deadline: float
    ) -> bytes:
        content_length = response.getheader("Content-Length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise UnsafeResponseError("The response Content-Length is invalid.") from exc
            if declared_length < 0 or declared_length > self.max_download_bytes:
                raise UnsafeResponseError("The response exceeds the download size limit.")

        encoding = (
            (response.getheader("Content-Encoding", "identity") or "identity").strip().lower()
        )
        if encoding in {"", "identity"}:
            decompressor: DecompressorLike | None = None
        elif encoding in {"gzip", "x-gzip"}:
            decompressor = cast(DecompressorLike, zlib.decompressobj(16 + zlib.MAX_WBITS))
        elif encoding == "deflate":
            decompressor = cast(DecompressorLike, zlib.decompressobj(zlib.MAX_WBITS))
        else:
            raise UnsafeResponseError("The response uses an unsupported Content-Encoding.")

        downloaded = 0
        output = bytearray()
        while True:
            remaining_time = min(self.read_timeout, self._remaining(deadline))
            if connection.sock is not None:
                connection.sock.settimeout(remaining_time)
            try:
                chunk = response.read(64 * 1024)
            except (OSError, socket.timeout, http.client.HTTPException) as exc:
                raise SafeHttpError("The response body could not be read safely.") from exc
            if not chunk:
                break
            downloaded += len(chunk)
            if downloaded > self.max_download_bytes:
                raise UnsafeResponseError("The response exceeds the download size limit.")

            if decompressor is None:
                if len(output) + len(chunk) > self.max_response_bytes:
                    raise UnsafeResponseError("The response exceeds the decoded size limit.")
                output.extend(chunk)
                continue

            remaining_output = self.max_response_bytes - len(output)
            try:
                decoded = decompressor.decompress(chunk, remaining_output + 1)
            except zlib.error as exc:
                raise UnsafeResponseError("The compressed response is malformed.") from exc
            if len(decoded) > remaining_output or decompressor.unconsumed_tail:
                raise UnsafeResponseError("The response exceeds the decoded size limit.")
            output.extend(decoded)

        if decompressor is not None:
            remaining_output = self.max_response_bytes - len(output)
            try:
                tail = decompressor.flush(remaining_output + 1)
            except zlib.error as exc:
                raise UnsafeResponseError("The compressed response is malformed.") from exc
            if len(tail) > remaining_output:
                raise UnsafeResponseError("The response exceeds the decoded size limit.")
            output.extend(tail)
            if not decompressor.eof or decompressor.unused_data:
                raise UnsafeResponseError(
                    "The compressed response is incomplete or contains trailing data."
                )
        return bytes(output)


class ApiHttpClient(SafeHttpClient):
    """HTTP transport for a small, explicit set of configured API hosts.

    Unlike ``SafeHttpClient``, this class can send an Authorization header and
    can POST to exact paths supplied by the connector at construction time.
    It remains HTTPS-only, pins validated DNS addresses, and never follows a
    redirect unless the caller explicitly opts in for a GET or HEAD request.
    """

    REQUEST_CONTENT_TYPES = frozenset({"application/json", "application/x-www-form-urlencoded"})

    def __init__(
        self,
        allowed_hosts: Iterable[str],
        *,
        allowed_post_paths: Iterable[str] = (),
        max_request_bytes: int = 65_536,
        **kwargs: object,
    ) -> None:
        reserved = {
            "allow_http",
            "block_social_domains",
            "allow_authorization",
        }.intersection(kwargs)
        if reserved:
            raise TypeError(f"ApiHttpClient controls {', '.join(sorted(reserved))} itself")
        hosts = frozenset(normalize_hostname(host) for host in allowed_hosts)
        if not hosts:
            raise ValueError("allowed_hosts must contain at least one hostname")
        paths = frozenset(allowed_post_paths)
        if any(not path.startswith("/") or "?" in path or "#" in path for path in paths):
            raise ValueError("allowed_post_paths must contain exact absolute paths")
        if max_request_bytes <= 0:
            raise ValueError("max_request_bytes must be positive")

        super().__init__(
            allow_http=False,
            block_social_domains=False,
            allow_authorization=True,
            **kwargs,  # type: ignore[arg-type]
        )
        self.allowed_hosts = hosts
        self.allowed_post_paths = paths
        self.max_request_bytes = max_request_bytes
        # Once an API request is handed to a connection, a response failure
        # does not prove that the server did not receive or bill it.  Trying a
        # second DNS address would therefore be an implicit paid-operation
        # retry.  Fail closed and let the operator start a new invocation.
        self.retry_resolved_addresses = False

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        allow_redirects: bool = False,
    ) -> HttpResponse:
        method = method.upper()
        if method not in {"GET", "HEAD", "POST"}:
            raise UnsafeUrlError(
                "The API HTTP client only supports GET, HEAD, and allowlisted POST requests."
            )
        if body is not None and not isinstance(body, bytes):
            raise UnsafeUrlError("An API request body must be bytes.")
        if method != "POST" and body is not None:
            raise UnsafeUrlError("Only an allowlisted POST request may include a body.")
        if allow_redirects and method == "POST":
            raise UnsafeUrlError("POST redirects are disabled to prevent credential replay.")

        target = validate_url(url, block_social_domains=False)
        if target.host not in self.allowed_hosts or target.port != 443:
            raise UnsafeUrlError("The API URL is outside the configured HTTPS host allowlist.")

        if method == "POST":
            path = target.request_target.split("?", 1)[0]
            if path not in self.allowed_post_paths:
                raise UnsafeUrlError("POST is not allowed for this API path.")
            if body is None:
                raise UnsafeUrlError("An allowlisted POST request must include a body.")
            if len(body) > self.max_request_bytes:
                raise UnsafeUrlError("The API request body exceeds the configured size limit.")
            content_type = _find_header(headers, "content-type")
            media_type = (content_type or "").split(";", 1)[0].strip().lower()
            if media_type not in self.REQUEST_CONTENT_TYPES:
                raise UnsafeUrlError("An API POST must use JSON or form-encoded content.")

        return self._request_bounded(
            method,
            target.url,
            headers=headers,
            body=body,
            follow_redirects=allow_redirects,
            allowed_hosts=self.allowed_hosts,
        )


def _is_http_token(value: str) -> bool:
    allowed_punctuation = "!#$%&'*+-.^_`|~"
    return all(
        character.isascii() and (character.isalnum() or character in allowed_punctuation)
        for character in value
    )


def _clean_metadata(value: str, *, max_chars: int) -> str:
    return "".join(
        character if 32 <= ord(character) < 127 else " " for character in value[:max_chars]
    ).strip()


def _find_header(headers: Mapping[str, str] | None, name: str) -> str | None:
    for candidate, value in (headers or {}).items():
        if candidate.lower() == name.lower():
            return str(value)
    return None


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"Non-standard JSON constant {value} is not accepted")


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key {key!r} is not accepted")
        result[key] = value
    return result


__all__ = [
    "ApiHttpClient",
    "HttpResponse",
    "HttpTimeoutError",
    "PinnedHTTPConnection",
    "PinnedHTTPSConnection",
    "SafeHttpClient",
    "SafeHttpError",
    "UnsafeResponseError",
]
