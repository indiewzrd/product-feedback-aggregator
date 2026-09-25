"""Security primitives shared by all network-facing connectors.

The functions in this module are deliberately small and dependency-free.  They
turn a user supplied URL into an unambiguous target, reject local/special-use
addresses, and keep credentials out of user-visible errors and logs.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .errors import SecurityError

SOCIAL_DOMAINS = frozenset(
    {
        "reddit.com",
        "redd.it",
        "x.com",
        "twitter.com",
        "t.co",
    }
)

_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SECRET_FIELD_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|api[-_]?key|access[-_]?token|"
    r"refresh[-_]?token|client[-_]?secret|password)\b(\s*[:=]\s*)"
    r"(?:bearer\s+|basic\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/-]+=*")


class UnsafeUrlError(SecurityError):
    """A URL or one of its resolved addresses is not safe to fetch."""


@dataclass(frozen=True, slots=True)
class ValidatedUrl:
    """A parsed URL whose syntax, scheme, and hostname passed validation."""

    url: str
    scheme: str
    host: str
    port: int
    request_target: str

    @property
    def origin(self) -> tuple[str, str, int]:
        return self.scheme, self.host, self.port


@dataclass(frozen=True, slots=True)
class ResolvedUrl:
    """A validated URL plus the public IP addresses returned by DNS."""

    target: ValidatedUrl
    addresses: tuple[str, ...]


Resolver = Callable[..., Sequence[tuple[object, object, object, object, tuple[object, ...]]]]


def normalize_hostname(hostname: str) -> str:
    """Return a lowercase ASCII hostname, rejecting ambiguous forms."""

    if not hostname or any(ord(character) < 33 or ord(character) == 127 for character in hostname):
        raise UnsafeUrlError("The URL hostname is empty or contains control characters.")
    if "\\" in hostname or "%" in hostname:
        raise UnsafeUrlError("The URL hostname uses an unsafe encoding.")

    # A terminal root-label dot is semantically harmless but removing it makes
    # suffix checks exact and prevents alternate spellings of blocked domains.
    hostname = hostname.rstrip(".")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UnsafeUrlError("The URL hostname is not valid IDNA.") from exc

    if not ascii_hostname or len(ascii_hostname) > 253:
        raise UnsafeUrlError("The URL hostname has an invalid length.")

    # IP literals contain ':' or only digits/dots and are validated later.
    try:
        ipaddress.ip_address(ascii_hostname)
        return ascii_hostname
    except ValueError:
        pass

    labels = ascii_hostname.split(".")
    if any(not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise UnsafeUrlError("The URL hostname is not a valid DNS name.")
    return ascii_hostname


def is_social_domain(hostname: str, blocked_domains: Iterable[str] = SOCIAL_DOMAINS) -> bool:
    """Return whether *hostname* is a blocked social host or its subdomain."""

    host = normalize_hostname(hostname)
    for domain in blocked_domains:
        normalized_domain = normalize_hostname(domain)
        if host == normalized_domain or host.endswith(f".{normalized_domain}"):
            return True
    return False


def is_public_ip(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return ``True`` only for an Internet-routable unicast address.

    ``is_global`` is intentionally used instead of merely negating
    ``is_private``.  It also excludes loopback, link-local, multicast,
    unspecified, reserved, and shared carrier-grade NAT space.  Mapped IPv4
    addresses are unwrapped explicitly for consistent behavior across Python
    patch versions.
    """

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return parsed.is_global and not (
        parsed.is_multicast
        or parsed.is_loopback
        or parsed.is_link_local
        or (isinstance(parsed, ipaddress.IPv6Address) and parsed.is_site_local)
        or parsed.is_reserved
        or parsed.is_unspecified
        or parsed.is_private
    )


def require_public_ip(address: str) -> str:
    """Return a canonical public IP address or raise ``UnsafeUrlError``."""

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise UnsafeUrlError("DNS returned an invalid IP address.") from exc
    if not is_public_ip(parsed):
        raise UnsafeUrlError("The URL resolves to a non-public IP address.")
    return parsed.compressed


def validate_url(
    value: str,
    *,
    allow_http: bool = False,
    block_social_domains: bool = True,
    blocked_domains: Iterable[str] = SOCIAL_DOMAINS,
    max_url_chars: int = 8_192,
) -> ValidatedUrl:
    """Parse and validate a URL without performing DNS resolution.

    HTTPS is mandatory unless ``allow_http`` is explicitly enabled.  Complete
    URLs are accepted because that is a product requirement, so components
    which commonly create parser disagreement (userinfo, fragments,
    backslashes, and control characters) are rejected rather than normalized.
    """

    if not isinstance(value, str) or not value or len(value) > max_url_chars:
        raise UnsafeUrlError("The URL is empty or too long.")
    if (
        value != value.strip()
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise UnsafeUrlError("The URL contains unsafe characters.")

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise UnsafeUrlError("The URL could not be parsed safely.") from exc

    allowed_schemes = {"https"}
    if allow_http:
        allowed_schemes.add("http")
    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes:
        raise UnsafeUrlError(
            "Only HTTPS URLs are allowed."
            if not allow_http
            else "Only HTTP and HTTPS URLs are allowed."
        )
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeUrlError("Credentials are not allowed inside URLs.")
    if parsed.fragment:
        raise UnsafeUrlError("URL fragments are not accepted.")
    if not parsed.hostname:
        raise UnsafeUrlError("The URL must include a hostname.")

    host = normalize_hostname(parsed.hostname)
    if block_social_domains and is_social_domain(host, blocked_domains):
        raise UnsafeUrlError("Use the dedicated Reddit or X connector for this URL.")

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeUrlError("The URL port is invalid.") from exc
    if not 1 <= port <= 65_535:
        raise UnsafeUrlError("The URL port is invalid.")

    # Reject unsafe IP literals before any network operation.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not is_public_ip(literal):
        raise UnsafeUrlError("The URL targets a non-public IP address.")

    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = display_host if port == default_port else f"{display_host}:{port}"
    path = parsed.path or "/"
    request_target = path + (f"?{parsed.query}" if parsed.query else "")
    normalized = urlunsplit(SplitResult(scheme, netloc, path, parsed.query, ""))
    return ValidatedUrl(normalized, scheme, host, port, request_target)


def resolve_public_addresses(
    target: ValidatedUrl,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> ResolvedUrl:
    """Resolve every address for *target* and require all of them to be public."""

    try:
        literal = ipaddress.ip_address(target.host)
    except ValueError:
        literal = None
    if literal is not None:
        return ResolvedUrl(target, (require_public_ip(target.host),))

    try:
        answers = resolver(
            target.host,
            target.port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, socket.gaierror) as exc:
        raise UnsafeUrlError(f"The hostname {target.host} could not be resolved.") from exc

    addresses: list[str] = []
    for answer in answers:
        try:
            sockaddr = answer[4]
            raw_address = str(sockaddr[0])
        except (IndexError, TypeError) as exc:
            raise UnsafeUrlError("DNS returned a malformed address record.") from exc
        canonical = require_public_ip(raw_address)
        if canonical not in addresses:
            addresses.append(canonical)
    if not addresses:
        raise UnsafeUrlError(f"The hostname {target.host} did not resolve to an IP address.")
    return ResolvedUrl(target, tuple(addresses))


def safe_display_url(value: str) -> str:
    """Return a URL suitable for diagnostics, without userinfo or query data."""

    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if not parsed.scheme or not host:
            return "[invalid URL]"
        host = normalize_hostname(host)
        display_host = f"[{host}]" if ":" in host else host
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is not None:
            display_host = f"{display_host}:{port}"
        suffix = "?[REDACTED]" if parsed.query else ""
        safe_path = "/" if parsed.path in {"", "/"} else "/..."
        return urlunsplit((parsed.scheme.lower(), display_host, safe_path, "", "")) + suffix
    except (TypeError, ValueError, UnsafeUrlError):
        return "[invalid URL]"


def redact_secrets(value: object, secrets: Iterable[str] = ()) -> str:
    """Mask known secret values and common credential assignments in text."""

    text = str(value)
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = _SECRET_FIELD_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", text)
    return _BEARER_RE.sub("Bearer [REDACTED]", text)


__all__ = [
    "ResolvedUrl",
    "SOCIAL_DOMAINS",
    "UnsafeUrlError",
    "ValidatedUrl",
    "is_public_ip",
    "is_social_domain",
    "normalize_hostname",
    "redact_secrets",
    "resolve_public_addresses",
    "safe_display_url",
    "validate_url",
]
