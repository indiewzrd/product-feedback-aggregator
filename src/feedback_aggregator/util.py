"""Deterministic identifiers, safe text handling, and atomic local files."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_CONTROL_RE = re.compile(
    r"(?:\x1b\][^\x07]*(?:\x07|\x1b\\))|(?:\x1b\[[0-?]*[ -/]*[@-~])|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)
_DIRECTIONAL_CONTROL_RE = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]")
_SPACE_RE = re.compile(r"[ \t]+")


def sanitize_text(value: object, *, max_chars: int = 200_000) -> str:
    """Remove terminal controls and normalize whitespace without hiding newlines."""

    text = str(value or "")[:max_chars]
    text = _CONTROL_RE.sub("", text)
    # Directional overrides can make terminal, source, and report text appear
    # in a different order than the stored characters ("Trojan Source").
    text = _DIRECTIONAL_CONTROL_RE.sub("", text)
    lines = [
        _SPACE_RE.sub(" ", line).strip()
        for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]
    return "\n".join(line for line in lines if line).strip()


def normalized_text(value: object) -> str:
    return " ".join(sanitize_text(value).lower().split())


def safe_provenance_url(value: object, *, max_chars: int = 8192) -> str:
    """Return provenance without userinfo, fragments, or query-string secrets."""

    text = sanitize_text(value, max_chars=max_chars)
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            # Imports may use a plain label rather than an absolute URL.  Even
            # then, discard components commonly used for credentials.
            return text.split("#", 1)[0].split("?", 1)[0]
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        netloc = f"{host}:{port}" if port is not None else host
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, "", ""))
    except (UnicodeError, ValueError):
        return ""


def stable_hash(*parts: object, prefix: str = "") -> str:
    payload = "\x1f".join(str(part) for part in parts).encode("utf-8", "surrogatepass")
    digest = hashlib.sha256(payload).hexdigest()
    return f"{prefix}{digest}"


def pseudonymize_author(source_type: str, author: object, salt: str) -> str:
    if not author:
        return ""
    return stable_hash(source_type, normalized_text(author), salt, prefix="author_")[:31]


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    """Write a private file atomically in its destination directory."""

    # Resolve the parent, never the final component.  Resolving the full path
    # would follow a malicious destination symlink before ``os.replace``.
    parent = path.expanduser().absolute().parent.resolve()
    path = parent / path.name
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary_name, mode)
        except OSError:
            pass
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def safe_json(value: Any, *, pretty: bool = False) -> str:
    kwargs: dict[str, Any] = {"ensure_ascii": False, "sort_keys": True}
    if pretty:
        kwargs["indent"] = 2
    return json.dumps(value, **kwargs)
