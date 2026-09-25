"""Private local state helpers."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from .errors import ReadinessError, SecurityError


def create_author_salt(path: Path) -> str:
    """Create a private pseudonymization salt without following a final symlink."""

    parent = path.expanduser().absolute().parent.resolve()
    path = parent / path.name
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = secrets.token_hex(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        return read_author_salt(path)
    except OSError as exc:
        raise SecurityError("Could not create the private author salt") from exc
    try:
        os.write(descriptor, (value + "\n").encode("ascii"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return value


def read_author_salt(path: Path) -> str:
    try:
        status = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise ReadinessError("Author salt is missing; run feedback init") from exc
    if not stat.S_ISREG(status.st_mode):
        raise SecurityError("Author salt must be a regular file")
    if os.name != "nt" and status.st_mode & 0o077:
        raise SecurityError("Author salt permissions are too broad; use chmod 600")
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise SecurityError("Author salt could not be read safely") from exc
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SecurityError("Author salt has an invalid format")
    return value
