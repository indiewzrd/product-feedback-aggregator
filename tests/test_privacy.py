from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from feedback_aggregator.errors import ReadinessError, SecurityError
from feedback_aggregator.privacy import create_author_salt, read_author_salt


def test_salt_is_created_once_and_private() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "state" / "author_salt"
        first = create_author_salt(path)
        second = create_author_salt(path)
        assert first == second == read_author_salt(path)
        if os.name != "nt":
            assert path.stat().st_mode & 0o077 == 0


def test_missing_salt_fails_readiness() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        with pytest.raises(ReadinessError):
            read_author_salt(Path(temporary) / "missing")


def test_broad_permissions_are_rejected() -> None:
    if os.name == "nt":
        pytest.skip("POSIX permission bits do not apply on Windows")
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "salt"
        path.write_text("a" * 64, encoding="ascii")
        path.chmod(0o644)
        with pytest.raises(SecurityError):
            read_author_salt(path)
