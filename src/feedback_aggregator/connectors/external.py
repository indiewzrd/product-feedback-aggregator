"""Explicitly trusted external NDJSON acquisition boundary."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import BinaryIO

from ..errors import CollectionError, ConfigurationError, SecurityError
from ..models import CheckItem, CollectionPlan, CollectionResult, RawRecord
from .base import Connector, connector_note
from .json_file import iter_json_records, iter_ndjson_bytes, record_from_mapping

_ENV_ALLOWLIST = ("LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "WINDIR")
_PROCESS_POLL_SECONDS = 0.02
_TERMINATION_GRACE_SECONDS = 0.5


def _posix_process_group_exists(process_group_id: int) -> bool:
    """Return whether our isolated POSIX process group still has members."""

    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # The group exists even if an unusual platform policy prevents probing it.
        return True
    return True


def _terminate_windows_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Ask Windows' built-in taskkill utility to terminate the complete tree."""

    windows_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR")
    taskkill = Path(windows_root, "System32", "taskkill.exe") if windows_root else None
    if taskkill is not None and taskkill.is_file():
        try:
            subprocess.run(  # noqa: S603
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                close_fds=True,
                timeout=2,
            )
        except (OSError, subprocess.TimeoutExpired):
            # Fall through to killing the direct process. This is less complete,
            # but still contains the collector if taskkill is unavailable.
            pass
    if process.poll() is None:
        process.kill()


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Terminate the collector's isolated process group and reap its parent."""

    if os.name == "posix":
        process_group_id = process.pid
        try:
            os.killpg(process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            if process.poll() is None:
                process.terminate()

        # Give signal handlers a short chance to close files and reap children.
        deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
        while time.monotonic() < deadline and _posix_process_group_exists(process_group_id):
            process.poll()
            time.sleep(_PROCESS_POLL_SECONDS)
        if _posix_process_group_exists(process_group_id):
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                if process.poll() is None:
                    process.kill()
    elif os.name == "nt":
        _terminate_windows_process_tree(process)
    elif process.poll() is None:
        process.kill()

    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_bounded_subprocess(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    max_output_bytes: int,
    stdin_bytes: bytes | None = None,
) -> bytes:
    """Run trusted local code without a shell or inherited secrets.

    Optional standard input is written to an anonymous temporary file instead
    of a pipe, so a child that exits without reading cannot deadlock its parent.
    Callers remain responsible for bounding the input before invoking this
    shared process boundary.
    """

    if not argv or not all(isinstance(value, str) for value in argv):
        raise ConfigurationError("External collector command must be an argv list")
    executable = Path(argv[0])
    if not executable.is_absolute():
        raise SecurityError("External collector executable must be an absolute path")
    try:
        status = executable.stat()
    except OSError as exc:
        raise CollectionError("External collector executable is unavailable") from exc
    if not stat.S_ISREG(status.st_mode) or not os.access(executable, os.X_OK):
        raise CollectionError("External collector executable must be a regular executable file")
    if os.name == "nt" and executable.suffix.lower() in {".bat", ".cmd"}:
        raise SecurityError("Windows batch collectors are not supported")
    environment = {key: os.environ[key] for key in _ENV_ALLOWLIST if key in os.environ}
    environment["FEEDBACK_SCHEMA_VERSION"] = "1"
    started = time.monotonic()
    if stdin_bytes is not None and not isinstance(stdin_bytes, bytes):
        raise ConfigurationError("External process input must be bytes")
    if max_output_bytes < 1:
        raise ConfigurationError("External process output limit must be positive")
    with tempfile.TemporaryFile() as stdin_file:
        if stdin_bytes is not None:
            stdin_file.write(stdin_bytes)
            stdin_file.seek(0)
        try:
            # argv[0] was required to be an absolute regular executable above;
            # source text never enters argv and shell execution is disabled.
            process = subprocess.Popen(  # noqa: S603
                argv,
                cwd=cwd,
                env=environment,
                stdin=stdin_file if stdin_bytes is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                # POSIX sessions and Windows process groups let failure cleanup
                # target descendants instead of only the direct child.
                start_new_session=os.name == "posix",
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
                ),
            )
        except OSError as exc:
            raise CollectionError("External collector could not be started") from exc

        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
            _terminate_process_tree(process)
            raise CollectionError("External collector output pipes were unavailable")

        output_lock = threading.Lock()
        output_exceeded = threading.Event()
        reader_failed = threading.Event()
        stdout_chunks: list[bytes] = []
        byte_counts = {"total": 0, "stderr": 0}

        def read_output(stream: BinaryIO, *, capture_stdout: bool) -> None:
            try:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        return
                    with output_lock:
                        room = max(0, max_output_bytes - byte_counts["total"])
                        accepted = chunk[:room]
                        byte_counts["total"] += len(accepted)
                        if capture_stdout:
                            if accepted:
                                stdout_chunks.append(accepted)
                        else:
                            byte_counts["stderr"] += len(accepted)
                        if len(accepted) != len(chunk):
                            output_exceeded.set()
                            return
            except (OSError, ValueError):
                # Closing pipes during process-tree termination is expected.
                if process.poll() is None:
                    reader_failed.set()

        readers = (
            threading.Thread(
                target=read_output,
                kwargs={"stream": process.stdout, "capture_stdout": True},
                daemon=True,
            ),
            threading.Thread(
                target=read_output,
                kwargs={"stream": process.stderr, "capture_stdout": False},
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()

        stop_reason = ""
        while process.poll() is None:
            if time.monotonic() - started > timeout_seconds:
                stop_reason = "timed out"
                break
            if output_exceeded.is_set():
                stop_reason = "exceeded its output limit"
                break
            if reader_failed.is_set():
                stop_reason = "output could not be read safely"
                break
            time.sleep(_PROCESS_POLL_SECONDS)
        if stop_reason:
            _terminate_process_tree(process)
            process.stdout.close()
            process.stderr.close()
            for reader in readers:
                reader.join(timeout=2)
            raise CollectionError(f"External collector {stop_reason}")
        return_code = process.wait()
        # A synchronous collector has no reason to leave background children.
        # On POSIX, close that escape hatch even when the direct process exits
        # successfully before the next polling interval.
        if os.name == "posix" and _posix_process_group_exists(process.pid):
            _terminate_process_tree(process)
        for reader in readers:
            reader.join(timeout=2)
        if any(reader.is_alive() for reader in readers):
            _terminate_process_tree(process)
            process.stdout.close()
            process.stderr.close()
            for reader in readers:
                reader.join(timeout=2)
            raise CollectionError("External collector output did not close safely")
        if output_exceeded.is_set():
            raise CollectionError("External collector exceeded its output limit")
        if reader_failed.is_set():
            raise CollectionError("External collector output could not be read safely")
        if return_code != 0:
            raise CollectionError(
                f"External collector exited with status {return_code}; "
                f"stderr bytes: {byte_counts['stderr']}"
            )
        return b"".join(stdout_chunks)


class ExternalConnector(Connector):
    def _mode(self) -> str:
        modes = [key for key in ("path", "stdin", "command") if key in self.source.options]
        if len(modes) != 1:
            raise ConfigurationError(
                "External source requires exactly one of options.path, options.stdin, or options.command"
            )
        return modes[0]

    def check(self, *, probe: bool = False) -> list[CheckItem]:
        del probe
        try:
            mode = self._mode()
            if mode == "path":
                raw_path = self.source.options["path"]
                if not isinstance(raw_path, str):
                    raise ConfigurationError("options.path must be a string")
                path = (
                    (self.config.root / raw_path).resolve()
                    if not Path(raw_path).expanduser().is_absolute()
                    else Path(raw_path).expanduser().resolve()
                )
                status = path.stat()
                if (
                    not stat.S_ISREG(status.st_mode)
                    or status.st_size > self.config.limits.max_file_bytes
                ):
                    raise CollectionError("External input path must be a bounded regular file")
            elif mode == "command":
                command = self.source.options["command"]
                if not isinstance(command, list) or not command:
                    raise ConfigurationError("options.command must be an argv list")
                executable = Path(str(command[0]))
                if (
                    not executable.is_absolute()
                    or not executable.is_file()
                    or not os.access(executable, os.X_OK)
                ):
                    raise CollectionError("External collector executable is not ready")
            return [
                connector_note(
                    self.context,
                    f"External {mode} input is configured; collector code is trusted arbitrary code",
                )
            ]
        except (OSError, ConfigurationError, CollectionError) as exc:
            return [connector_note(self.context, str(exc), "error")]

    def plan(self) -> CollectionPlan:
        mode = self._mode()
        return CollectionPlan(
            self.source.id,
            self.source.type,
            f"external:{mode}",
            self.source.max_items,
            0,
            0.0,
            (
                "Acquisition is labeled external",
                "Configured collector code is trusted arbitrary code",
            ),
        )

    def _data(self) -> tuple[bytes | None, Path | None, str]:
        mode = self._mode()
        if mode == "stdin":
            if self.context.stdin_bytes is None:
                raise CollectionError("No standard-input data was provided")
            if len(self.context.stdin_bytes) > self.config.limits.external_output_bytes:
                raise CollectionError("Standard-input data exceeds the configured limit")
            return self.context.stdin_bytes, None, "stdin"
        if mode == "path":
            raw = self.source.options["path"]
            path = (
                (self.config.root / raw).resolve()
                if not Path(raw).expanduser().is_absolute()
                else Path(raw).expanduser().resolve()
            )
            return None, path, str(path)
        command = self.source.options["command"]
        data = run_bounded_subprocess(
            list(command),
            cwd=self.config.root,
            timeout_seconds=self.config.limits.external_timeout_seconds,
            max_output_bytes=self.config.limits.external_output_bytes,
        )
        return data, None, "external-command"

    def collect(self, *, cursor: str | None = None) -> CollectionResult:
        del cursor
        data, path, label = self._data()
        if path is not None:
            source_records = iter_json_records(
                path,
                max_file_bytes=self.config.limits.max_file_bytes,
                max_line_bytes=self.config.limits.max_line_bytes,
            )
        else:
            source_records = iter_ndjson_bytes(
                data or b"",
                label=label,
                max_line_bytes=self.config.limits.max_line_bytes,
            )
        mapping = self.source.options.get("mapping", {})
        if not isinstance(mapping, dict):
            raise ConfigurationError("options.mapping must be a mapping")
        records: list[RawRecord] = []
        for item, location in source_records:
            if len(records) >= self.source.max_items:
                return CollectionResult.from_records(
                    records, resources_read=len(records), stop_reason="item_cap"
                )
            try:
                records.append(
                    record_from_mapping(
                        item,
                        source_id=self.source.id,
                        # External input cannot impersonate a trusted built-in
                        # source class and distort source-diversity scoring.
                        source_type="external",
                        location=location,
                        mapping=mapping,
                        author_salt=self.context.author_salt,
                        acquisition_mode="external",
                        policy_assurance="user",
                    )
                )
            except ValueError as exc:
                raise CollectionError(f"{location}: {exc}") from exc
        return CollectionResult.from_records(records, resources_read=len(records))
