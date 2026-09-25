from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

from feedback_aggregator.config import (
    AnalysisConfig,
    AppConfig,
    LimitsConfig,
    OutputConfig,
    PrivacyConfig,
    ProductConfig,
    SourceConfig,
    StorageConfig,
)
from feedback_aggregator.connectors.base import ConnectorContext
from feedback_aggregator.connectors.external import ExternalConnector, run_bounded_subprocess
from feedback_aggregator.errors import CollectionError
from feedback_aggregator.models import PolicyCapabilities


def test_subprocess_uses_argv_without_shell_expansion() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        sentinel = root / "must-not-exist"
        argument = f"; touch {sentinel}"
        script = "import json,sys; print(json.dumps({'text': sys.argv[1]}))"
        output = run_bounded_subprocess(
            [sys.executable, "-c", script, argument],
            cwd=root,
            timeout_seconds=2,
            max_output_bytes=4096,
        )
        assert json.loads(output)["text"] == argument
        assert not sentinel.exists()


def test_subprocess_does_not_inherit_api_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("X_BEARER_TOKEN", "canary-secret")
    script = "import os,json; print(json.dumps({'text': str('X_BEARER_TOKEN' in os.environ)}))"
    output = run_bounded_subprocess(
        [sys.executable, "-c", script],
        cwd=Path.cwd(),
        timeout_seconds=2,
        max_output_bytes=4096,
    )
    assert json.loads(output)["text"] == "False"
    assert b"canary-secret" not in output


def test_subprocess_timeout_is_contained() -> None:
    with pytest.raises(CollectionError, match="timed out"):
        run_bounded_subprocess(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            cwd=Path.cwd(),
            timeout_seconds=0.05,
            max_output_bytes=4096,
        )


def test_subprocess_output_limit_is_contained() -> None:
    with pytest.raises(CollectionError, match="output limit"):
        run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('x' * 100000); sys.stdout.flush()",
            ],
            cwd=Path.cwd(),
            timeout_seconds=2,
            max_output_bytes=1024,
        )


def test_subprocess_output_limit_includes_stderr() -> None:
    with pytest.raises(CollectionError, match="output limit"):
        run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('x' * 100000); sys.stderr.flush()",
            ],
            cwd=Path.cwd(),
            timeout_seconds=2,
            max_output_bytes=1024,
        )


def test_single_large_write_is_stopped_by_the_pipe_budget() -> None:
    started = time.monotonic()
    with pytest.raises(CollectionError, match="output limit"):
        run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                "import os; os.write(1, b'x' * (32 * 1024 * 1024))",
            ],
            cwd=Path.cwd(),
            timeout_seconds=3,
            max_output_bytes=1024,
        )
    assert time.monotonic() - started < 3


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group behavior")
def test_subprocess_timeout_terminates_child_process_group() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        child_pid_path = root / "child.pid"
        child_code = "\n".join(
            (
                "import os",
                "import signal",
                "import time",
                "from pathlib import Path",
                f"pid_path = Path({str(child_pid_path)!r})",
                "def stop(_signum, _frame):",
                "    raise SystemExit(0)",
                "signal.signal(signal.SIGTERM, stop)",
                "pid_path.write_text(str(os.getpid()), encoding='utf-8')",
                "while True:",
                "    time.sleep(1)",
            )
        )
        parent_code = "\n".join(
            (
                "import signal",
                "import subprocess",
                "import sys",
                "import time",
                "from pathlib import Path",
                f"pid_path = Path({str(child_pid_path)!r})",
                f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}])",
                "def stop(_signum, _frame):",
                "    child.wait(timeout=2)",
                "    raise SystemExit(0)",
                "signal.signal(signal.SIGTERM, stop)",
                "deadline = time.monotonic() + 2",
                "while not pid_path.exists() and time.monotonic() < deadline:",
                "    time.sleep(0.01)",
                "while True:",
                "    time.sleep(1)",
            )
        )

        with pytest.raises(CollectionError, match="timed out"):
            run_bounded_subprocess(
                [sys.executable, "-c", parent_code],
                cwd=root,
                timeout_seconds=0.5,
                max_output_bytes=4096,
            )

        assert child_pid_path.exists()
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail("collector child process was not terminated")


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group behavior")
def test_successful_subprocess_cannot_leave_a_background_child() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        child_pid_path = root / "background-child.pid"
        parent_code = "\n".join(
            (
                "import json",
                "import subprocess",
                "import sys",
                "import time",
                "from pathlib import Path",
                f"pid_path = Path({str(child_pid_path)!r})",
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])",
                "pid_path.write_text(str(child.pid), encoding='utf-8')",
                "print(json.dumps({'text': 'complete'}), flush=True)",
            )
        )

        output = run_bounded_subprocess(
            [sys.executable, "-c", parent_code],
            cwd=root,
            timeout_seconds=2,
            max_output_bytes=4096,
        )

        assert json.loads(output)["text"] == "complete"
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail("background collector child was not terminated")


def test_subprocess_error_does_not_expose_stderr() -> None:
    secret = "stderr-canary-secret"
    with pytest.raises(CollectionError) as caught:
        run_bounded_subprocess(
            [
                sys.executable,
                "-c",
                f"import sys; sys.stderr.write({secret!r}); raise SystemExit(9)",
            ],
            cwd=Path.cwd(),
            timeout_seconds=2,
            max_output_bytes=4096,
        )
    assert secret not in str(caught.value)


def test_external_input_cannot_spoof_a_builtin_source_type() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        input_path = root / "external.ndjson"
        input_path.write_text(
            '{"id":"one","text":"Example has a bug","source_type":"reddit"}\n',
            encoding="utf-8",
        )
        source = SourceConfig(
            id="external-test",
            type="external",
            enabled=True,
            max_items=10,
            options={"path": str(input_path)},
            policy=PolicyCapabilities(
                acquisition_mode="external",
                approval_required=False,
                approval_reference="Test input",
                policy_version="test-v1",
                policy_version_checked_at="2026-09-25",
            ),
        )
        config = AppConfig(
            path=root / "feedback.yml",
            root=root,
            product=ProductConfig(name="Example"),
            storage=StorageConfig(root / "feedback.db"),
            privacy=PrivacyConfig(root / "salt"),
            limits=LimitsConfig(),
            analysis=AnalysisConfig(),
            outputs=OutputConfig(root / "reports"),
            sources=(source,),
            config_hash="cfg_test",
        )
        connector = ExternalConnector(ConnectorContext(config, source, "0" * 64))
        result = connector.collect()
        assert result.records[0].source_type == "external"
