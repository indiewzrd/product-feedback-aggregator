"""Optional semantic provider boundary.

The deterministic analyzer remains the default and never imports or invokes a
provider.  An operator may explicitly enable a trusted local executable that
accepts one JSON request on standard input and returns one bounded JSON object
on standard output.  The executable is run without a shell and with the same
minimal environment and process-tree limits as an external collector.

This is a process boundary, not an operating-system sandbox.  A configured
executable is trusted code and may itself access files or the network using the
operator's account.  The application ships no hosted transport or credentials.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import SemanticProviderConfig
from .connectors.external import run_bounded_subprocess
from .errors import CollectionError, ProviderError, SecurityError
from .models import CheckItem
from .storage import Storage
from .util import canonical_json, sanitize_text, stable_hash

PROVIDER_CONTRACT_VERSION = 1
SEMANTIC_OUTPUT_SCHEMA_VERSION = 1
MAX_PROVIDER_INPUT_CHARS = 200_000
MAX_PROVIDER_PROMPT_CHARS = 32_000
MAX_PROVIDER_JSON_DEPTH = 12
MAX_PROVIDER_JSON_NODES = 20_000
MAX_PROVIDER_LABELS = 100
MAX_PROVIDER_EMBEDDING_DIMENSIONS = 4_096
_TASK_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


@dataclass(frozen=True, slots=True)
class SemanticRequest:
    """One bounded semantic task. Source text remains untrusted data."""

    task: str
    input_text: str
    prompt: str
    output_schema_version: int = SEMANTIC_OUTPUT_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class ProviderResponse:
    """Validated provider output plus cache and retry provenance."""

    output: dict[str, Any]
    cache_key: str
    cached: bool
    attempts: int


@dataclass(frozen=True, slots=True)
class _PreparedRequest:
    task: str
    input_text: str
    prompt: str
    output_schema_version: int
    input_hash: str
    prompt_hash: str
    cache_key: str


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _validate_json_shape(
    value: Any,
    *,
    depth: int = 0,
    counter: list[int] | None = None,
) -> None:
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if counter[0] > MAX_PROVIDER_JSON_NODES:
        raise ProviderError("semantic provider output contains too many values")
    if depth > MAX_PROVIDER_JSON_DEPTH:
        raise ProviderError("semantic provider output is nested too deeply")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ProviderError("semantic provider output keys must be strings")
            _validate_json_shape(child, depth=depth + 1, counter=counter)
    elif isinstance(value, list):
        for child in value:
            _validate_json_shape(child, depth=depth + 1, counter=counter)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ProviderError("semantic provider output contains an unsupported value")


def _parse_provider_output(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProviderError("semantic provider output must be UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ProviderError("semantic provider output must be one valid JSON object") from error
    if not isinstance(value, dict):
        raise ProviderError("semantic provider output must be a JSON object")
    _validate_json_shape(value)
    return value


def validate_semantic_output(
    value: dict[str, Any],
    *,
    expected_schema_version: int = SEMANTIC_OUTPUT_SCHEMA_VERSION,
) -> dict[str, Any]:
    """Validate and normalize semantic output schema version one."""

    _validate_json_shape(value)
    if set(value) != {"schema_version", "result"}:
        raise ProviderError(
            "semantic provider output must contain only schema_version and result"
        )
    schema_version = value["schema_version"]
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != expected_schema_version
    ):
        raise ProviderError("semantic provider output schema version does not match")
    result = value["result"]
    if not isinstance(result, dict):
        raise ProviderError("semantic provider result must be an object")
    allowed_result_keys = {"summary", "labels", "embedding"}
    unknown = set(result) - allowed_result_keys
    if unknown:
        raise ProviderError("semantic provider result contains unknown fields")
    if not result:
        raise ProviderError("semantic provider result must not be empty")

    normalized: dict[str, Any] = {}
    if "summary" in result:
        summary = result["summary"]
        if not isinstance(summary, str):
            raise ProviderError("semantic provider summary must be a string")
        summary = sanitize_text(summary, max_chars=20_001)
        if len(summary) > 20_000:
            raise ProviderError("semantic provider summary is too long")
        normalized["summary"] = summary

    if "labels" in result:
        labels = result["labels"]
        if not isinstance(labels, list) or len(labels) > MAX_PROVIDER_LABELS:
            raise ProviderError("semantic provider labels must be a bounded list")
        normalized_labels: list[dict[str, Any]] = []
        for label in labels:
            if not isinstance(label, dict) or set(label) != {"name", "confidence"}:
                raise ProviderError("each semantic label must contain name and confidence")
            name = label["name"]
            confidence = label["confidence"]
            if not isinstance(name, str) or not name.strip() or len(name) > 256:
                raise ProviderError("semantic label names must be short non-empty strings")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                raise ProviderError("semantic label confidence must be a number")
            numeric_confidence = float(confidence)
            if not math.isfinite(numeric_confidence) or not 0 <= numeric_confidence <= 1:
                raise ProviderError("semantic label confidence must be between zero and one")
            safe_name = sanitize_text(name.strip(), max_chars=256)
            if not safe_name:
                raise ProviderError("semantic label names must contain visible text")
            normalized_labels.append(
                {
                    "name": safe_name,
                    "confidence": numeric_confidence,
                }
            )
        normalized["labels"] = normalized_labels

    if "embedding" in result:
        embedding = result["embedding"]
        if (
            not isinstance(embedding, list)
            or not embedding
            or len(embedding) > MAX_PROVIDER_EMBEDDING_DIMENSIONS
        ):
            raise ProviderError("semantic embedding must be a bounded non-empty list")
        normalized_embedding: list[float] = []
        for component in embedding:
            if isinstance(component, bool) or not isinstance(component, (int, float)):
                raise ProviderError("semantic embedding components must be numbers")
            numeric_component = float(component)
            if not math.isfinite(numeric_component) or abs(numeric_component) > 1_000_000:
                raise ProviderError("semantic embedding components must be finite and bounded")
            normalized_embedding.append(numeric_component)
        normalized["embedding"] = normalized_embedding

    return {"schema_version": expected_schema_version, "result": normalized}


class LocalSubprocessProvider:
    """Versioned adapter for an operator-trusted local executable."""

    contract_version = PROVIDER_CONTRACT_VERSION

    def __init__(
        self,
        config: SemanticProviderConfig,
        *,
        root: Path,
        storage: Storage | None = None,
    ):
        self.config = config
        self.root = root
        self.storage = storage

    def check(self) -> CheckItem:
        if not self.config.enabled:
            return CheckItem(
                name=f"provider:{self.config.id}",
                status="skipped",
                message="optional local semantic provider is disabled",
            )
        executable = Path(self.config.command[0])
        try:
            details = executable.stat()
        except OSError:
            return CheckItem(
                name=f"provider:{self.config.id}",
                status="error",
                message="local semantic provider executable is unavailable",
            )
        if not stat.S_ISREG(details.st_mode) or not os.access(executable, os.X_OK):
            return CheckItem(
                name=f"provider:{self.config.id}",
                status="error",
                message="local semantic provider must be a regular executable file",
            )
        return CheckItem(
            name=f"provider:{self.config.id}",
            status="ok",
            message="trusted local semantic provider is ready",
        )

    def _prepare(self, request: SemanticRequest) -> _PreparedRequest:
        if not isinstance(request.task, str) or not _TASK_NAME.fullmatch(request.task):
            raise ProviderError("semantic task name is invalid")
        if not isinstance(request.input_text, str):
            raise ProviderError("semantic provider input must be a string")
        if not isinstance(request.prompt, str) or not request.prompt:
            raise ProviderError("semantic provider prompt must be a non-empty string")
        if (
            isinstance(request.output_schema_version, bool)
            or request.output_schema_version != self.config.output_schema_version
        ):
            raise ProviderError("semantic request schema version does not match provider config")
        input_text = sanitize_text(request.input_text, max_chars=MAX_PROVIDER_INPUT_CHARS + 1)
        prompt = sanitize_text(request.prompt, max_chars=MAX_PROVIDER_PROMPT_CHARS + 1)
        if not input_text:
            raise ProviderError("semantic provider input must contain visible text")
        if not prompt:
            raise ProviderError("semantic provider prompt must contain visible text")
        if len(input_text) > MAX_PROVIDER_INPUT_CHARS:
            raise ProviderError("semantic provider input is too long")
        if len(prompt) > MAX_PROVIDER_PROMPT_CHARS:
            raise ProviderError("semantic provider prompt is too long")
        input_hash = stable_hash(input_text, prefix="provider_input_")
        prompt_hash = stable_hash(prompt, prefix="provider_prompt_")
        cache_key = stable_hash(
            input_text,
            self.config.id,
            self.config.type,
            self.config.model,
            request.task,
            prompt,
            str(request.output_schema_version),
            str(self.contract_version),
            prefix="provider_cache_",
        )
        return _PreparedRequest(
            task=request.task,
            input_text=input_text,
            prompt=prompt,
            output_schema_version=request.output_schema_version,
            input_hash=input_hash,
            prompt_hash=prompt_hash,
            cache_key=cache_key,
        )

    def cache_key(self, request: SemanticRequest) -> str:
        """Return the exact versioned identity used by the persistent cache."""

        return self._prepare(request).cache_key

    def _cached(self, request: _PreparedRequest) -> dict[str, Any] | None:
        if self.storage is None:
            raise ProviderError("semantic provider storage is unavailable")
        cached = self.storage.get_provider_cache(request.cache_key)
        if cached is None:
            return None
        expected = {
            "provider_id": self.config.id,
            "provider_type": self.config.type,
            "model": self.config.model,
            "input_hash": request.input_hash,
            "prompt_hash": request.prompt_hash,
            "schema_version": request.output_schema_version,
        }
        if any(cached.get(key) != value for key, value in expected.items()):
            raise SecurityError("semantic provider cache metadata does not match its key")
        output = cached.get("output")
        if not isinstance(output, dict):
            raise SecurityError("semantic provider cache output has an invalid shape")
        return validate_semantic_output(
            output,
            expected_schema_version=request.output_schema_version,
        )

    def _wire_request(self, request: _PreparedRequest) -> bytes:
        payload = {
            "contract_version": self.contract_version,
            "output_schema_version": request.output_schema_version,
            "task": request.task,
            "model": self.config.model,
            "prompt": request.prompt,
            "input": request.input_text,
        }
        encoded = canonical_json(payload).encode("utf-8")
        # This also guards future changes that add fields around the bounded
        # input and prompt.
        maximum = MAX_PROVIDER_INPUT_CHARS * 4 + MAX_PROVIDER_PROMPT_CHARS * 4 + 4_096
        if len(encoded) > maximum:
            raise ProviderError("semantic provider request exceeds its byte limit")
        return encoded

    def infer(self, request: SemanticRequest) -> ProviderResponse:
        """Return a validated cached result or invoke the local provider."""

        if not self.config.enabled:
            raise ProviderError("semantic provider is disabled")
        storage = self.storage
        if storage is None:
            raise ProviderError("semantic provider storage is unavailable")
        prepared = self._prepare(request)
        cached = self._cached(prepared)
        if cached is not None:
            return ProviderResponse(cached, prepared.cache_key, True, 0)

        wire_request = self._wire_request(prepared)
        last_error: ProviderError | None = None
        for attempt in range(1, self.config.max_retries + 2):
            try:
                raw = run_bounded_subprocess(
                    list(self.config.command),
                    cwd=self.root,
                    timeout_seconds=self.config.timeout_seconds,
                    max_output_bytes=self.config.max_output_bytes,
                    stdin_bytes=wire_request,
                )
                output = validate_semantic_output(
                    _parse_provider_output(raw),
                    expected_schema_version=prepared.output_schema_version,
                )
            except CollectionError as error:
                last_error = ProviderError("local semantic provider process failed")
                last_error.__cause__ = error
                continue
            except ProviderError as error:
                last_error = error
                continue

            inserted = storage.save_provider_cache(
                cache_key=prepared.cache_key,
                provider_id=self.config.id,
                provider_type=self.config.type,
                model=self.config.model,
                input_hash=prepared.input_hash,
                prompt_hash=prepared.prompt_hash,
                schema_version=prepared.output_schema_version,
                output=output,
            )
            if not inserted:
                concurrent = self._cached(prepared)
                if concurrent is None:
                    raise SecurityError("semantic provider cache disappeared during write")
                return ProviderResponse(concurrent, prepared.cache_key, True, attempt)
            return ProviderResponse(output, prepared.cache_key, False, attempt)

        if last_error is None:  # pragma: no cover - range above always executes
            raise ProviderError("local semantic provider failed")
        raise last_error


__all__ = [
    "LocalSubprocessProvider",
    "PROVIDER_CONTRACT_VERSION",
    "ProviderResponse",
    "SEMANTIC_OUTPUT_SCHEMA_VERSION",
    "SemanticRequest",
    "validate_semantic_output",
]
