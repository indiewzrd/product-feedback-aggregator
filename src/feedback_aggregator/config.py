"""Strict, versioned configuration loading.

The loader accepts ordinary YAML but deliberately rejects tags, anchors, aliases,
duplicate keys, excessive nesting, and unknown top-level keys. Configuration may
name an environment variable containing a secret; it may never contain the secret.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.tokens import AliasToken, AnchorToken, TagToken

from .errors import ConfigurationError
from .models import PolicyCapabilities
from .util import canonical_json, stable_hash

CONFIG_VERSION = 1
RESERVED_REPORT_FILENAMES = ("feedback-report.json", "feedback-report.md")
MAX_CONFIG_BYTES = 1_048_576
MAX_CONFIG_DEPTH = 12
MAX_CONFIG_NODES = 20_000
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_SOURCE_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_TOP_LEVEL_KEYS = {
    "version",
    "product",
    "storage",
    "privacy",
    "limits",
    "analysis",
    "outputs",
    "providers",
    "sources",
}
_PRODUCT_KEYS = {"name", "aliases", "terms", "exclusions", "languages"}
_STORAGE_KEYS = {"path"}
_PRIVACY_KEYS = {"author_salt_file"}
_LIMIT_KEYS = {
    "max_items_per_source",
    "max_file_bytes",
    "max_line_bytes",
    "max_url_bytes",
    "max_decompressed_bytes",
    "connect_timeout_seconds",
    "read_timeout_seconds",
    "total_timeout_seconds",
    "max_redirects",
    "external_timeout_seconds",
    "external_output_bytes",
}
_ANALYSIS_KEYS = {
    "relevance_threshold",
    "suppression_threshold",
    "cluster_similarity_threshold",
    "weights",
}
_OUTPUT_KEYS = {"directory"}
_PROVIDER_KEYS = {
    "id",
    "type",
    "enabled",
    "command",
    "model",
    "output_schema_version",
    "timeout_seconds",
    "max_output_bytes",
    "max_retries",
}
_SOURCE_KEYS = {"id", "type", "enabled", "max_items", "options", "policy"}
_SOURCE_OPTION_KEYS = {
    "json": {"paths", "permissive", "mapping"},
    "url": {"urls", "allow_http"},
    "external": {"path", "stdin", "command", "mapping"},
    "reddit": {
        "approval_confirmed",
        "client_id_env",
        "client_secret_env",
        "user_agent",
        "subreddits",
        "query",
        "page_size",
        "max_pages",
        "max_comments_per_post",
        "comment_depth",
        "sort",
        "time_filter",
    },
    "x": {
        "approval_confirmed",
        "bearer_token_env",
        "mode",
        "query",
        "user_id",
        "page_size",
        "max_pages",
        "sort_order",
    },
    "reddit_apify": {
        "approval_confirmed",
        "token_env",
        "actor_build",
        "searches",
        "start_urls",
        "search_community_name",
        "search_comments",
        "max_post_count",
        "max_comments",
        "include_nsfw",
        "dataset_page_size",
        "poll_interval_seconds",
        "initial_lookback_days",
        "overlap_hours",
    },
    "x_apify": {
        "approval_confirmed",
        "token_env",
        "actor_build",
        "search_terms",
        "start_urls",
        "sort",
        "tweet_language",
        "exclude_retweets",
        "dataset_page_size",
        "poll_interval_seconds",
        "initial_lookback_days",
        "overlap_hours",
    },
}
_POLICY_KEYS = {
    "acquisition_mode",
    "approval_required",
    "approval_reference",
    "credential_owner",
    "commercial_use_allowed",
    "remote_processing_allowed",
    "raw_ttl_hours",
    "deletion_reconcile_interval_hours",
    "redistribution_mode",
    "cost_per_resource_usd",
    "max_cost_usd",
    "policy_version",
    "policy_version_checked_at",
}


class _UniqueSafeLoader(yaml.SafeLoader):
    pass


# Treat ISO-looking dates as strings. Policy review dates are metadata, not code,
# and implicit construction into Python date objects makes validation surprising.
_UniqueSafeLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _construct_unique_mapping(
    loader: _UniqueSafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be scalar",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "duplicate key",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True, slots=True)
class ProductConfig:
    name: str
    aliases: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    languages: tuple[str, ...] = ("en",)


@dataclass(frozen=True, slots=True)
class StorageConfig:
    path: Path


@dataclass(frozen=True, slots=True)
class PrivacyConfig:
    author_salt_file: Path


@dataclass(frozen=True, slots=True)
class LimitsConfig:
    max_items_per_source: int = 1_000
    max_file_bytes: int = 10 * 1024 * 1024
    max_line_bytes: int = 1 * 1024 * 1024
    max_url_bytes: int = 2 * 1024 * 1024
    max_decompressed_bytes: int = 4 * 1024 * 1024
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 15.0
    total_timeout_seconds: float = 30.0
    max_redirects: int = 3
    external_timeout_seconds: float = 60.0
    external_output_bytes: int = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    relevance_threshold: float = 0.35
    suppression_threshold: float = 0.80
    cluster_similarity_threshold: float = 0.42
    weights: dict[str, float] = field(
        default_factory=lambda: {
            "authors": 0.28,
            "sources": 0.17,
            "recency": 0.15,
            "severity": 0.18,
            "relevance": 0.17,
            "engagement": 0.05,
        }
    )


@dataclass(frozen=True, slots=True)
class OutputConfig:
    directory: Path


@dataclass(frozen=True, slots=True)
class SourceConfig:
    id: str
    type: str
    enabled: bool
    max_items: int
    options: dict[str, Any]
    policy: PolicyCapabilities


@dataclass(frozen=True, slots=True)
class SemanticProviderConfig:
    """An optional, explicitly trusted local semantic provider."""

    id: str
    type: str
    enabled: bool
    command: tuple[str, ...]
    model: str
    output_schema_version: int = 1
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1 * 1024 * 1024
    max_retries: int = 0


@dataclass(frozen=True, slots=True)
class AppConfig:
    path: Path
    root: Path
    product: ProductConfig
    storage: StorageConfig
    privacy: PrivacyConfig
    limits: LimitsConfig
    analysis: AnalysisConfig
    outputs: OutputConfig
    sources: tuple[SourceConfig, ...]
    config_hash: str
    providers: tuple[SemanticProviderConfig, ...] = ()
    version: int = CONFIG_VERSION

    def public_dict(self) -> dict[str, Any]:
        """Return a JSON-safe configuration view containing no secret values."""

        return {
            "version": self.version,
            "product": asdict(self.product),
            "storage": {"path": str(self.storage.path)},
            "privacy": {"author_salt_file": str(self.privacy.author_salt_file)},
            "limits": asdict(self.limits),
            "analysis": asdict(self.analysis),
            "outputs": {"directory": str(self.outputs.directory)},
            "providers": [
                {
                    "id": provider.id,
                    "type": provider.type,
                    "enabled": provider.enabled,
                    "command": list(provider.command),
                    "model": provider.model,
                    "output_schema_version": provider.output_schema_version,
                    "timeout_seconds": provider.timeout_seconds,
                    "max_output_bytes": provider.max_output_bytes,
                    "max_retries": provider.max_retries,
                }
                for provider in self.providers
            ],
            "sources": [
                {
                    "id": source.id,
                    "type": source.type,
                    "enabled": source.enabled,
                    "max_items": source.max_items,
                    "options": source.options,
                    "policy": asdict(source.policy),
                }
                for source in self.sources
            ],
        }


def _read_regular_text(path: Path) -> str:
    try:
        status = path.stat()
    except OSError as exc:
        raise ConfigurationError(f"Cannot read configuration file: {path}") from exc
    if not stat.S_ISREG(status.st_mode):
        raise ConfigurationError("Configuration path must be a regular file")
    if status.st_size > MAX_CONFIG_BYTES:
        raise ConfigurationError(f"Configuration exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError("Configuration must be valid UTF-8") from exc


def _load_yaml(text: str) -> dict[str, Any]:
    try:
        for token in yaml.scan(text, Loader=_UniqueSafeLoader):
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise ConfigurationError("YAML anchors, aliases, and explicit tags are not allowed")
        # The custom loader inherits SafeLoader. Tags, aliases, and anchors are
        # rejected above; object construction is therefore unavailable.
        value = yaml.load(text, Loader=_UniqueSafeLoader)  # noqa: S506
    except ConfigurationError:
        raise
    except ConstructorError as exc:
        # PyYAML diagnostics include the source line. Configuration files often
        # contain credential *references* and users sometimes paste credentials
        # by mistake, so expected CLI errors must never echo parser snippets.
        detail = "duplicate key" if exc.problem == "duplicate key" else "invalid mapping"
        raise ConfigurationError(f"Invalid YAML configuration: {detail}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError("Invalid YAML configuration") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("Configuration root must be a mapping")
    _validate_shape(value)
    return value


def _validate_shape(value: Any, depth: int = 0, counter: list[int] | None = None) -> None:
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if counter[0] > MAX_CONFIG_NODES:
        raise ConfigurationError("Configuration contains too many values")
    if depth > MAX_CONFIG_DEPTH:
        raise ConfigurationError("Configuration is nested too deeply")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ConfigurationError("Configuration keys must be strings")
            _validate_shape(child, depth + 1, counter)
    elif isinstance(value, list):
        for child in value:
            _validate_shape(child, depth + 1, counter)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise ConfigurationError(f"Unsupported configuration value: {type(value).__name__}")


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigurationError(f"{name} must be a mapping")
    return dict(value)


def _reject_unknown(value: dict[str, Any], allowed: set[str], name: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ConfigurationError(f"Unknown keys in {name}: {', '.join(sorted(unknown))}")


def _strings(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ConfigurationError(f"{name} must be a list of non-empty strings")
    return tuple(item.strip() for item in value)


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{name} must be an integer")
    result = value
    if result < minimum or result > maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return result


def _bounded_float(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{name} must be a number")
    result = float(value)
    if (
        result != result
        or result in (float("inf"), float("-inf"))
        or not minimum <= result <= maximum
    ):
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return result


def _boolean(value: Any, name: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigurationError(f"{name} must be true or false")
    return value


def _resolve_local(root: Path, raw: Any, name: str) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ConfigurationError(f"{name} must be a non-empty path")
    path = Path(raw).expanduser()
    # Keep the final component unresolved so the storage, salt, and report
    # boundaries can detect and reject a final symlink before use.
    return (root / path).absolute() if not path.is_absolute() else path.absolute()


def _credential_reference(options: dict[str, Any], key: str) -> None:
    if key not in options:
        return
    value = options[key]
    if not isinstance(value, str) or not _ENV_NAME.fullmatch(value):
        raise ConfigurationError(f"{key} must name an uppercase environment variable")
    suspicious = ("token_", "secret_", "bearer ", "eyj", "-----begin")
    if value.lower().startswith(suspicious):
        raise ConfigurationError(
            f"{key} appears to contain a secret; provide only its environment-variable name"
        )


def _default_policy(source_type: str) -> dict[str, Any]:
    if source_type == "reddit":
        return {
            "acquisition_mode": "official_api",
            "approval_required": True,
            "approval_reference": "Reddit Responsible Builder Policy",
            "raw_ttl_hours": 48,
            "deletion_reconcile_interval_hours": 48,
            "redistribution_mode": "ids_links_aggregates",
        }
    if source_type == "x":
        return {
            "acquisition_mode": "official_api",
            "approval_required": True,
            "approval_reference": "X Developer Guidelines",
            "raw_ttl_hours": 24,
            "deletion_reconcile_interval_hours": 24,
            "redistribution_mode": "ids_links_aggregates",
        }
    if source_type in {"reddit_apify", "x_apify"}:
        is_reddit = source_type == "reddit_apify"
        return {
            "acquisition_mode": "third_party_scraper",
            "approval_required": True,
            "approval_reference": (
                "Reddit and Apify terms" if is_reddit else "X and Apify terms"
            ),
            # Remote processing is deliberately not opted in by default. The
            # source policy must contain an explicit true value below.
            "remote_processing_allowed": False,
            "raw_ttl_hours": 48 if is_reddit else 24,
            "deletion_reconcile_interval_hours": 48 if is_reddit else 24,
            "redistribution_mode": "ids_links_aggregates",
        }
    if source_type == "external":
        return {
            "acquisition_mode": "external",
            "approval_required": False,
            "approval_reference": "User-supplied policy assurance",
            "raw_ttl_hours": 0,
            "redistribution_mode": "user_asserted",
        }
    return {
        "acquisition_mode": "user_input",
        "approval_required": False,
        "approval_reference": "Local user input",
        "raw_ttl_hours": 0,
        "redistribution_mode": "local_only",
    }


def _parse_sources(values: Any, limits: LimitsConfig) -> tuple[SourceConfig, ...]:
    if not isinstance(values, list) or not values:
        raise ConfigurationError("sources must be a non-empty list")
    result: list[SourceConfig] = []
    seen: set[str] = set()
    for index, raw in enumerate(values):
        item = _mapping(raw, f"sources[{index}]")
        unknown_source_keys = set(item) - _SOURCE_KEYS
        if unknown_source_keys:
            raise ConfigurationError(
                f"Unknown keys in sources[{index}]: {', '.join(sorted(unknown_source_keys))}"
            )
        source_id = item.get("id", "")
        source_type = item.get("type", "")
        if not isinstance(source_id, str):
            raise ConfigurationError(f"sources[{index}].id must be a string")
        if not isinstance(source_type, str):
            raise ConfigurationError(f"sources[{index}].type must be a string")
        if not _SOURCE_ID.fullmatch(source_id):
            raise ConfigurationError(f"sources[{index}].id must match {_SOURCE_ID.pattern}")
        if source_id in seen:
            raise ConfigurationError(f"Duplicate source id: {source_id}")
        seen.add(source_id)
        if source_type not in {
            "json",
            "url",
            "external",
            "reddit",
            "x",
            "reddit_apify",
            "x_apify",
        }:
            raise ConfigurationError(f"Unsupported source type: {source_type}")
        enabled = _boolean(item.get("enabled"), f"sources[{index}].enabled", True)
        max_items = _bounded_int(
            item.get("max_items", limits.max_items_per_source),
            f"sources[{index}].max_items",
            1,
            limits.max_items_per_source,
        )
        options = _mapping(item.get("options"), f"sources[{index}].options")
        unknown_options = set(options) - _SOURCE_OPTION_KEYS[source_type]
        if unknown_options:
            raise ConfigurationError(
                f"Unknown options for {source_type} source {source_id}: "
                f"{', '.join(sorted(unknown_options))}"
            )
        for boolean_option in (
            "allow_http",
            "permissive",
            "approval_confirmed",
            "stdin",
            "search_comments",
            "include_nsfw",
            "exclude_retweets",
        ):
            if boolean_option in options:
                _boolean(
                    options[boolean_option],
                    f"sources[{index}].options.{boolean_option}",
                    False,
                )
        for key in (
            "client_id_env",
            "client_secret_env",
            "bearer_token_env",
            "user_token_env",
            "token_env",
        ):
            _credential_reference(options, key)
        if source_type == "external":
            modes = [key for key in ("path", "stdin", "command") if key in options]
            if len(modes) != 1:
                raise ConfigurationError(
                    "External source requires exactly one of options.path, "
                    "options.stdin, or options.command"
                )
            if "stdin" in options and options["stdin"] is not True:
                raise ConfigurationError("external options.stdin must be true when selected")
        if source_type == "external" and "command" in options:
            command = options["command"]
            if (
                not isinstance(command, list)
                or not command
                or len(command) > 64
                or not all(isinstance(arg, str) and arg for arg in command)
            ):
                raise ConfigurationError(
                    "external command must contain between 1 and 64 arguments"
                )
            if any(len(argument) > 4_096 or "\x00" in argument for argument in command):
                raise ConfigurationError(
                    "external command contains an invalid or oversized argument"
                )
            executable = Path(command[0])
            if not executable.is_absolute():
                raise ConfigurationError("external command executable must be an absolute path")
            if os.name == "nt" and executable.suffix.lower() in {".bat", ".cmd"}:
                raise ConfigurationError("Windows batch collectors are not supported")
        policy_input = _mapping(item.get("policy"), f"sources[{index}].policy")
        unknown_policy = set(policy_input) - _POLICY_KEYS
        if unknown_policy:
            raise ConfigurationError(
                f"Unknown policy keys for source {source_id}: {', '.join(sorted(unknown_policy))}"
            )
        if source_type in {"x", "reddit_apify", "x_apify"}:
            max_cost = policy_input.get("max_cost_usd")
            if max_cost is None:
                raise ConfigurationError(
                    f"Paid source {source_id} requires policy.max_cost_usd"
                )
        policy_values = _default_policy(source_type)
        policy_values.update(policy_input)
        try:
            policy = PolicyCapabilities.from_mapping(policy_values)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"Invalid policy for source {source_id}: {exc}") from exc
        social_types = {"reddit", "x", "reddit_apify", "x_apify"}
        if source_type in social_types and policy.raw_ttl_hours < 1:
            raise ConfigurationError(
                f"Social source {source_id} requires policy.raw_ttl_hours of at least 1"
            )
        if source_type in social_types and (
            not policy.policy_version or not policy.policy_version_checked_at
        ):
            raise ConfigurationError(
                f"Source {source_id} requires policy_version and policy_version_checked_at"
            )
        if source_type in {"reddit_apify", "x_apify"}:
            if policy_input.get("remote_processing_allowed") is not True:
                raise ConfigurationError(
                    f"Apify source {source_id} requires explicit "
                    "policy.remote_processing_allowed: true"
                )
        result.append(SourceConfig(source_id, source_type, enabled, max_items, options, policy))
    return tuple(result)


_CASE_INSENSITIVE_PATHS = os.name == "nt" or sys.platform == "darwin"


def _collision_path(path: Path) -> Path:
    """Normalize a path for ownership comparison while still rejecting it at use."""

    return path.expanduser().absolute().resolve(strict=False)


def _collision_key(path: Path) -> str:
    # APFS commonly treats canonically equivalent Unicode spellings as the
    # same name.  Normalize even before either path exists so a writable report
    # can never be configured over a database or input using NFC/NFD aliases.
    value = unicodedata.normalize("NFC", os.path.normpath(str(_collision_path(path))))
    return value.casefold() if _CASE_INSENSITIVE_PATHS else os.path.normcase(value)


def _paths_collide(first: Path, second: Path) -> bool:
    if _collision_key(first) == _collision_key(second):
        return True
    try:
        return first.exists() and second.exists() and os.path.samefile(first, second)
    except OSError:
        return False


def validate_path_ownership(config: AppConfig) -> None:
    """Keep fixed report outputs from overlapping private or user-owned files."""

    # A path marked writable may be created, replaced, or deleted by the app.
    # It must not alias any other owned path. Read-only inputs may intentionally
    # be shared by more than one source, so those do not conflict with each
    # other.
    owned: list[tuple[str, Path, bool]] = [
        ("configuration file", config.path, False),
        ("storage.path", config.storage.path, True),
        ("storage journal", Path(f"{config.storage.path}-journal"), True),
        ("storage WAL", Path(f"{config.storage.path}-wal"), True),
        ("storage shared-memory file", Path(f"{config.storage.path}-shm"), True),
        ("privacy.author_salt_file", config.privacy.author_salt_file, True),
        ("outputs.directory", config.outputs.directory, True),
    ]
    owned.extend(
        (f"report destination {name}", config.outputs.directory / name, True)
        for name in RESERVED_REPORT_FILENAMES
    )

    def source_path(raw: str) -> Path:
        value = Path(raw).expanduser()
        return (config.root / value).absolute() if not value.is_absolute() else value.absolute()

    for source in config.sources:
        if source.type == "json":
            paths = source.options.get("paths", [])
            if isinstance(paths, list):
                owned.extend(
                    (f"JSON input for source {source.id}", source_path(value), False)
                    for value in paths
                    if isinstance(value, str)
                )
        elif source.type == "external":
            path = source.options.get("path")
            if isinstance(path, str):
                owned.append(
                    (f"external input for source {source.id}", source_path(path), False)
                )
            command = source.options.get("command")
            if isinstance(command, list) and command and isinstance(command[0], str):
                owned.append(
                    (f"external executable for source {source.id}", Path(command[0]), False)
                )
    for provider in config.providers:
        if provider.command:
            owned.append(
                (f"provider executable {provider.id}", Path(provider.command[0]), False)
            )

    for index, (first_label, first_path, first_writable) in enumerate(owned):
        for second_label, second_path, second_writable in owned[index + 1 :]:
            if not (first_writable or second_writable):
                continue
            if _paths_collide(first_path, second_path):
                raise ConfigurationError(
                    f"Path ownership conflict between {first_label} and {second_label}"
                )


def _parse_providers(values: Any) -> tuple[SemanticProviderConfig, ...]:
    """Parse optional local providers without introducing a hosted data path."""

    if values is None:
        return ()
    if not isinstance(values, list):
        raise ConfigurationError("providers must be a list")
    result: list[SemanticProviderConfig] = []
    seen: set[str] = set()
    for index, raw in enumerate(values):
        item = _mapping(raw, f"providers[{index}]")
        _reject_unknown(item, _PROVIDER_KEYS, f"providers[{index}]")
        provider_id = item.get("id", "")
        provider_type = item.get("type", "")
        if not isinstance(provider_id, str) or not _SOURCE_ID.fullmatch(provider_id):
            raise ConfigurationError(f"providers[{index}].id must match {_SOURCE_ID.pattern}")
        if provider_id in seen:
            raise ConfigurationError(f"Duplicate provider id: {provider_id}")
        seen.add(provider_id)
        if provider_type != "local_subprocess":
            raise ConfigurationError(
                f"providers[{index}].type must be local_subprocess"
            )
        enabled = _boolean(item.get("enabled"), f"providers[{index}].enabled", False)
        command = item.get("command")
        if (
            not isinstance(command, list)
            or not command
            or len(command) > 64
            or not all(isinstance(argument, str) and argument for argument in command)
        ):
            raise ConfigurationError(
                f"providers[{index}].command must contain between 1 and 64 arguments"
            )
        if any(len(argument) > 4_096 or "\x00" in argument for argument in command):
            raise ConfigurationError(
                f"providers[{index}].command contains an invalid or oversized argument"
            )
        executable = Path(command[0])
        if not executable.is_absolute():
            raise ConfigurationError(
                f"providers[{index}].command executable must be an absolute path"
            )
        if os.name == "nt" and executable.suffix.lower() in {".bat", ".cmd"}:
            raise ConfigurationError("Windows batch providers are not supported")
        model = item.get("model", "")
        if not isinstance(model, str) or not model.strip() or len(model) > 256:
            raise ConfigurationError(
                f"providers[{index}].model must be a non-empty string of at most 256 characters"
            )
        result.append(
            SemanticProviderConfig(
                id=provider_id,
                type=provider_type,
                enabled=enabled,
                command=tuple(command),
                model=model.strip(),
                output_schema_version=_bounded_int(
                    item.get("output_schema_version", 1),
                    f"providers[{index}].output_schema_version",
                    1,
                    1,
                ),
                timeout_seconds=_bounded_float(
                    item.get("timeout_seconds", 30),
                    f"providers[{index}].timeout_seconds",
                    0.1,
                    600,
                ),
                max_output_bytes=_bounded_int(
                    item.get("max_output_bytes", 1 * 1024 * 1024),
                    f"providers[{index}].max_output_bytes",
                    1024,
                    10 * 1024 * 1024,
                ),
                max_retries=_bounded_int(
                    item.get("max_retries", 0),
                    f"providers[{index}].max_retries",
                    0,
                    2,
                ),
            )
        )
    return tuple(result)


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path).expanduser().resolve()
    raw = _load_yaml(_read_regular_text(config_path))
    unknown = set(raw) - _TOP_LEVEL_KEYS
    if unknown:
        raise ConfigurationError(
            f"Unknown top-level configuration keys: {', '.join(sorted(unknown))}"
        )
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != CONFIG_VERSION:
        raise ConfigurationError(f"Configuration version must be {CONFIG_VERSION}")
    root = config_path.parent
    product_raw = _mapping(raw.get("product"), "product")
    _reject_unknown(product_raw, _PRODUCT_KEYS, "product")
    raw_name = product_raw.get("name", "")
    if not isinstance(raw_name, str):
        raise ConfigurationError("product.name must be a string")
    name = raw_name.strip()
    if not name:
        raise ConfigurationError("product.name is required")
    aliases = _strings(product_raw.get("aliases", []), "product.aliases")
    terms = _strings(product_raw.get("terms", []), "product.terms")
    exclusions = _strings(product_raw.get("exclusions", []), "product.exclusions")
    languages = _strings(product_raw.get("languages", ["en"]), "product.languages")
    product = ProductConfig(name, aliases, terms, exclusions, languages)

    storage_raw = _mapping(raw.get("storage"), "storage")
    _reject_unknown(storage_raw, _STORAGE_KEYS, "storage")
    storage = StorageConfig(
        _resolve_local(root, storage_raw.get("path", ".feedback/feedback.db"), "storage.path")
    )
    privacy_raw = _mapping(raw.get("privacy"), "privacy")
    _reject_unknown(privacy_raw, _PRIVACY_KEYS, "privacy")
    privacy = PrivacyConfig(
        _resolve_local(
            root,
            privacy_raw.get("author_salt_file", ".feedback/author_salt"),
            "privacy.author_salt_file",
        )
    )

    limit_raw = _mapping(raw.get("limits"), "limits")
    _reject_unknown(limit_raw, _LIMIT_KEYS, "limits")
    limits = LimitsConfig(
        max_items_per_source=_bounded_int(
            limit_raw.get("max_items_per_source", 1000), "limits.max_items_per_source", 1, 100_000
        ),
        max_file_bytes=_bounded_int(
            limit_raw.get("max_file_bytes", 10 * 1024 * 1024),
            "limits.max_file_bytes",
            1024,
            1_000_000_000,
        ),
        max_line_bytes=_bounded_int(
            limit_raw.get("max_line_bytes", 1024 * 1024), "limits.max_line_bytes", 256, 100_000_000
        ),
        max_url_bytes=_bounded_int(
            limit_raw.get("max_url_bytes", 2 * 1024 * 1024),
            "limits.max_url_bytes",
            1024,
            100_000_000,
        ),
        max_decompressed_bytes=_bounded_int(
            limit_raw.get("max_decompressed_bytes", 4 * 1024 * 1024),
            "limits.max_decompressed_bytes",
            1024,
            200_000_000,
        ),
        connect_timeout_seconds=_bounded_float(
            limit_raw.get("connect_timeout_seconds", 5), "limits.connect_timeout_seconds", 0.1, 60
        ),
        read_timeout_seconds=_bounded_float(
            limit_raw.get("read_timeout_seconds", 15), "limits.read_timeout_seconds", 0.1, 300
        ),
        total_timeout_seconds=_bounded_float(
            limit_raw.get("total_timeout_seconds", 30), "limits.total_timeout_seconds", 0.1, 600
        ),
        max_redirects=_bounded_int(
            limit_raw.get("max_redirects", 3), "limits.max_redirects", 0, 10
        ),
        external_timeout_seconds=_bounded_float(
            limit_raw.get("external_timeout_seconds", 60),
            "limits.external_timeout_seconds",
            0.1,
            3600,
        ),
        external_output_bytes=_bounded_int(
            limit_raw.get("external_output_bytes", 10 * 1024 * 1024),
            "limits.external_output_bytes",
            1024,
            1_000_000_000,
        ),
    )

    analysis_raw = _mapping(raw.get("analysis"), "analysis")
    _reject_unknown(analysis_raw, _ANALYSIS_KEYS, "analysis")
    weights_raw = (
        _mapping(analysis_raw.get("weights"), "analysis.weights") or AnalysisConfig().weights
    )
    weights = {
        str(key): _bounded_float(value, f"analysis.weights.{key}", 0.0, 1.0)
        for key, value in weights_raw.items()
    }
    expected_weights = {"authors", "sources", "recency", "severity", "relevance", "engagement"}
    if set(weights) != expected_weights:
        raise ConfigurationError(
            f"analysis.weights must contain exactly: {', '.join(sorted(expected_weights))}"
        )
    total_weight = sum(weights.values())
    if not 0.99 <= total_weight <= 1.01:
        raise ConfigurationError("analysis.weights must sum to 1.0")
    analysis = AnalysisConfig(
        relevance_threshold=_bounded_float(
            analysis_raw.get("relevance_threshold", 0.35), "analysis.relevance_threshold", 0, 1
        ),
        suppression_threshold=_bounded_float(
            analysis_raw.get("suppression_threshold", 0.8), "analysis.suppression_threshold", 0, 1
        ),
        cluster_similarity_threshold=_bounded_float(
            analysis_raw.get("cluster_similarity_threshold", 0.42),
            "analysis.cluster_similarity_threshold",
            0,
            1,
        ),
        weights=weights,
    )

    output_raw = _mapping(raw.get("outputs"), "outputs")
    _reject_unknown(output_raw, _OUTPUT_KEYS, "outputs")
    outputs = OutputConfig(
        _resolve_local(root, output_raw.get("directory", "reports"), "outputs.directory")
    )
    providers = _parse_providers(raw.get("providers"))
    sources = _parse_sources(raw.get("sources"), limits)
    hash_payload = json.loads(canonical_json(raw))
    config_hash = stable_hash(canonical_json(hash_payload), prefix="cfg_")
    config = AppConfig(
        config_path,
        root,
        product,
        storage,
        privacy,
        limits,
        analysis,
        outputs,
        sources,
        config_hash,
        providers,
    )
    validate_path_ownership(config)
    return config
