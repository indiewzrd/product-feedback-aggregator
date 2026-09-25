from __future__ import annotations

import json
from pathlib import Path

import yaml
from jsonschema import FormatChecker
from jsonschema.validators import validator_for

ROOT = Path(__file__).parents[1]


def _schema(name: str) -> dict[str, object]:
    value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    validator_for(value).check_schema(value)
    return value


def test_published_schemas_are_valid_and_accept_bundled_examples() -> None:
    config_schema = _schema("feedback.schema.json")
    input_schema = _schema("input.schema.json")
    config_validator = validator_for(config_schema)(
        config_schema,
        format_checker=FormatChecker(),
    )
    input_validator = validator_for(input_schema)(
        input_schema,
        format_checker=FormatChecker(),
    )

    config = yaml.safe_load((ROOT / "examples" / "feedback.example.yml").read_text("utf-8"))
    records = json.loads((ROOT / "examples" / "feedback.json").read_text("utf-8"))
    config_validator.validate(config)
    input_validator.validate(records)
    input_validator.validate({"schema_version": 1, "records": records})


def test_input_schema_matches_strict_runtime_field_boundaries() -> None:
    schema = _schema("input.schema.json")
    validator = validator_for(schema)(schema, format_checker=FormatChecker())
    valid = {
        "schema_version": 1,
        "id": 123,
        "text": "Example crashes on launch",
        "created_at": "2026-09-25T12:00:00Z",
        "author": None,
        "metadata": {"note": None},
    }
    validator.validate(valid)

    invalid = (
        {**valid, "id": True},
        {**valid, "text": 123},
        {**valid, "text": "x" * 200_001},
        {**valid, "url": 123},
        {**valid, "author": False},
        {**valid, "metadata": {"nested": []}},
        {**valid, "metadata": {"input_location": "spoofed"}},
    )
    assert all(not validator.is_valid(item) for item in invalid)


def test_config_schema_documents_structural_not_semantic_validation() -> None:
    schema = _schema("feedback.schema.json")
    assert "feedback check" in str(schema["description"])
    validator = validator_for(schema)(schema)
    # Empty weights mean "use deterministic defaults" in the loader, and a
    # source may be structurally declared before its readiness options exist.
    validator.validate(
        {
            "version": 1,
            "product": {"name": "Example"},
            "analysis": {"weights": {}},
            "sources": [{"id": "local", "type": "json"}],
        }
    )


def test_config_schema_accepts_pinned_apify_social_sources() -> None:
    schema = _schema("feedback.schema.json")
    validator = validator_for(schema)(schema)
    common_policy = {
        "acquisition_mode": "third_party_scraper",
        "approval_required": True,
        "approval_reference": "Operator-reviewed platform and Apify terms",
        "remote_processing_allowed": True,
        "raw_ttl_hours": 24,
        "max_cost_usd": 1.0,
        "policy_version": "apify-2026-09-25",
        "policy_version_checked_at": "2026-09-25",
    }

    validator.validate(
        {
            "version": 1,
            "product": {"name": "Example"},
            "sources": [
                {
                    "id": "reddit-apify",
                    "type": "reddit_apify",
                    "options": {
                        "approval_confirmed": True,
                        "actor_build": "1.2.3",
                        "searches": ["Example"],
                    },
                    "policy": {**common_policy, "raw_ttl_hours": 48},
                },
                {
                    "id": "x-apify",
                    "type": "x_apify",
                    "options": {
                        "approval_confirmed": True,
                        "actor_build": "1.2.3",
                        "search_terms": ["Example"],
                    },
                    "policy": common_policy,
                },
            ],
        }
    )
