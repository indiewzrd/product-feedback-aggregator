"""Deterministic, local feedback analysis.

The implementation deliberately uses small, inspectable lexical rules.  It is
not intended to decide whether a person is a bot or whether a product decision
is correct.  It creates reproducible evidence that a reviewer can inspect and
override, and it works without network access or model credentials.
"""

from __future__ import annotations

import math
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .models import RawRecord
from .util import canonical_json, normalized_text, sanitize_text, stable_hash

QUALITY_VERSION = "quality-lexical-v1"
EXTRACTION_VERSION = "sentence-signals-v1"
CLUSTERING_VERSION = "lexical-jaccard-v1"
SCORING_VERSION = "bounded-linear-v1"

_WORD_RE = re.compile(r"[\w']+", re.UNICODE)
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_SENTENCE_RE = re.compile(r"[^.!?\n]+(?:[.!?]+|(?=\n|$))", re.MULTILINE)
_REPEATED_PUNCTUATION_RE = re.compile(r"([!?$])\1{3,}")

_FEEDBACK_CUES = {
    "annoying",
    "broken",
    "bug",
    "confusing",
    "crash",
    "crashes",
    "difficult",
    "error",
    "fail",
    "fails",
    "feature",
    "fix",
    "frustrating",
    "hate",
    "improve",
    "issue",
    "love",
    "missing",
    "need",
    "problem",
    "request",
    "slow",
    "uninstall",
    "wish",
}
_PROMOTION_CUES = {
    "affiliate",
    "buy now",
    "coupon",
    "crypto",
    "discount",
    "free money",
    "giveaway",
    "promo code",
    "sponsored",
}
_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "but",
    "by",
    "for",
    "from",
    "has",
    "have",
    "i",
    "in",
    "is",
    "it",
    "my",
    "of",
    "on",
    "or",
    "that",
    "the",
    "this",
    "to",
    "was",
    "we",
    "with",
    "would",
    "you",
}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _record_id(record: RawRecord) -> str:
    """Return the identity used by both analysis and SQLite storage."""

    return stable_hash(
        sanitize_text(record.source_type),
        sanitize_text(record.source_id),
        sanitize_text(record.native_id),
        prefix="item_",
    )[:45]


def raw_record_id(record: RawRecord) -> str:
    """Public helper for the stable identity of a source record."""

    return _record_id(record)


def _tokens(value: object, *, drop_stop_words: bool = False) -> tuple[str, ...]:
    words = tuple(_WORD_RE.findall(normalized_text(value)))
    if drop_stop_words:
        return tuple(word for word in words if word not in _STOP_WORDS and len(word) > 1)
    return words


def _parse_time(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class ScoreWeights:
    """Version-one scoring weights.

    Positive weights sum to one.  Penalties are separately bounded so a noisy
    cluster can lose influence without producing a negative score.
    """

    distinct_authors: float = 0.22
    source_diversity: float = 0.10
    recency: float = 0.16
    severity_churn: float = 0.17
    relevance_confidence: float = 0.30
    engagement: float = 0.05
    exact_duplicate_penalty: float = 0.12
    burst_penalty: float = 0.08
    automation_spam_penalty: float = 0.15

    def validated(self) -> "ScoreWeights":
        values = asdict(self)
        if any(not math.isfinite(value) or value < 0 or value > 1 for value in values.values()):
            raise ValueError("score weights must be finite and between zero and one")
        positive = sum(
            values[name]
            for name in (
                "distinct_authors",
                "source_diversity",
                "recency",
                "severity_churn",
                "relevance_confidence",
                "engagement",
            )
        )
        if positive <= 0:
            raise ValueError("at least one positive score weight is required")
        return self


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    """Bounds and thresholds for deterministic analysis."""

    product_terms: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    languages: tuple[str, ...] = ("en",)
    relevance_threshold: float = 0.35
    noise_threshold: float = 0.75
    spam_threshold: float = 0.75
    automation_review_threshold: float = 0.70
    minimum_confidence: float = 0.45
    cluster_similarity: float = 0.45
    minimum_signal_chars: int = 8
    maximum_signals_per_record: int = 40
    maximum_total_signals: int = 10_000
    recency_half_life_days: float = 30.0
    score_weights: ScoreWeights = field(default_factory=ScoreWeights)

    @classmethod
    def from_runtime(
        cls,
        value: object,
        *,
        product_terms: Sequence[str] = (),
        exclusions: Sequence[str] = (),
        languages: Sequence[str] = (),
    ) -> "AnalysisConfig":
        """Adapt the public YAML configuration without coupling to its module.

        ``feedback_aggregator.config.AnalysisConfig`` intentionally contains a
        smaller user-facing vocabulary.  This adapter keeps the local analysis
        module independently testable while making the application integration
        a one-line conversion.
        """

        if isinstance(value, cls):
            return replace(
                value,
                product_terms=tuple(product_terms or value.product_terms),
                exclusions=tuple(exclusions or value.exclusions),
                languages=tuple(languages or value.languages),
            )
        incoming_weights = getattr(value, "weights", {})
        if not isinstance(incoming_weights, Mapping):
            incoming_weights = {}
        defaults = ScoreWeights()
        weights = ScoreWeights(
            distinct_authors=float(incoming_weights.get("authors", defaults.distinct_authors)),
            source_diversity=float(incoming_weights.get("sources", defaults.source_diversity)),
            recency=float(incoming_weights.get("recency", defaults.recency)),
            severity_churn=float(incoming_weights.get("severity", defaults.severity_churn)),
            relevance_confidence=float(
                incoming_weights.get("relevance", defaults.relevance_confidence)
            ),
            engagement=float(incoming_weights.get("engagement", defaults.engagement)),
            exact_duplicate_penalty=defaults.exact_duplicate_penalty,
            burst_penalty=defaults.burst_penalty,
            automation_spam_penalty=defaults.automation_spam_penalty,
        )
        suppression = float(getattr(value, "suppression_threshold", 0.75))
        return cls(
            product_terms=tuple(product_terms),
            exclusions=tuple(exclusions),
            languages=tuple(languages or ("en",)),
            relevance_threshold=float(getattr(value, "relevance_threshold", 0.35)),
            noise_threshold=suppression,
            spam_threshold=suppression,
            cluster_similarity=float(getattr(value, "cluster_similarity_threshold", 0.45)),
            score_weights=weights,
        )

    def validated(self) -> "AnalysisConfig":
        for name in (
            "relevance_threshold",
            "noise_threshold",
            "spam_threshold",
            "automation_review_threshold",
            "minimum_confidence",
            "cluster_similarity",
        ):
            value = float(getattr(self, name))
            if not 0 <= value <= 1:
                raise ValueError(f"{name} must be between zero and one")
        if (
            self.minimum_signal_chars < 1
            or self.maximum_signals_per_record < 1
            or self.maximum_total_signals < 1
        ):
            raise ValueError("signal limits must be positive")
        if not math.isfinite(self.recency_half_life_days) or self.recency_half_life_days <= 0:
            raise ValueError("recency_half_life_days must be positive")
        self.score_weights.validated()
        return self

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["product_terms"] = list(self.product_terms)
        return data


@dataclass(frozen=True, slots=True)
class QualityAssessment:
    record_id: str
    relevance: float
    noise: float
    spam: float
    automation: float
    confidence: float
    relevance_reasons: tuple[str, ...]
    noise_reasons: tuple[str, ...]
    spam_reasons: tuple[str, ...]
    automation_reasons: tuple[str, ...]
    disposition: str
    version: str = QUALITY_VERSION

    @property
    def reason_codes(self) -> tuple[str, ...]:
        return (
            self.relevance_reasons
            + self.noise_reasons
            + self.spam_reasons
            + self.automation_reasons
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["reason_codes"] = list(self.reason_codes)
        return data


@dataclass(frozen=True, slots=True)
class Signal:
    signal_id: str
    record_id: str
    source_id: str
    source_type: str
    author_key: str
    created_at: str
    signal_type: str
    normalized_statement: str
    evidence_start: int
    evidence_end: int
    evidence_text: str
    exact_hash: str
    relevance: float
    confidence: float
    extraction_version: str = EXTRACTION_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DuplicateGroup:
    group_id: str
    exact_hash: str
    signal_ids: tuple[str, ...]
    representative_signal_id: str
    method_version: str = EXTRACTION_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["signal_ids"] = list(self.signal_ids)
        return data


@dataclass(frozen=True, slots=True)
class Cluster:
    cluster_id: str
    label: str
    summary: str
    signal_ids: tuple[str, ...]
    representative_signal_id: str
    distinct_authors: int
    source_distribution: tuple[tuple[str, int], ...]
    time_start: str
    time_end: str
    clustering_version: str = CLUSTERING_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["signal_ids"] = list(self.signal_ids)
        data["source_distribution"] = dict(self.source_distribution)
        return data


@dataclass(frozen=True, slots=True)
class Score:
    cluster_id: str
    total: float
    rank: int
    components: Mapping[str, float]
    weights: Mapping[str, float]
    penalties: Mapping[str, float]
    formula_version: str
    configuration_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "total": self.total,
            "rank": self.rank,
            "components": dict(self.components),
            "weights": dict(self.weights),
            "penalties": dict(self.penalties),
            "formula_version": self.formula_version,
            "configuration_hash": self.configuration_hash,
        }


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    assessments: tuple[QualityAssessment, ...]
    signals: tuple[Signal, ...]
    duplicate_groups: tuple[DuplicateGroup, ...]
    clusters: tuple[Cluster, ...]
    scores: tuple[Score, ...]
    reference_time: str
    configuration_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessments": [item.to_dict() for item in self.assessments],
            "signals": [item.to_dict() for item in self.signals],
            "duplicate_groups": [item.to_dict() for item in self.duplicate_groups],
            "clusters": [item.to_dict() for item in self.clusters],
            "scores": [item.to_dict() for item in self.scores],
            "reference_time": self.reference_time,
            "configuration_hash": self.configuration_hash,
        }


def assess_record(
    record: RawRecord,
    config: AnalysisConfig | None = None,
) -> QualityAssessment:
    """Assess one record with separate, explainable probabilities.

    Automation likelihood alone never suppresses content.  A high value moves
    the item to pending review, which avoids turning a weak heuristic into a
    public assertion about an author.
    """

    config = AnalysisConfig.from_runtime(config or AnalysisConfig()).validated()
    text = sanitize_text(record.text)
    lowered = normalized_text(text)
    record_id = _record_id(record)
    tokens = _tokens(lowered)
    token_set = set(tokens)

    relevance_reasons: list[str] = []
    noise_reasons: list[str] = []
    spam_reasons: list[str] = []
    automation_reasons: list[str] = []

    if not lowered:
        return QualityAssessment(
            record_id=record_id,
            relevance=0.0,
            noise=1.0,
            spam=0.0,
            automation=0.0,
            confidence=1.0,
            relevance_reasons=("relevance:empty_text",),
            noise_reasons=("noise:empty_text",),
            spam_reasons=("spam:no_evidence",),
            automation_reasons=("automation:no_evidence",),
            disposition="invalid",
        )

    feedback_matches = sorted(token_set.intersection(_FEEDBACK_CUES))
    product_terms = tuple(
        term for term in (normalized_text(value) for value in config.product_terms) if term
    )
    term_matches = tuple(term for term in product_terms if term in lowered)
    exclusions = tuple(
        term for term in (normalized_text(value) for value in config.exclusions) if term
    )
    exclusion_matches = tuple(term for term in exclusions if term in lowered)

    if product_terms:
        relevance = 0.12
        if term_matches:
            relevance += 0.48 + min(0.18, 0.06 * (len(term_matches) - 1))
            relevance_reasons.append("relevance:product_term_match")
        else:
            relevance_reasons.append("relevance:no_product_term_match")
    else:
        relevance = 0.45
        relevance_reasons.append("relevance:no_product_terms_configured")
    if feedback_matches:
        relevance += 0.22
        relevance_reasons.append("relevance:feedback_language")
    if len(text) < 20:
        relevance -= 0.15
        relevance_reasons.append("relevance:very_short_text")
    relevance = _clamp(relevance)

    noise = 0.05
    if exclusion_matches:
        noise = 1.0
        noise_reasons.append("noise:configured_exclusion")
    metadata = record.metadata if isinstance(record.metadata, dict) else {}
    declared_language = normalized_text(metadata.get("lang") or metadata.get("language") or "")
    declared_language = declared_language.split("-", 1)[0]
    allowed_languages = {
        normalized_text(language).split("-", 1)[0]
        for language in config.languages
        if normalized_text(language)
    }
    if declared_language and allowed_languages and declared_language not in allowed_languages:
        noise = 1.0
        noise_reasons.append("noise:language_not_allowed")
    elif allowed_languages and not declared_language:
        noise_reasons.append("noise:language_unverified")
    if len(text) < 12:
        noise += 0.55
        noise_reasons.append("noise:too_short")
    if _URL_RE.fullmatch(text.strip()):
        noise += 0.45
        noise_reasons.append("noise:url_only")
    alphabetic = sum(character.isalpha() for character in text)
    if len(text) >= 20 and alphabetic / max(1, len(text)) < 0.45:
        noise += 0.35
        noise_reasons.append("noise:low_alphabetic_ratio")
    if not noise_reasons:
        noise_reasons.append("noise:no_strong_evidence")
    noise = _clamp(noise)

    spam = 0.03
    url_count = len(_URL_RE.findall(text))
    if url_count >= 3:
        spam += 0.45
        spam_reasons.append("spam:many_links")
    if any(cue in lowered for cue in _PROMOTION_CUES):
        spam += 0.55
        spam_reasons.append("spam:promotion_language")
    if _REPEATED_PUNCTUATION_RE.search(text):
        spam += 0.20
        spam_reasons.append("spam:repeated_punctuation")
    if len(tokens) >= 12 and len(token_set) / len(tokens) < 0.30:
        spam += 0.25
        spam_reasons.append("spam:repetitive_text")
    if not spam_reasons:
        spam_reasons.append("spam:no_strong_evidence")
    spam = _clamp(spam)

    automation = 0.02
    if metadata.get("is_bot") is True or metadata.get("automated") is True:
        automation = max(automation, 0.90)
        automation_reasons.append("automation:explicit_source_flag")
    claimed_probability = metadata.get("automation_probability")
    if isinstance(claimed_probability, (int, float)) and math.isfinite(claimed_probability):
        automation = max(automation, _clamp(float(claimed_probability)))
        automation_reasons.append("automation:source_probability")
    account_label = normalized_text(metadata.get("account_label") or metadata.get("username") or "")
    if account_label and (account_label.endswith("bot") or account_label.endswith("_bot")):
        automation = max(automation, 0.65)
        automation_reasons.append("automation:self_identified_name")
    if not automation_reasons:
        automation_reasons.append("automation:no_strong_evidence")
    automation = _clamp(automation)

    confidence = 0.82
    if not product_terms:
        confidence -= 0.12
    if len(text) < 20:
        confidence -= 0.15
    if not record.source_type or not record.native_id:
        confidence -= 0.12
    confidence = _clamp(confidence)

    if confidence < config.minimum_confidence:
        disposition = "pending_review"
    elif automation >= config.automation_review_threshold:
        disposition = "pending_review"
    elif (
        relevance < config.relevance_threshold
        or noise >= config.noise_threshold
        or spam >= config.spam_threshold
    ):
        disposition = "suppressed"
    else:
        disposition = "eligible"

    return QualityAssessment(
        record_id=record_id,
        relevance=round(relevance, 6),
        noise=round(noise, 6),
        spam=round(spam, 6),
        automation=round(automation, 6),
        confidence=round(confidence, 6),
        relevance_reasons=tuple(relevance_reasons),
        noise_reasons=tuple(noise_reasons),
        spam_reasons=tuple(spam_reasons),
        automation_reasons=tuple(automation_reasons),
        disposition=disposition,
    )


def _sentence_spans(text: str) -> Iterable[tuple[int, int, str]]:
    for match in _SENTENCE_RE.finditer(text):
        start, end = match.span()
        while start < end and text[start].isspace():
            start += 1
        while end > start and text[end - 1].isspace():
            end -= 1
        if start < end:
            yield start, end, text[start:end]


def _signal_type(statement: str) -> str:
    lowered = normalized_text(statement)
    words = set(_tokens(lowered))
    if words.intersection({"uninstall", "cancel", "leaving", "quit", "refund"}):
        return "churn_risk"
    if words.intersection({"crash", "crashes", "broken", "bug", "error", "fails", "failure"}):
        return "bug"
    if (
        words.intersection({"wish", "need", "feature", "request", "add", "support"})
        or "would like" in lowered
    ):
        return "feature_request"
    if words.intersection({"love", "great", "excellent", "helpful", "fast"}):
        return "praise"
    if words.intersection({"hate", "annoying", "confusing", "frustrating", "slow", "problem"}):
        return "complaint"
    return "other"


def extract_signals(
    record: RawRecord,
    assessment: QualityAssessment,
    config: AnalysisConfig | None = None,
) -> tuple[Signal, ...]:
    """Extract sentence-sized signals with offsets into the original text."""

    config = AnalysisConfig.from_runtime(config or AnalysisConfig()).validated()
    if assessment.disposition != "eligible":
        return ()
    record_id = _record_id(record)
    if assessment.record_id != record_id:
        raise ValueError("assessment does not belong to the supplied record")

    signals: list[Signal] = []
    for start, end, evidence in _sentence_spans(record.text):
        statement = normalized_text(evidence.lstrip("-*\u2022 "))
        if len(statement) < config.minimum_signal_chars:
            continue
        signal_type = _signal_type(statement)
        signal_id = stable_hash(
            record_id,
            start,
            end,
            statement,
            EXTRACTION_VERSION,
            prefix="signal_",
        )[:47]
        exact_hash = stable_hash(statement, prefix="exact_")[:46]
        signals.append(
            Signal(
                signal_id=signal_id,
                record_id=record_id,
                source_id=record.source_id,
                source_type=record.source_type,
                author_key=record.author_key,
                created_at=record.created_at,
                signal_type=signal_type,
                normalized_statement=statement,
                evidence_start=start,
                evidence_end=end,
                evidence_text=evidence,
                exact_hash=exact_hash,
                relevance=assessment.relevance,
                confidence=assessment.confidence,
            )
        )
        if len(signals) >= config.maximum_signals_per_record:
            break
    return tuple(signals)


def find_exact_duplicates(signals: Sequence[Signal]) -> tuple[DuplicateGroup, ...]:
    by_hash: dict[str, list[Signal]] = defaultdict(list)
    for signal in signals:
        by_hash[signal.exact_hash].append(signal)
    groups: list[DuplicateGroup] = []
    for exact_hash, members in sorted(by_hash.items()):
        if len(members) < 2:
            continue
        ids = tuple(sorted(member.signal_id for member in members))
        groups.append(
            DuplicateGroup(
                group_id=stable_hash(exact_hash, prefix="duplicate_")[:49],
                exact_hash=exact_hash,
                signal_ids=ids,
                representative_signal_id=ids[0],
            )
        )
    return tuple(groups)


def lexical_similarity(left: str, right: str) -> float:
    """Return stop-word-filtered token Jaccard similarity."""

    left_tokens = set(_tokens(left, drop_stop_words=True))
    right_tokens = set(_tokens(right, drop_stop_words=True))
    if not left_tokens and not right_tokens:
        return 1.0 if normalized_text(left) == normalized_text(right) else 0.0
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def cluster_signals(
    signals: Sequence[Signal],
    *,
    similarity_threshold: float = 0.45,
) -> tuple[Cluster, ...]:
    """Cluster signals as deterministic connected components of similar text."""

    if not 0 <= similarity_threshold <= 1:
        raise ValueError("similarity_threshold must be between zero and one")
    ordered = sorted(signals, key=lambda item: item.signal_id)
    parents = list(range(len(ordered)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            parents[right_root] = left_root
        else:
            parents[left_root] = right_root

    if similarity_threshold == 0 and ordered:
        for index in range(1, len(ordered)):
            union(0, index)
    else:
        # Candidate blocking keeps ordinary runs far below an all-pairs comparison.
        # Very common terms (often the product name) do not make useful blocks.
        token_sets = [
            set(_tokens(item.normalized_statement, drop_stop_words=True)) for item in ordered
        ]
        frequencies = Counter(token for values in token_sets for token in values)
        common_cutoff = max(50, math.ceil(len(ordered) * 0.25))
        token_index: dict[str, list[int]] = defaultdict(list)
        hash_index: dict[str, list[int]] = defaultdict(list)
        for right_index, right in enumerate(ordered):
            candidates = set(hash_index[right.exact_hash])
            for token in token_sets[right_index]:
                if frequencies[token] <= common_cutoff:
                    candidates.update(token_index[token])
            for left_index in sorted(candidates):
                left = ordered[left_index]
                if (
                    left.exact_hash == right.exact_hash
                    or lexical_similarity(left.normalized_statement, right.normalized_statement)
                    >= similarity_threshold
                ):
                    union(left_index, right_index)
            hash_index[right.exact_hash].append(right_index)
            for token in token_sets[right_index]:
                if frequencies[token] <= common_cutoff:
                    token_index[token].append(right_index)

    components: dict[int, list[Signal]] = defaultdict(list)
    for index, signal in enumerate(ordered):
        components[find(index)].append(signal)

    clusters: list[Cluster] = []
    for members in components.values():
        members.sort(key=lambda item: item.signal_id)
        representative = sorted(
            members,
            key=lambda item: (
                -(item.relevance * item.confidence),
                len(item.normalized_statement),
                item.normalized_statement,
                item.signal_id,
            ),
        )[0]
        distinct_hashes = tuple(sorted({member.exact_hash for member in members}))
        cluster_id = stable_hash(
            CLUSTERING_VERSION,
            *distinct_hashes,
            prefix="cluster_",
        )[:48]
        label_text = representative.normalized_statement[:96].strip()
        label = label_text[:1].upper() + label_text[1:]
        source_counts = Counter(member.source_type for member in members)
        authors = {member.author_key for member in members if member.author_key}
        valid_times = sorted(
            member.created_at for member in members if _parse_time(member.created_at)
        )
        summary = (
            f"1 signal: {label}"
            if len(members) == 1
            else f"{len(members)} related signals about {label.lower()}"
        )
        clusters.append(
            Cluster(
                cluster_id=cluster_id,
                label=label,
                summary=summary,
                signal_ids=tuple(member.signal_id for member in members),
                representative_signal_id=representative.signal_id,
                distinct_authors=len(authors),
                source_distribution=tuple(sorted(source_counts.items())),
                time_start=valid_times[0] if valid_times else "",
                time_end=valid_times[-1] if valid_times else "",
            )
        )
    return tuple(sorted(clusters, key=lambda item: item.cluster_id))


def _engagement_percentiles(records: Sequence[RawRecord]) -> dict[str, float]:
    grouped: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for record in records:
        total = sum(
            max(0.0, float(value))
            for value in record.engagement.values()
            if isinstance(value, (int, float)) and math.isfinite(value)
        )
        grouped[record.source_type].append((_record_id(record), total))

    percentiles: dict[str, float] = {}
    for values in grouped.values():
        numeric = sorted(value for _, value in values)
        if not numeric or max(numeric) <= 0:
            percentiles.update({record_id: 0.0 for record_id, _ in values})
            continue
        for record_id, value in values:
            percentiles[record_id] = bisect_right(numeric, value) / len(numeric)
    return percentiles


def _reference_time(signals: Sequence[Signal], requested: str | None) -> tuple[datetime, str]:
    if requested:
        parsed = _parse_time(requested)
        if parsed is None:
            raise ValueError("reference_time must be an RFC 3339 timestamp")
        return parsed, parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    parsed_times = [parsed for signal in signals if (parsed := _parse_time(signal.created_at))]
    reference = max(parsed_times) if parsed_times else datetime(1970, 1, 1, tzinfo=timezone.utc)
    return reference, reference.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def score_clusters(
    clusters: Sequence[Cluster],
    signals: Sequence[Signal],
    assessments: Sequence[QualityAssessment],
    records: Sequence[RawRecord],
    config: AnalysisConfig | None = None,
    *,
    reference_time: str | None = None,
) -> tuple[Score, ...]:
    """Calculate a bounded, reconstructable score for every cluster."""

    config = AnalysisConfig.from_runtime(config or AnalysisConfig()).validated()
    weights = asdict(config.score_weights)
    positive_names = (
        "distinct_authors",
        "source_diversity",
        "recency",
        "severity_churn",
        "relevance_confidence",
        "engagement",
    )
    positive_total = sum(weights[name] for name in positive_names)
    normalized_weights = {name: weights[name] / positive_total for name in positive_names}
    penalty_weights = {
        "exact_duplicates": weights["exact_duplicate_penalty"],
        "burst": weights["burst_penalty"],
        "automation_spam": weights["automation_spam_penalty"],
    }
    configuration_hash = stable_hash(
        canonical_json(config.to_dict()),
        SCORING_VERSION,
        prefix="config_",
    )[:47]
    reference, _ = _reference_time(signals, reference_time)
    engagement = _engagement_percentiles(records)
    by_signal = {signal.signal_id: signal for signal in signals}
    by_assessment = {assessment.record_id: assessment for assessment in assessments}

    severity = {
        "churn_risk": 1.0,
        "bug": 0.78,
        "complaint": 0.64,
        "feature_request": 0.55,
        "other": 0.38,
        "praise": 0.20,
    }
    provisional: list[tuple[Cluster, float, dict[str, float], dict[str, float]]] = []
    for cluster in clusters:
        members = [
            by_signal[signal_id] for signal_id in cluster.signal_ids if signal_id in by_signal
        ]
        if not members:
            continue
        author_count = cluster.distinct_authors or 1
        distinct_authors = min(1.0, math.log1p(author_count) / math.log1p(20))
        source_diversity = min(1.0, len(cluster.source_distribution) / 3.0)
        recencies: list[float] = []
        for member in members:
            created = _parse_time(member.created_at)
            if created is None:
                recencies.append(0.0)
            else:
                age_days = max(0.0, (reference - created).total_seconds() / 86_400)
                recencies.append(2 ** (-age_days / config.recency_half_life_days))
        component_values = {
            "distinct_authors": _clamp(distinct_authors),
            "source_diversity": _clamp(source_diversity),
            "recency": _clamp(sum(recencies) / len(recencies)),
            "severity_churn": _clamp(
                sum(severity.get(member.signal_type, severity["other"]) for member in members)
                / len(members)
            ),
            "relevance_confidence": _clamp(
                sum(member.relevance * member.confidence for member in members) / len(members)
            ),
            "engagement": _clamp(
                sum(engagement.get(member.record_id, 0.0) for member in members) / len(members)
            ),
        }
        unique_hashes = len({member.exact_hash for member in members})
        exact_duplicate_penalty = 1.0 - unique_hashes / len(members)
        buckets = Counter(
            (
                member.source_type,
                member.created_at[:10],
                member.author_key or "unknown",
            )
            for member in members
        )
        burst_penalty = 0.0
        if len(members) >= 3:
            concentration = max(buckets.values()) / len(members)
            burst_penalty = _clamp((concentration - 0.5) * 2)
        automation_values: list[float] = []
        for member in members:
            member_assessment = by_assessment.get(member.record_id)
            automation_values.append(
                max(member_assessment.automation, member_assessment.spam)
                if member_assessment is not None
                else 0.0
            )
        automation_spam = sum(automation_values) / len(members)
        penalties = {
            "exact_duplicates": _clamp(exact_duplicate_penalty),
            "burst": _clamp(burst_penalty),
            "automation_spam": _clamp(automation_spam),
        }
        positive_score = sum(
            normalized_weights[name] * component_values[name] for name in positive_names
        )
        penalty_score = sum(penalty_weights[name] * penalties[name] for name in penalties)
        total = round(100 * _clamp(positive_score - penalty_score), 3)
        provisional.append((cluster, total, component_values, penalties))

    provisional.sort(key=lambda item: (-item[1], item[0].cluster_id))
    return tuple(
        Score(
            cluster_id=cluster.cluster_id,
            total=total,
            rank=rank,
            components={name: round(value, 6) for name, value in components.items()},
            weights={
                **{name: round(value, 6) for name, value in normalized_weights.items()},
                **{f"{name}_penalty": round(value, 6) for name, value in penalty_weights.items()},
            },
            penalties={name: round(value, 6) for name, value in penalties.items()},
            formula_version=SCORING_VERSION,
            configuration_hash=configuration_hash,
        )
        for rank, (cluster, total, components, penalties) in enumerate(provisional, start=1)
    )


def analyze_records(
    records: Iterable[RawRecord],
    config: AnalysisConfig | None = None,
    *,
    reference_time: str | None = None,
    product_terms: Sequence[str] | None = None,
    disposition_overrides: Mapping[str, str] | None = None,
) -> AnalysisResult:
    """Run the complete deterministic local analysis pipeline."""

    config = AnalysisConfig.from_runtime(
        config or AnalysisConfig(),
        product_terms=tuple(product_terms or ()),
    ).validated()
    ordered_records = tuple(
        sorted(records, key=lambda record: (record.source_type, record.source_id, record.native_id))
    )
    overrides = dict(disposition_overrides or {})
    assessment_values: list[QualityAssessment] = []
    for record in ordered_records:
        assessment = assess_record(record, config)
        action = overrides.get(assessment.record_id)
        if action == "include":
            assessment = replace(
                assessment,
                disposition="eligible",
                relevance_reasons=assessment.relevance_reasons + ("review:include",),
            )
        elif action == "exclude":
            assessment = replace(
                assessment,
                disposition="suppressed",
                noise_reasons=assessment.noise_reasons + ("review:exclude",),
            )
        assessment_values.append(assessment)
    assessments = tuple(assessment_values)
    collected_signals: list[Signal] = []
    for record, assessment in zip(ordered_records, assessments, strict=True):
        collected_signals.extend(extract_signals(record, assessment, config))
        if len(collected_signals) > config.maximum_total_signals:
            raise ValueError("analysis signal limit exceeded")
    signals = tuple(collected_signals)
    duplicate_groups = find_exact_duplicates(signals)
    clusters = cluster_signals(signals, similarity_threshold=config.cluster_similarity)
    _, resolved_reference_time = _reference_time(signals, reference_time)
    scores = score_clusters(
        clusters,
        signals,
        assessments,
        ordered_records,
        config,
        reference_time=resolved_reference_time,
    )
    configuration_hash = stable_hash(
        canonical_json(config.to_dict()),
        QUALITY_VERSION,
        EXTRACTION_VERSION,
        CLUSTERING_VERSION,
        SCORING_VERSION,
        prefix="config_",
    )[:47]
    return AnalysisResult(
        assessments=assessments,
        signals=signals,
        duplicate_groups=duplicate_groups,
        clusters=clusters,
        scores=scores,
        reference_time=resolved_reference_time,
        configuration_hash=configuration_hash,
    )
