"""X feedback collection through the fixed Apify community Actor."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Mapping
from urllib.parse import urlsplit

from ..errors import CollectionError, ConfigurationError
from ..models import RawRecord
from ..util import pseudonymize_author, sanitize_text
from .apify import (
    ApifyProvenance,
    ApifySettings,
    ApifySocialConnector,
    bounded_string_list,
    finite_engagement,
    scalar_metadata,
    social_url,
    utc_timestamp,
)

_X_HOSTS = frozenset({"x.com", "www.x.com", "twitter.com", "www.twitter.com"})
_POST_ID = re.compile(r"^[0-9]{1,20}$")
_LANGUAGE = re.compile(r"^[a-z]{2}$")
_STATUS_PATH = re.compile(r"^/[^/]{1,64}/status/([0-9]{1,20})(?:/)?$")


def _x_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise CollectionError("X Apify item has an invalid creation timestamp")
    parsed: datetime | None = None
    try:
        candidate = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if candidate.tzinfo is not None:
            parsed = candidate
    except ValueError:
        pass
    if parsed is None:
        try:
            parsed = datetime.strptime(value, "%a %b %d %H:%M:%S %z %Y")
        except ValueError as exc:
            raise CollectionError("X Apify item has an invalid creation timestamp") from exc
    return utc_timestamp(parsed)


class XApifyConnector(ApifySocialConnector):
    """Collect public X posts without X developer credentials."""

    actor_id = "apidojo/twitter-scraper-lite"

    def _searches_and_urls(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        options = self.source.options
        raw_urls = options.get("start_urls")
        raw_searches = options.get("search_terms")
        if raw_urls is not None and raw_searches is not None:
            raise ConfigurationError("X Apify options must use search_terms or start_urls, not both")
        urls: tuple[str, ...] = ()
        if raw_urls is not None:
            supplied = bounded_string_list(
                raw_urls,
                "X Apify options.start_urls",
                maximum_items=50,
                maximum_chars=4_096,
            )
            try:
                urls = tuple(
                    social_url(
                        item,
                        allowed_hosts=_X_HOSTS,
                        label="X Apify start URL",
                        keep_query=True,
                    )
                    for item in supplied
                )
            except CollectionError as exc:
                raise ConfigurationError(str(exc)) from exc
            return (), urls
        if raw_searches is not None:
            searches = bounded_string_list(
                raw_searches,
                "X Apify options.search_terms",
                maximum_items=50,
                maximum_chars=512,
            )
        else:
            terms = (self.config.product.name, *self.config.product.aliases)
            clean_terms = [
                sanitize_text(term, max_chars=128).replace('"', "") for term in terms
            ]
            query = " OR ".join(f'"{term}"' for term in clean_terms if term)
            exclusions = [
                sanitize_text(term, max_chars=64).replace('"', "")
                for term in self.config.product.exclusions
            ]
            if exclusions:
                query += " " + " ".join(f'-"{term}"' for term in exclusions if term)
            if not query or len(query) > 512:
                raise ConfigurationError(
                    "Product name and aliases cannot form a bounded X Apify search"
                )
            searches = (query,)
        exclude_retweets = options.get("exclude_retweets", True)
        if not isinstance(exclude_retweets, bool):
            raise ConfigurationError("X Apify options.exclude_retweets must be true or false")
        if exclude_retweets:
            searches = tuple(
                item if "-filter:retweets" in item else f"{item} -filter:retweets"
                for item in searches
            )
            if any(len(item) > 512 for item in searches):
                raise ConfigurationError(
                    "X Apify search term exceeds 512 characters after retweet filtering"
                )
        return searches, ()

    def _platform_options(self) -> dict[str, Any]:
        options = self.source.options
        searches, urls = self._searches_and_urls()
        sort = options.get("sort", "Latest")
        if sort not in {"Top", "Latest", "Latest + Top"}:
            raise ConfigurationError("X Apify options.sort has an unsupported value")
        language = options.get("tweet_language", "")
        if language != "" and (
            not isinstance(language, str) or _LANGUAGE.fullmatch(language) is None
        ):
            raise ConfigurationError(
                "X Apify options.tweet_language must be a lowercase ISO 639-1 code"
            )
        exclude_retweets = options.get("exclude_retweets", True)
        if not isinstance(exclude_retweets, bool):
            raise ConfigurationError("X Apify options.exclude_retweets must be true or false")
        return {
            "exclude_retweets": exclude_retweets,
            "search_terms": searches,
            "sort": sort,
            "start_urls": urls,
            "tweet_language": language,
        }

    def _scope_options(self, settings: ApifySettings) -> Mapping[str, Any]:
        del settings
        return self._platform_options()

    def _actor_input(self, settings: ApifySettings, *, since: datetime) -> dict[str, Any]:
        del settings
        options = self._platform_options()
        actor_input: dict[str, Any] = {
            "includeSearchTerms": False,
            "maxItems": self.source.max_items,
            "sort": options["sort"],
            "start": since.date().isoformat(),
        }
        if options["search_terms"]:
            actor_input["searchTerms"] = list(options["search_terms"])
        else:
            actor_input["startUrls"] = list(options["start_urls"])
        language = options["tweet_language"]
        if language:
            actor_input["tweetLanguage"] = language
        return actor_input

    def _query_label(self, settings: ApifySettings) -> str:
        del settings
        options = self._platform_options()
        if options["search_terms"]:
            return "x_apify search=" + " | ".join(options["search_terms"])
        return f"x_apify urls={len(options['start_urls'])}"

    def _normalize_item(
        self,
        item: Mapping[str, Any],
        *,
        provenance: ApifyProvenance,
        retrieved_at: str,
    ) -> RawRecord | None:
        if item.get("type") != "tweet":
            return None
        native_id = item.get("id")
        if not isinstance(native_id, str) or _POST_ID.fullmatch(native_id) is None:
            raise CollectionError("X Apify item has an invalid native ID")
        if self.source.options.get("exclude_retweets", True) and item.get("isRetweet") is True:
            return None
        text = item.get("text")
        if not isinstance(text, str) or not text or len(text) > 200_000:
            raise CollectionError("X Apify item has invalid or oversized text")
        cleaned_text = sanitize_text(text, max_chars=200_000)
        if not cleaned_text:
            return None
        canonical_url = social_url(
            item.get("url") or item.get("twitterUrl"),
            allowed_hosts=_X_HOSTS,
            label="X Apify result URL",
        )
        path_match = _STATUS_PATH.fullmatch(urlsplit(canonical_url).path)
        if path_match is None or path_match.group(1) != native_id:
            raise CollectionError("X Apify result URL does not match its native ID")
        author = item.get("author")
        if author is None:
            author = {}
        if not isinstance(author, dict):
            raise CollectionError("X Apify item has an invalid author object")
        author_id = author.get("id")
        username = author.get("userName")
        if author_id is not None and (
            not isinstance(author_id, str) or _POST_ID.fullmatch(author_id) is None
        ):
            raise CollectionError("X Apify item has an invalid author ID")
        if username is not None and (
            not isinstance(username, str) or not username or len(username) > 64
        ):
            raise CollectionError("X Apify item has an invalid author username")
        metadata: dict[str, Any] = {
            "actor_build_id": provenance.build_id,
            "actor_build_number": provenance.build_number,
            "actor_id": provenance.actor_id,
            "actor_requested_build": provenance.requested_build,
            "actor_run_id": provenance.run_id,
        }
        for source_name, target_name in (
            ("lang", "language"),
            ("quoteId", "quote_id"),
            ("isReply", "is_reply"),
            ("isRetweet", "is_retweet"),
            ("isQuote", "is_quote"),
        ):
            value = scalar_metadata(item.get(source_name))
            if value not in {None, ""}:
                metadata[target_name] = value
        return RawRecord(
            source_id=self.source.id,
            source_type=self.source.type,
            native_id=native_id,
            canonical_url=canonical_url,
            text=cleaned_text,
            created_at=_x_timestamp(item.get("createdAt")),
            retrieved_at=retrieved_at,
            author_key=pseudonymize_author(
                self.source.type,
                author_id or username,
                self.context.author_salt,
            ),
            engagement=finite_engagement(
                item,
                {
                    "bookmarkCount": "bookmarks",
                    "likeCount": "likes",
                    "quoteCount": "quotes",
                    "replyCount": "replies",
                    "retweetCount": "retweets",
                },
            ),
            metadata=metadata,
            query=self._query_label(self._common_settings(require_secret=False)),
            acquisition_mode="third_party_scraper",
            policy_assurance="operator_confirmed",
        )


__all__ = ["XApifyConnector"]
