"""Reddit feedback collection through the fixed Apify community Actor."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Mapping

from ..errors import CollectionError, ConfigurationError
from ..models import RawRecord
from ..util import pseudonymize_author, sanitize_text
from .apify import (
    ApifyProvenance,
    ApifySettings,
    ApifySocialConnector,
    bounded_integer,
    bounded_string_list,
    finite_engagement,
    scalar_metadata,
    social_url,
    utc_timestamp,
)

_REDDIT_HOSTS = frozenset(
    {"reddit.com", "www.reddit.com", "old.reddit.com", "redd.it", "www.redd.it"}
)
_FULLNAME = re.compile(r"^t[13]_[A-Za-z0-9]{1,252}$")
_SUBREDDIT = re.compile(r"^[A-Za-z0-9_]{2,21}$")


def _iso_timestamp(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise CollectionError("Reddit Apify item has an invalid creation timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CollectionError("Reddit Apify item has an invalid creation timestamp") from exc
    if parsed.tzinfo is None:
        raise CollectionError("Reddit Apify item creation timestamp lacks a timezone")
    return utc_timestamp(parsed)


class RedditApifyConnector(ApifySocialConnector):
    """Collect Reddit posts and comments without Reddit developer credentials."""

    actor_id = "trudax/reddit-scraper-lite"

    def _searches_and_urls(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        options = self.source.options
        raw_urls = options.get("start_urls")
        raw_searches = options.get("searches")
        if raw_urls is not None and raw_searches is not None:
            raise ConfigurationError(
                "Reddit Apify options must use searches or start_urls, not both"
            )
        urls: tuple[str, ...] = ()
        if raw_urls is not None:
            supplied = bounded_string_list(
                raw_urls,
                "Reddit Apify options.start_urls",
                maximum_items=50,
                maximum_chars=4_096,
            )
            try:
                urls = tuple(
                    social_url(
                        item,
                        allowed_hosts=_REDDIT_HOSTS,
                        label="Reddit Apify start URL",
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
                "Reddit Apify options.searches",
                maximum_items=20,
                maximum_chars=512,
            )
            return searches, ()

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
                "Product name and aliases cannot form a bounded Reddit Apify search"
            )
        return (query,), ()

    def _platform_options(self) -> dict[str, Any]:
        options = self.source.options
        searches, urls = self._searches_and_urls()
        community = options.get("search_community_name", "")
        if community != "" and (
            not isinstance(community, str) or _SUBREDDIT.fullmatch(community) is None
        ):
            raise ConfigurationError(
                "Reddit Apify options.search_community_name must be a subreddit name"
            )
        search_comments = options.get("search_comments", False)
        include_nsfw = options.get("include_nsfw", False)
        if not isinstance(search_comments, bool) or not isinstance(include_nsfw, bool):
            raise ConfigurationError("Reddit Apify boolean options must be true or false")
        return {
            "include_nsfw": include_nsfw,
            "max_comments": bounded_integer(
                options.get("max_comments", 20),
                "Reddit Apify options.max_comments",
                0,
                500,
            ),
            "max_post_count": bounded_integer(
                options.get("max_post_count", min(self.source.max_items, 1000)),
                "Reddit Apify options.max_post_count",
                1,
                10_000,
            ),
            "search_comments": search_comments,
            "search_community_name": community,
            "searches": searches,
            "start_urls": urls,
        }

    def _scope_options(self, settings: ApifySettings) -> Mapping[str, Any]:
        del settings
        return self._platform_options()

    def _actor_input(self, settings: ApifySettings, *, since: datetime) -> dict[str, Any]:
        del settings
        options = self._platform_options()
        max_comments = int(options["max_comments"])
        actor_input: dict[str, Any] = {
            "debugMode": False,
            "ignoreStartUrls": False,
            "includeMediaLinks": False,
            "includeNSFW": options["include_nsfw"],
            "maxComments": max_comments,
            "maxItems": self.source.max_items,
            "maxPostCount": options["max_post_count"],
            "postDateLimit": utc_timestamp(since),
            "commentDateLimit": utc_timestamp(since),
            "searchComments": options["search_comments"],
            "searchCommunities": False,
            "searchMedia": False,
            "searchPosts": True,
            "searchUsers": False,
            "skipComments": max_comments == 0,
            "skipCommunity": True,
            "skipUserPosts": True,
            "sort": "new",
            "time": "all",
        }
        searches = options["searches"]
        urls = options["start_urls"]
        if searches:
            actor_input["searches"] = list(searches)
            community = options["search_community_name"]
            if community:
                actor_input["searchCommunityName"] = community
        else:
            actor_input["startUrls"] = [{"url": item} for item in urls]
        return actor_input

    def _query_label(self, settings: ApifySettings) -> str:
        del settings
        options = self._platform_options()
        if options["searches"]:
            detail = " | ".join(options["searches"])
            community = options["search_community_name"]
            return f"reddit_apify search={detail}; community={community or 'all'}"
        return f"reddit_apify urls={len(options['start_urls'])}"

    def _normalize_item(
        self,
        item: Mapping[str, Any],
        *,
        provenance: ApifyProvenance,
        retrieved_at: str,
    ) -> RawRecord | None:
        data_type = item.get("dataType")
        if data_type not in {"post", "comment"}:
            return None
        native_id = item.get("id")
        expected_prefix = "t3_" if data_type == "post" else "t1_"
        if (
            not isinstance(native_id, str)
            or _FULLNAME.fullmatch(native_id) is None
            or not native_id.startswith(expected_prefix)
        ):
            raise CollectionError("Reddit Apify item has an invalid native ID")
        title = item.get("title", "")
        body = item.get("body", "")
        if title is None:
            title = ""
        if body is None:
            body = ""
        if not isinstance(title, str) or not isinstance(body, str):
            raise CollectionError("Reddit Apify item has invalid text fields")
        if len(title) > 10_000 or len(body) > 200_000:
            raise CollectionError("Reddit Apify item text exceeds the supported limit")
        text = sanitize_text(
            f"{title}\n{body}" if data_type == "post" else body,
            max_chars=200_000,
        )
        if not text:
            return None
        canonical_url = social_url(
            item.get("url"),
            allowed_hosts=_REDDIT_HOSTS,
            label="Reddit Apify result URL",
        )
        author = item.get("username")
        if author is not None and (
            not isinstance(author, str) or not author or len(author) > 256
        ):
            raise CollectionError("Reddit Apify item has an invalid author")
        metadata: dict[str, Any] = {
            "actor_build_id": provenance.build_id,
            "actor_build_number": provenance.build_number,
            "actor_id": provenance.actor_id,
            "actor_requested_build": provenance.requested_build,
            "actor_run_id": provenance.run_id,
            "data_type": data_type,
        }
        for source_name, target_name in (
            ("communityName", "community"),
            ("parentId", "parent_id"),
            ("postId", "post_id"),
            ("isAd", "is_ad"),
            ("over18", "over_18"),
        ):
            value = scalar_metadata(item.get(source_name))
            if value not in {None, ""}:
                metadata[target_name] = value
        return RawRecord(
            source_id=self.source.id,
            source_type=self.source.type,
            native_id=native_id,
            canonical_url=canonical_url,
            text=text,
            created_at=_iso_timestamp(item.get("createdAt")),
            retrieved_at=retrieved_at,
            author_key=pseudonymize_author(
                self.source.type,
                author,
                self.context.author_salt,
            ),
            engagement=finite_engagement(
                item,
                {
                    "numberOfComments": "comments",
                    "numberOfReplies": "replies",
                    "upVotes": "upvotes",
                },
            ),
            metadata=metadata,
            query=self._query_label(self._common_settings(require_secret=False)),
            acquisition_mode="third_party_scraper",
            policy_assurance="operator_confirmed",
        )


__all__ = ["RedditApifyConnector"]
