"""
Tests for group slug + GroupCreate validation. No DB required.
"""
from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from morok_relay.schemas import (
    GROUP_NAME_MAX_BYTES,
    RESERVED_SLUGS,
    SLUG_MAX_LEN,
    SLUG_MIN_LEN,
    GroupCreate,
    normalize_slug,
    validate_slug,
)


# ============================================================================
# Slug normalization
# ============================================================================

class TestNormalizeSlug:
    def test_strips_slash(self):
        assert normalize_slug("/news") == "news"

    def test_strips_at(self):
        assert normalize_slug("@news") == "news"

    def test_lowercases(self):
        assert normalize_slug("NEWS") == "news"

    def test_strips_whitespace(self):
        assert normalize_slug("  news  ") == "news"


# ============================================================================
# Slug validation
# ============================================================================

class TestValidateSlug:
    def test_valid_3_char(self):
        assert validate_slug("abc") == "abc"

    def test_valid_with_digits(self):
        assert validate_slug("news2026") == "news2026"

    def test_valid_with_underscore(self):
        assert validate_slug("news_ua") == "news_ua"

    def test_normalizes_uppercase(self):
        assert validate_slug("NEWS") == "news"

    def test_too_short(self):
        with pytest.raises(ValueError, match="too short"):
            validate_slug("ab")

    def test_too_long(self):
        with pytest.raises(ValueError, match="too long"):
            validate_slug("a" * (SLUG_MAX_LEN + 1))

    def test_starts_with_digit(self):
        with pytest.raises(ValueError, match="cannot start with digit"):
            validate_slug("42news")

    def test_starts_with_underscore(self):
        with pytest.raises(ValueError, match="cannot start with digit"):
            validate_slug("_news")

    def test_invalid_chars_dash(self):
        with pytest.raises(ValueError, match="lowercase letters"):
            validate_slug("news-ua")

    def test_invalid_chars_dot(self):
        with pytest.raises(ValueError, match="lowercase letters"):
            validate_slug("news.ua")

    def test_reserved_admin(self):
        with pytest.raises(ValueError, match="reserved"):
            validate_slug("admin")

    def test_reserved_api(self):
        with pytest.raises(ValueError, match="reserved"):
            validate_slug("api")

    def test_reserved_normalized_first(self):
        """Reserved check must apply AFTER normalization."""
        with pytest.raises(ValueError, match="reserved"):
            validate_slug("@ADMIN")


class TestReservedSlugList:
    def test_contains_routing_words(self):
        for s in ["api", "docs", "admin", "channel", "group"]:
            assert s in RESERVED_SLUGS

    def test_all_lowercase(self):
        for s in RESERVED_SLUGS:
            assert s == s.lower()


# ============================================================================
# GroupCreate
# ============================================================================

def _good_name(payload_bytes: bytes = b"\x01\x02\x03\x04 group-name-encrypted") -> str:
    """Helper to get a base64-encoded encrypted name."""
    return base64.b64encode(payload_bytes).decode()


class TestGroupCreate:
    def test_minimal(self):
        g = GroupCreate(name_encrypted=_good_name())
        assert g.is_channel is False
        assert g.default_ttl_seconds == 86400
        assert g.anonymous_senders is False
        assert g.expires_at is None
        assert g.slug is None

    def test_with_slug(self):
        g = GroupCreate(name_encrypted=_good_name(), slug="news")
        assert g.slug == "news"

    def test_slug_normalized(self):
        g = GroupCreate(name_encrypted=_good_name(), slug="NEWS")
        assert g.slug == "news"

    def test_slug_too_short_rejected(self):
        with pytest.raises(ValidationError):
            GroupCreate(name_encrypted=_good_name(), slug="ab")

    def test_reserved_slug_rejected(self):
        with pytest.raises(ValidationError):
            GroupCreate(name_encrypted=_good_name(), slug="admin")

    def test_ttl_too_low(self):
        with pytest.raises(ValidationError):
            GroupCreate(name_encrypted=_good_name(), default_ttl_seconds=10)

    def test_ttl_too_high(self):
        """TTL must not exceed 24 hours."""
        with pytest.raises(ValidationError):
            GroupCreate(name_encrypted=_good_name(), default_ttl_seconds=86401)

    def test_channel_flag(self):
        g = GroupCreate(name_encrypted=_good_name(), is_channel=True)
        assert g.is_channel is True

    def test_anonymous_flag(self):
        g = GroupCreate(name_encrypted=_good_name(), anonymous_senders=True)
        assert g.anonymous_senders is True

    def test_expires_at_set(self):
        g = GroupCreate(name_encrypted=_good_name(), expires_at=1900000000)
        assert g.expires_at == 1900000000

    def test_expires_at_negative_rejected(self):
        with pytest.raises(ValidationError):
            GroupCreate(name_encrypted=_good_name(), expires_at=-1)


class TestGroupCreateName:
    def test_empty_name_rejected(self):
        with pytest.raises(ValidationError):
            GroupCreate(name_encrypted=base64.b64encode(b"").decode())

    def test_oversized_name_rejected(self):
        big = base64.b64encode(b"x" * (GROUP_NAME_MAX_BYTES + 1)).decode()
        with pytest.raises(ValidationError):
            GroupCreate(name_encrypted=big)

    def test_max_size_accepted(self):
        ok = base64.b64encode(b"x" * GROUP_NAME_MAX_BYTES).decode()
        g = GroupCreate(name_encrypted=ok)
        assert g.name_encrypted == ok

    def test_invalid_base64_rejected(self):
        with pytest.raises(ValidationError):
            GroupCreate(name_encrypted="not base64!!!")
