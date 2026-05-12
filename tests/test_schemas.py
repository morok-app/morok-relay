"""
Tests for schema validation — especially username rules.

No DB required.
"""
import pytest
from pydantic import ValidationError

from morok_relay.schemas import (
    RESERVED_USERNAMES,
    UsernameClaim,
    normalize_username,
)


class TestNormalizeUsername:
    def test_strips_at_sign(self):
        assert normalize_username("@lesya") == "lesya"

    def test_strips_multiple_at_signs(self):
        assert normalize_username("@@@stas") == "stas"

    def test_lowercases(self):
        assert normalize_username("LESYA") == "lesya"

    def test_strips_whitespace(self):
        assert normalize_username("  lesya  ") == "lesya"

    def test_combination(self):
        assert normalize_username("  @LESYA  ") == "lesya"


class TestUsernameValidator:
    def test_simple_valid(self):
        u = UsernameClaim(username="lesya")
        assert u.username == "lesya"

    def test_with_underscore(self):
        u = UsernameClaim(username="anon_42")
        assert u.username == "anon_42"

    def test_with_digits(self):
        u = UsernameClaim(username="user2026")
        assert u.username == "user2026"

    def test_normalizes_at_sign(self):
        u = UsernameClaim(username="@stas")
        assert u.username == "stas"

    def test_too_short(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="ab")

    def test_too_long(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="a" * 21)

    def test_uppercase_normalized(self):
        # Uppercase is normalized to lowercase, so this should pass.
        u = UsernameClaim(username="LESYA")
        assert u.username == "lesya"

    def test_starts_with_digit(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="42lesya")

    def test_starts_with_underscore(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="_admin")

    def test_invalid_chars(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="les-ya")
        with pytest.raises(ValidationError):
            UsernameClaim(username="les.ya")
        with pytest.raises(ValidationError):
            UsernameClaim(username="лесья")  # cyrillic not allowed

    def test_reserved_admin(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="admin")

    def test_reserved_morok(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="morok")

    def test_reserved_is_case_insensitive(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="ADMIN")

    def test_reserved_with_at_sign(self):
        with pytest.raises(ValidationError):
            UsernameClaim(username="@admin")


class TestReservedList:
    def test_contains_common_admin_names(self):
        for name in ["admin", "root", "system", "morok"]:
            assert name in RESERVED_USERNAMES

    def test_all_lowercase(self):
        for name in RESERVED_USERNAMES:
            assert name == name.lower()
