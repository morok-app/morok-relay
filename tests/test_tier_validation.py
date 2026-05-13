"""
Tests for username validation per tier.

No DB required — pure validation logic.
"""
import pytest

from morok_relay.schemas import (
    TIER_MIN_LENGTH,
    UsernameClaim,
    validate_username_for_tier,
)


class TestTierMinLengths:
    def test_free_is_5(self):
        assert TIER_MIN_LENGTH["free"] == 5

    def test_premium_is_3(self):
        assert TIER_MIN_LENGTH["premium"] == 3

    def test_admin_is_1(self):
        assert TIER_MIN_LENGTH["admin"] == 1


class TestFreeTier:
    def test_5_chars_passes(self):
        assert validate_username_for_tier("lesya", "free") == "lesya"

    def test_4_chars_rejected(self):
        with pytest.raises(ValueError, match="free accounts need 5"):
            validate_username_for_tier("anna", "free")

    def test_3_chars_rejected(self):
        with pytest.raises(ValueError, match="free accounts need 5"):
            validate_username_for_tier("max", "free")

    def test_long_name_passes(self):
        assert validate_username_for_tier("longusername", "free") == "longusername"


class TestPremiumTier:
    def test_3_chars_passes(self):
        assert validate_username_for_tier("max", "premium") == "max"

    def test_4_chars_passes(self):
        assert validate_username_for_tier("anna", "premium") == "anna"

    def test_2_chars_rejected(self):
        with pytest.raises(ValueError, match="premium tier needs 3"):
            validate_username_for_tier("ab", "premium")

    def test_1_char_rejected(self):
        with pytest.raises(ValueError, match="premium tier needs 3"):
            validate_username_for_tier("a", "premium")


class TestAdminTier:
    def test_1_char_passes(self):
        assert validate_username_for_tier("a", "admin") == "a"

    def test_2_chars_passes(self):
        assert validate_username_for_tier("ab", "admin") == "ab"


class TestCommonRules:
    @pytest.mark.parametrize("tier", ["free", "premium", "admin"])
    def test_uppercase_normalized(self, tier):
        assert validate_username_for_tier("LESYA", tier) == "lesya"

    @pytest.mark.parametrize("tier", ["free", "premium", "admin"])
    def test_at_sign_stripped(self, tier):
        if tier == "free":
            assert validate_username_for_tier("@lesya", tier) == "lesya"
        else:
            assert validate_username_for_tier("@max", tier) == "max"

    @pytest.mark.parametrize("tier", ["free", "premium", "admin"])
    def test_invalid_chars_rejected(self, tier):
        with pytest.raises(ValueError, match="lowercase letters, digits"):
            validate_username_for_tier("les-ya", tier)

    @pytest.mark.parametrize("tier", ["free", "premium", "admin"])
    def test_leading_digit_rejected(self, tier):
        with pytest.raises(ValueError, match="cannot start with digit"):
            validate_username_for_tier("42lesya", tier)

    @pytest.mark.parametrize("tier", ["free", "premium", "admin"])
    def test_leading_underscore_rejected(self, tier):
        with pytest.raises(ValueError, match="cannot start with digit"):
            validate_username_for_tier("_lesya", tier)

    @pytest.mark.parametrize("tier", ["free", "premium", "admin"])
    def test_too_long_rejected(self, tier):
        with pytest.raises(ValueError, match="too long"):
            validate_username_for_tier("a" * 21, tier)

    @pytest.mark.parametrize("tier", ["free", "premium", "admin"])
    def test_reserved_rejected(self, tier):
        with pytest.raises(ValueError, match="reserved"):
            validate_username_for_tier("admin", tier)


class TestPydanticSchema:
    """
    The Pydantic UsernameClaim does NOT enforce tier length (because tier
    isn't known until the endpoint loads the user from DB). It should still
    catch tier-independent issues.
    """
    def test_2_chars_passes_pydantic_but_fails_validator_later(self):
        # Pydantic itself allows it; endpoint validates tier separately.
        u = UsernameClaim(username="ab")
        assert u.username == "ab"

    def test_pydantic_rejects_reserved(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UsernameClaim(username="admin")

    def test_pydantic_rejects_bad_chars(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UsernameClaim(username="les-ya")
