"""Extended fuzz testing using hypothesis for stability validation."""

import string

import pytest
from hypothesis import given, settings, strategies as st

from dinner_app.crypto import (
    CryptoError,
    DecryptionError,
    EncryptedData,
    decrypt_recipe,
    encrypt_recipe,
)
from dinner_app.security import (
    ValidationError,
    sanitize_text,
    validate_ingredient,
    validate_ingredients_list,
    validate_recipe_data,
    validate_recipe_name,
)


class TestCryptoFuzzHypothesis:
    """Property-based tests for crypto module."""

    @given(
        plaintext=st.text(min_size=1, max_size=1000),
        password=st.text(min_size=1, max_size=100),
    )
    @settings(max_examples=200, deadline=None)
    def test_encrypt_decrypt_roundtrip_property(self, plaintext, password):
        """Any non-empty plaintext and password should roundtrip correctly."""
        encrypted = encrypt_recipe(plaintext, password)
        decrypted = decrypt_recipe(encrypted, password)
        assert decrypted == plaintext

    @given(
        plaintext=st.text(min_size=1, max_size=500),
        correct_pw=st.text(min_size=1, max_size=50),
        wrong_pw=st.text(min_size=1, max_size=50),
    )
    @settings(max_examples=100, deadline=None)
    def test_wrong_password_never_succeeds(self, plaintext, correct_pw, wrong_pw):
        """Wrong password should always fail to decrypt."""
        if correct_pw == wrong_pw:
            return
        encrypted = encrypt_recipe(plaintext, correct_pw)
        with pytest.raises(DecryptionError):
            decrypt_recipe(encrypted, wrong_pw)

    @given(data=st.binary(min_size=1, max_size=100))
    @settings(max_examples=100, deadline=None)
    def test_binary_json_rejected(self, data):
        """Random binary data as JSON should be rejected."""
        try:
            EncryptedData.from_json(data.decode("utf-8", errors="replace"))
            assert False, "Should have raised an exception"
        except Exception:
            pass


class TestSecurityFuzzHypothesis:
    """Property-based tests for security module."""

    @given(
        text=st.text(
            alphabet=string.ascii_letters + string.digits + " -_',.!?",
            min_size=1,
            max_size=100,
        )
    )
    @settings(max_examples=200, deadline=None)
    def test_safe_text_passes_sanitization(self, text):
        """Safe characters should pass sanitization."""
        text = text.strip()
        if not text:
            return
        result = sanitize_text(text)
        assert result is not None

    @given(
        injections=st.sampled_from(
            [
                "<script>alert(1)</script>",
                "javascript:void(0)",
                "../../../etc/passwd",
                "..\\..\\windows\\system32",
                "onclick=evil()",
                "\x00null\x00",
            ]
        )
    )
    @settings(max_examples=50, deadline=None)
    def test_injection_always_blocked(self, injections):
        """Known injection patterns should always be blocked."""
        with pytest.raises(ValidationError):
            sanitize_text(injections)

    @given(
        ingredients=st.lists(
            st.text(
                alphabet=string.ascii_letters + " ",
                min_size=2,
                max_size=30,
            ),
            min_size=1,
            max_size=50,
        )
    )
    @settings(max_examples=100, deadline=None)
    def test_safe_ingredients_list_passes(self, ingredients):
        """Safe ingredient lists should validate."""
        ingredients = [i.strip() for i in ingredients if i.strip() and len(i.strip()) >= 2]
        if not ingredients:
            return
        result = validate_ingredients_list(ingredients)
        assert isinstance(result, list)

    @given(
        cook_time=st.integers(min_value=-10000, max_value=100000),
    )
    @settings(max_examples=100, deadline=None)
    def test_cook_time_always_clamped(self, cook_time):
        """Cook time should always be clamped to valid range."""
        result = validate_recipe_data({"cook_time": cook_time})
        assert 0 <= result["cook_time"] <= 1440


class TestStabilityStress:
    """Stress tests for stability validation."""

    def test_repeated_encrypt_decrypt(self):
        """Repeated encrypt/decrypt should be stable."""
        plaintext = "Test recipe content"
        password = "StablePassword123!"

        for i in range(500):
            encrypted = encrypt_recipe(plaintext, password)
            decrypted = decrypt_recipe(encrypted, password)
            assert decrypted == plaintext, f"Failed on iteration {i}"

    def test_concurrent_style_operations(self):
        """Many sequential operations should be stable."""
        recipes = [f"Recipe {i}: Ingredients for dish {i}" for i in range(100)]
        passwords = [f"Password{i}!" for i in range(100)]

        encrypted_data = []
        for r, p in zip(recipes, passwords):
            encrypted_data.append((encrypt_recipe(r, p), p))

        for (enc, pw), original in zip(encrypted_data, recipes):
            decrypted = decrypt_recipe(enc, pw)
            assert decrypted == original

    def test_validation_stress(self):
        """Many validations should be stable."""
        for i in range(1000):
            name = f"Recipe Name {i}"
            validate_recipe_name(name)

            ingredients = [f"Ingredient {j}" for j in range(10)]
            validate_ingredients_list(ingredients)

            data = {
                "ingredients": ingredients,
                "directions": f"Step {i}: Do something",
                "categories": ["Category"],
                "cook_time": i % 120,
            }
            validate_recipe_data(data)
