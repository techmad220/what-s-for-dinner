"""
Comprehensive tests for crypto module.

Tests encryption/decryption, error handling, and fuzzes with random inputs.
"""

import json
import secrets
import string

import pytest

from dinner_app.crypto import (
    CRYPTO_VERSION,
    CryptoError,
    DecryptionError,
    EncryptedData,
    IntegrityError,
    decrypt_recipe,
    encrypt_recipe,
    validate_password_strength,
    verify_password,
)


class TestBasicEncryption:
    """Test basic encrypt/decrypt functionality."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt should return original."""
        plaintext = "Grandma's Secret Cookie Recipe: 2 cups love, 1 cup patience"
        password = "SecretPassword123!"

        encrypted = encrypt_recipe(plaintext, password)
        decrypted = decrypt_recipe(encrypted, password)

        assert decrypted == plaintext

    def test_encrypt_produces_different_output(self):
        """Same plaintext encrypted twice should produce different ciphertext."""
        plaintext = "Secret recipe"
        password = "password123"

        enc1 = encrypt_recipe(plaintext, password)
        enc2 = encrypt_recipe(plaintext, password)

        assert enc1.ciphertext != enc2.ciphertext
        assert enc1.salt != enc2.salt
        assert enc1.nonce != enc2.nonce

    def test_wrong_password_fails(self):
        """Decryption with wrong password should fail."""
        plaintext = "Secret recipe"
        encrypted = encrypt_recipe(plaintext, "correct_password")

        with pytest.raises(DecryptionError):
            decrypt_recipe(encrypted, "wrong_password")

    def test_tampered_ciphertext_fails(self):
        """Tampering with ciphertext should be detected."""
        plaintext = "Secret recipe"
        password = "password123"
        encrypted = encrypt_recipe(plaintext, password)

        # Tamper with ciphertext
        tampered = bytearray(encrypted.ciphertext)
        tampered[0] ^= 0xFF
        encrypted.ciphertext = bytes(tampered)

        with pytest.raises(IntegrityError):
            decrypt_recipe(encrypted, password)

    def test_tampered_tag_fails(self):
        """Tampering with auth tag should be detected."""
        plaintext = "Secret recipe"
        password = "password123"
        encrypted = encrypt_recipe(plaintext, password)

        # Tamper with tag
        tampered = bytearray(encrypted.tag)
        tampered[0] ^= 0xFF
        encrypted.tag = bytes(tampered)

        with pytest.raises(IntegrityError):
            decrypt_recipe(encrypted, password)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_plaintext_fails(self):
        """Empty plaintext should raise error."""
        with pytest.raises(CryptoError):
            encrypt_recipe("", "password")

    def test_empty_password_fails(self):
        """Empty password should raise error."""
        with pytest.raises(CryptoError):
            encrypt_recipe("plaintext", "")

    def test_unicode_plaintext(self):
        """Unicode characters should be handled correctly."""
        plaintext = "Recette de grand-mère: Crème brûlée avec des fraises"
        password = "motdepasse123"

        encrypted = encrypt_recipe(plaintext, password)
        decrypted = decrypt_recipe(encrypted, password)

        assert decrypted == plaintext

    def test_unicode_password(self):
        """Unicode passwords should work."""
        plaintext = "Secret recipe"
        password = "パスワード123"

        encrypted = encrypt_recipe(plaintext, password)
        decrypted = decrypt_recipe(encrypted, password)

        assert decrypted == plaintext

    def test_very_long_plaintext(self):
        """Long plaintext should work."""
        plaintext = "Recipe: " + "ingredient, " * 10000
        password = "password123"

        encrypted = encrypt_recipe(plaintext, password)
        decrypted = decrypt_recipe(encrypted, password)

        assert decrypted == plaintext

    def test_special_characters(self):
        """Special characters in both plaintext and password."""
        plaintext = "Recipe: <script>alert('xss')</script> & \"quotes\" 'single'"
        password = "p@$$w0rd!#$%^&*()"

        encrypted = encrypt_recipe(plaintext, password)
        decrypted = decrypt_recipe(encrypted, password)

        assert decrypted == plaintext


class TestSerialization:
    """Test JSON serialization/deserialization."""

    def test_to_json_roundtrip(self):
        """Serialize to JSON and back should preserve data."""
        plaintext = "Secret recipe"
        password = "password123"

        original = encrypt_recipe(plaintext, password)
        json_str = original.to_json()
        restored = EncryptedData.from_json(json_str)

        assert original.version == restored.version
        assert original.salt == restored.salt
        assert original.nonce == restored.nonce
        assert original.ciphertext == restored.ciphertext
        assert original.tag == restored.tag
        assert original.key_check == restored.key_check

        # Should still decrypt correctly
        decrypted = decrypt_recipe(restored, password)
        assert decrypted == plaintext

    def test_json_is_valid(self):
        """Generated JSON should be valid."""
        encrypted = encrypt_recipe("test", "password")
        json_str = encrypted.to_json()

        parsed = json.loads(json_str)
        assert "version" in parsed
        assert "salt" in parsed
        assert "nonce" in parsed
        assert "ciphertext" in parsed
        assert "tag" in parsed


class TestPasswordVerification:
    """Test password verification without decryption."""

    def test_verify_correct_password(self):
        """Correct password should verify."""
        encrypted = encrypt_recipe("secret", "correct_password")
        assert verify_password(encrypted, "correct_password") is True

    def test_verify_wrong_password(self):
        """Wrong password should not verify."""
        encrypted = encrypt_recipe("secret", "correct_password")
        assert verify_password(encrypted, "wrong_password") is False

    def test_verify_empty_password(self):
        """Empty password should not verify."""
        encrypted = encrypt_recipe("secret", "correct_password")
        assert verify_password(encrypted, "") is False


class TestPasswordStrength:
    """Test password strength validation."""

    def test_short_password(self):
        """Short passwords should fail."""
        is_valid, issues = validate_password_strength("short")
        assert is_valid is False
        assert any("8 characters" in i for i in issues)

    def test_strong_password(self):
        """Strong passwords should pass."""
        is_valid, _issues = validate_password_strength("Str0ng!Password123")
        assert is_valid is True

    def test_medium_password_suggestions(self):
        """Medium passwords should get suggestions."""
        is_valid, issues = validate_password_strength("password12")
        assert is_valid is True
        assert len(issues) > 0  # Should have suggestions


class TestFuzzing:
    """Fuzz testing with random inputs."""

    def test_fuzz_random_plaintext(self):
        """Random plaintext should encrypt/decrypt correctly."""
        password = "FuzzPassword123!"

        for _ in range(100):
            length = secrets.randbelow(1000) + 1
            plaintext = "".join(
                secrets.choice(string.printable) for _ in range(length)
            )

            encrypted = encrypt_recipe(plaintext, password)
            decrypted = decrypt_recipe(encrypted, password)
            assert decrypted == plaintext

    def test_fuzz_random_password(self):
        """Random passwords should work."""
        plaintext = "Fixed plaintext for testing"

        for _ in range(100):
            length = secrets.randbelow(50) + 8
            password = "".join(
                secrets.choice(string.printable) for _ in range(length)
            )

            encrypted = encrypt_recipe(plaintext, password)
            decrypted = decrypt_recipe(encrypted, password)
            assert decrypted == plaintext

    def test_fuzz_binary_like_content(self):
        """Binary-like content (base64) should work."""
        password = "password123"

        for _ in range(50):
            random_bytes = secrets.token_bytes(secrets.randbelow(500) + 1)
            plaintext = random_bytes.hex()

            encrypted = encrypt_recipe(plaintext, password)
            decrypted = decrypt_recipe(encrypted, password)
            assert decrypted == plaintext

    def test_fuzz_corrupted_json_rejected(self):
        """Corrupted JSON should be rejected gracefully."""
        encrypted = encrypt_recipe("test", "password")
        json_str = encrypted.to_json()

        # Various corruption attempts
        corrupted_inputs = [
            json_str[:-10],  # Truncated
            json_str + "extra",  # Extra data
            json_str.replace("salt", "pepper"),  # Wrong field
            "{invalid json",  # Invalid JSON
            "",  # Empty
            "null",  # Null
        ]

        for corrupted in corrupted_inputs:
            with pytest.raises((json.JSONDecodeError, KeyError, TypeError)):
                EncryptedData.from_json(corrupted)

    def test_fuzz_wrong_passwords_never_decrypt(self):
        """Random wrong passwords should never decrypt correctly."""
        plaintext = "Grandma's secret: love"
        correct_password = "CorrectHorse123!"
        encrypted = encrypt_recipe(plaintext, correct_password)

        for _ in range(100):
            wrong_password = "".join(
                secrets.choice(string.ascii_letters + string.digits)
                for _ in range(secrets.randbelow(20) + 1)
            )
            if wrong_password == correct_password:
                continue

            with pytest.raises(DecryptionError):
                decrypt_recipe(encrypted, wrong_password)


class TestVersioning:
    """Test version handling for future upgrades."""

    def test_current_version(self):
        """Current version should be set correctly."""
        encrypted = encrypt_recipe("test", "password")
        assert encrypted.version == CRYPTO_VERSION

    def test_wrong_version_rejected(self):
        """Wrong version should be rejected."""
        encrypted = encrypt_recipe("test", "password")
        encrypted.version = 999

        with pytest.raises(CryptoError) as exc:
            decrypt_recipe(encrypted, "password")
        assert "version" in str(exc.value).lower()
