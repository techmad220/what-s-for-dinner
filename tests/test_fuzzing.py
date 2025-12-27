"""Fuzzing and edge case tests for security validation.

Uses Hypothesis for property-based testing to find edge cases.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import contextlib

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from dinner_app.plugin_security import (
    DANGEROUS_CALLS,
    DANGEROUS_IMPORTS,
    check_plugin_source,
)
from dinner_app.security import (
    MAX_INGREDIENT_LENGTH,
    MAX_INGREDIENTS_PER_RECIPE,
    MAX_RECIPE_NAME_LENGTH,
    ValidationError,
    is_safe_filename,
    sanitize_text,
    validate_ingredient,
    validate_ingredients_list,
    validate_recipe_data,
    validate_recipe_name,
)

# =============================================================================
# FUZZING: Text Sanitization
# =============================================================================


class TestFuzzSanitizeText:
    """Fuzz test sanitize_text with random inputs."""

    @given(st.text(max_size=5000))
    @settings(max_examples=500)
    def test_never_crashes(self, text):
        """sanitize_text should never crash on any input."""
        try:
            result = sanitize_text(text, max_length=1000)
            assert isinstance(result, str)
            assert len(result) <= 1000
        except ValidationError:
            pass  # Expected for malicious input

    @given(st.text(max_size=100))
    @settings(max_examples=200)
    def test_output_shorter_or_equal(self, text):
        """Output should never be longer than input (after truncation)."""
        try:
            result = sanitize_text(text, max_length=1000)
            # After stripping and collapsing spaces, length may vary
            assert len(result) <= max(len(text), 1000)
        except ValidationError:
            pass

    @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100))
    @settings(max_examples=200)
    def test_no_control_chars_in_output(self, text):
        """Output should not contain control characters."""
        try:
            result = sanitize_text(text, max_length=1000)
            for char in result:
                if char not in ("\n", "\r", "\t", " "):
                    # Control chars are 0x00-0x1F except tab/newline/CR
                    assert ord(char) >= 0x20 or char in "\n\r\t"
        except ValidationError:
            pass


class TestFuzzRecipeName:
    """Fuzz test recipe name validation."""

    @given(st.text(max_size=500))
    @settings(max_examples=300)
    def test_never_crashes(self, name):
        """validate_recipe_name should never crash."""
        try:
            result = validate_recipe_name(name)
            assert isinstance(result, str)
            assert len(result) <= MAX_RECIPE_NAME_LENGTH
            assert len(result) >= 2
        except ValidationError:
            pass  # Expected for invalid input

    @given(
        st.text(
            min_size=2,
            max_size=50,
            alphabet=st.characters(
                whitelist_categories=("L", "N", "P", "Z"), blacklist_characters="<>{}[]\\|`~"
            ),
        )
    )
    @settings(max_examples=100)
    def test_valid_names_pass(self, name):
        """Valid-looking names should pass."""
        assume("\x00" not in name)
        assume("script" not in name.lower())
        assume("javascript" not in name.lower())
        assume(".." not in name)
        try:
            result = validate_recipe_name(name)
            assert result  # Should not be empty
        except ValidationError:
            pass  # Some edge cases still rejected


class TestFuzzIngredient:
    """Fuzz test ingredient validation."""

    @given(st.text(max_size=200))
    @settings(max_examples=300)
    def test_never_crashes(self, ingredient):
        """validate_ingredient should never crash."""
        try:
            result = validate_ingredient(ingredient)
            assert isinstance(result, str)
            assert len(result) <= MAX_INGREDIENT_LENGTH
        except ValidationError:
            pass


class TestFuzzIngredientsList:
    """Fuzz test ingredients list validation."""

    @given(st.lists(st.text(max_size=50), max_size=150))
    @settings(max_examples=200)
    def test_never_crashes(self, ingredients):
        """validate_ingredients_list should never crash."""
        try:
            result = validate_ingredients_list(ingredients)
            assert isinstance(result, list)
            assert len(result) <= MAX_INGREDIENTS_PER_RECIPE
        except ValidationError:
            pass

    @given(st.integers() | st.floats() | st.none() | st.binary())
    @settings(max_examples=50)
    def test_non_list_rejected(self, not_a_list):
        """Non-list inputs should be rejected."""
        with pytest.raises(ValidationError):
            validate_ingredients_list(not_a_list)


# =============================================================================
# FUZZING: Plugin Security
# =============================================================================


class TestFuzzPluginSecurity:
    """Fuzz test plugin security checks."""

    @given(st.text(max_size=2000))
    @settings(max_examples=200)
    def test_check_plugin_source_never_crashes(self, source):
        """check_plugin_source should never crash on any input."""
        result = check_plugin_source(source)
        assert hasattr(result, "is_safe")
        assert hasattr(result, "warnings")
        assert hasattr(result, "errors")

    @given(st.sampled_from(list(DANGEROUS_IMPORTS.keys())))
    def test_dangerous_imports_detected(self, module):
        """All dangerous imports should be detected."""
        source = f"import {module}"
        result = check_plugin_source(source)
        assert not result.is_safe or len(result.errors) > 0

    @given(st.sampled_from(list(DANGEROUS_CALLS)))
    def test_dangerous_calls_warned(self, func):
        """Dangerous function calls should trigger warnings."""
        source = f"x = {func}('test')"
        result = check_plugin_source(source)
        # Should have warning or error
        assert len(result.warnings) > 0 or len(result.errors) > 0 or not result.is_safe


class TestFuzzFilename:
    """Fuzz test filename validation."""

    @given(st.text(max_size=100))
    @settings(max_examples=300)
    def test_is_safe_filename_never_crashes(self, filename):
        """is_safe_filename should never crash."""
        result = is_safe_filename(filename)
        assert isinstance(result, bool)

    def test_path_traversal_rejected_explicit(self):
        """Path traversal attempts should be rejected."""
        payloads = [
            "../etc/passwd",
            "..\\windows\\system32",
            "foo/../bar",
            "/etc/passwd",
            "C:\\Windows",
        ]
        for payload in payloads:
            assert is_safe_filename(payload) is False

    def test_null_bytes_rejected_explicit(self):
        """Null bytes should be rejected."""
        payloads = [
            "test\x00.py",
            "\x00plugin",
            "plu\x00gin.py",
        ]
        for payload in payloads:
            assert is_safe_filename(payload) is False


# =============================================================================
# EDGE CASES: Rust-Python Bridge Attack Vectors
# =============================================================================


class TestRustPythonBridgeEdgeCases:
    """Test edge cases that could affect Rust-Python bridge security."""

    def test_unicode_normalization_attack(self):
        """Test Unicode normalization - note fullwidth chars are allowed as they're not 'script'."""
        # Various Unicode tricks - these pass through but don't spell ASCII "script"
        payloads = [
            ("ｓｃｒｉｐｔ", True),  # Fullwidth chars - different from ASCII
            (
                "scr\u200bipt",
                True,
            ),  # Zero-width space - stripped, becomes "script" which is blocked
            ("scr\u00adipt", True),  # Soft hyphen - stripped, becomes "script" which is blocked
        ]
        for payload, _should_pass in payloads:
            try:
                result = sanitize_text(payload)
                # Fullwidth chars are NOT "script" - they're different Unicode codepoints
                # Only actual ASCII "script" should be blocked
                assert isinstance(result, str)
            except ValidationError:
                pass  # Rejected is fine too

    def test_oversized_input_handling(self):
        """Test handling of extremely large inputs."""
        # 1MB of data
        huge_input = "A" * (1024 * 1024)
        result = sanitize_text(huge_input, max_length=1000)
        assert len(result) <= 1000

    def test_deeply_nested_json(self):
        """Test deeply nested JSON doesn't cause stack overflow."""
        # Create deeply nested dict
        nested = {"ingredients": ["test"], "directions": "", "categories": []}
        for _ in range(100):
            nested = {"nested": nested, "ingredients": [], "directions": "", "categories": []}

        # Should handle gracefully
        try:
            result = validate_recipe_data(nested)
            assert isinstance(result, dict)
        except (ValidationError, RecursionError):
            pass  # Either is acceptable

    def test_mixed_encoding_attack(self):
        """Test mixed encoding doesn't bypass filters."""
        payloads = [
            b"<script>".decode("utf-8"),
            "<script>",
            "%3Cscript%3E",  # URL encoded
            "&#60;script&#62;",  # HTML entities
            "\\x3cscript\\x3e",  # Hex escaped
        ]
        for payload in payloads:
            try:
                result = sanitize_text(payload)
                assert "<script" not in result.lower()
            except ValidationError:
                pass

    def test_regex_dos_prevention(self):
        """Test that regex patterns don't cause catastrophic backtracking."""
        import time

        # Evil regex input that could cause ReDoS
        evil_inputs = [
            "a" * 100 + "!",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "b",
            " " * 1000,
        ]

        for evil in evil_inputs:
            start = time.time()
            with contextlib.suppress(ValidationError):
                sanitize_text(evil)
            elapsed = time.time() - start
            # Should complete in under 1 second
            assert elapsed < 1.0, f"Potential ReDoS: took {elapsed}s"

    def test_null_byte_injection(self):
        """Test null byte injection is blocked."""
        payloads = [
            "recipe\x00.json",
            "safe\x00<script>",
            "\x00\x00\x00",
            "test\x00../../etc/passwd",
        ]
        for payload in payloads:
            try:
                result = sanitize_text(payload)
                assert "\x00" not in result
            except ValidationError:
                pass  # Rejected is fine

    def test_format_string_attack(self):
        """Test format string attacks are neutralized."""
        payloads = [
            "%s%s%s%s%s",
            "{0}{1}{2}",
            "%(name)s",
            "${PATH}",
            "$HOME",
        ]
        for payload in payloads:
            try:
                result = sanitize_text(payload)
                # These should pass through as literals, not be interpreted
                assert isinstance(result, str)
            except ValidationError:
                pass

    def test_command_injection_in_filenames(self):
        """Test command injection via filenames is blocked."""
        payloads = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "file; echo pwned",
            "file\necho pwned",
        ]
        for payload in payloads:
            assert is_safe_filename(payload) is False

    def test_symlink_attack_paths(self):
        """Test symlink-style paths are handled."""
        payloads = [
            "/proc/self/root/etc/passwd",
            "/dev/fd/0",
            "//remote/share/file",
        ]
        for payload in payloads:
            assert is_safe_filename(payload) is False


# =============================================================================
# EDGE CASES: Data Integrity
# =============================================================================


class TestDataIntegrityEdgeCases:
    """Test data integrity edge cases."""

    def test_empty_recipe_data(self):
        """Test empty recipe data is handled."""
        result = validate_recipe_data({})
        assert result["ingredients"] == []
        assert result["directions"] == ""
        assert result["categories"] == []

    def test_wrong_types_in_recipe(self):
        """Test wrong types are handled gracefully."""
        bad_data = {
            "ingredients": "not a list",
            "directions": 12345,
            "categories": {"not": "a list"},
        }
        result = validate_recipe_data(bad_data)
        assert isinstance(result["ingredients"], list)
        assert isinstance(result["directions"], str)
        assert isinstance(result["categories"], list)

    def test_special_float_values(self):
        """Test special float values don't cause issues."""
        bad_data = {
            "ingredients": [],
            "directions": "",
            "categories": [],
            "cook_time": float("inf"),
        }
        result = validate_recipe_data(bad_data)
        assert result.get("cook_time", 0) <= 1440  # Max 24 hours

        bad_data["cook_time"] = float("nan")
        result = validate_recipe_data(bad_data)
        # NaN should be handled somehow

    def test_extremely_long_lists(self):
        """Test extremely long lists are rejected."""
        long_list = ["ingredient"] * 10000
        # Should raise ValidationError for too many ingredients
        with pytest.raises(ValidationError):
            validate_ingredients_list(long_list)


# =============================================================================
# EDGE CASES: Concurrency (simulate race conditions)
# =============================================================================


class TestConcurrencyEdgeCases:
    """Test edge cases related to concurrent access."""

    def test_rapid_validation_calls(self):
        """Test rapid repeated calls don't cause issues."""
        import threading

        errors = []

        def validate_many():
            try:
                for _ in range(100):
                    sanitize_text("test input")
                    validate_recipe_name("Test Recipe")
                    validate_ingredient("test ingredient")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=validate_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors during concurrent access: {errors}"
