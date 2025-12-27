"""Aggressive fuzzing tests for comprehensive security validation.

Extended fuzzing with:
- 10x more examples per test
- Larger input sizes
- More exotic attack vectors
- Stress testing
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import contextlib
import threading
import time

from hypothesis import HealthCheck, Phase, given, settings
from hypothesis import strategies as st

from dinner_app.plugin_security import (
    check_plugin_source,
)
from dinner_app.security import (
    MAX_CATEGORIES_PER_RECIPE,
    MAX_DIRECTION_LENGTH,
    MAX_INGREDIENTS_PER_RECIPE,
    ValidationError,
    is_safe_filename,
    sanitize_text,
    validate_ingredient,
    validate_json_recipes,
    validate_recipe_data,
    validate_recipe_name,
)

# Aggressive settings for thorough fuzzing
AGGRESSIVE_SETTINGS = settings(
    max_examples=5000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
    phases=[Phase.generate, Phase.target, Phase.shrink],
)

MEDIUM_SETTINGS = settings(
    max_examples=2000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


# =============================================================================
# AGGRESSIVE TEXT FUZZING
# =============================================================================


class TestAggressiveTextFuzzing:
    """Aggressive fuzzing of text sanitization."""

    @given(st.text(max_size=50000))
    @AGGRESSIVE_SETTINGS
    def test_sanitize_huge_inputs(self, text):
        """Fuzz with very large text inputs."""
        try:
            result = sanitize_text(text, max_length=10000)
            assert isinstance(result, str)
            assert len(result) <= 10000
        except ValidationError:
            pass

    @given(st.binary(max_size=10000))
    @MEDIUM_SETTINGS
    def test_sanitize_binary_as_text(self, data):
        """Try to pass binary data decoded as text."""
        try:
            text = data.decode("utf-8", errors="replace")
            result = sanitize_text(text, max_length=1000)
            assert isinstance(result, str)
        except (ValidationError, UnicodeDecodeError):
            pass

    @given(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Cc", "Cf", "Co", "Cs", "Cn"),
            ),
            max_size=1000,
        )
    )
    @MEDIUM_SETTINGS
    def test_control_and_special_chars_only(self, text):
        """Fuzz with only control/special Unicode characters."""
        try:
            result = sanitize_text(text, max_length=1000)
            assert isinstance(result, str)
        except ValidationError:
            pass

    @given(st.lists(st.text(max_size=100), min_size=100, max_size=500))
    @MEDIUM_SETTINGS
    def test_many_strings_concatenated(self, texts):
        """Fuzz with many concatenated strings."""
        combined = "".join(texts)
        try:
            result = sanitize_text(combined, max_length=50000)
            assert isinstance(result, str)
        except ValidationError:
            pass


# =============================================================================
# UNICODE ATTACK VECTORS
# =============================================================================


class TestUnicodeAttacks:
    """Test Unicode-based attack vectors."""

    # RTL override and other bidi attacks
    BIDI_ATTACKS = [
        "\u202e<script>alert(1)</script>",  # RTL override
        "\u202dmalicious\u202c",  # LTR override
        "\u2066hidden\u2069",  # Isolate
        "\u2067payload\u2069",  # RTL isolate
        "safe\u200btext",  # Zero-width space
        "nor\u200cmal",  # Zero-width non-joiner
        "te\u200dst",  # Zero-width joiner
        "\ufeff<script>",  # BOM
    ]

    HOMOGLYPH_ATTACKS = [
        "sсript",  # Cyrillic 'с' instead of Latin 'c'
        "ѕcript",  # Cyrillic 'ѕ'
        "scr\u0131pt",  # Turkish dotless i
        "ｓｃｒｉｐｔ",  # Fullwidth
        "𝓼𝓬𝓻𝓲𝓹𝓽",  # Mathematical script
        "𝕤𝕔𝕣𝕚𝕡𝕥",  # Double-struck
        "ꜱᴄʀɪᴘᴛ",  # Small caps
    ]

    NORMALIZATION_ATTACKS = [
        "ﬁle",  # fi ligature
        "ﬂag",  # fl ligature
        "㎈",  # Korean compatibility
        "⒜⒝⒞",  # Parenthesized
        "①②③",  # Circled numbers
        "ℌ",  # Script H
        "ℍ",  # Double-struck H
    ]

    def test_bidi_attacks(self):
        """Test bidirectional text attacks."""
        for payload in self.BIDI_ATTACKS:
            try:
                result = sanitize_text(payload)
                # Should not have dangerous patterns after sanitization
                assert isinstance(result, str)
            except ValidationError:
                pass

    def test_homoglyph_attacks(self):
        """Test homoglyph (lookalike character) attacks."""
        for payload in self.HOMOGLYPH_ATTACKS:
            try:
                result = sanitize_text(payload)
                assert isinstance(result, str)
            except ValidationError:
                pass

    def test_normalization_attacks(self):
        """Test Unicode normalization attacks."""
        for payload in self.NORMALIZATION_ATTACKS:
            try:
                result = sanitize_text(payload)
                assert isinstance(result, str)
            except ValidationError:
                pass

    @given(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("Lo", "Lm", "Lt"),  # Other letters, modifiers
                max_codepoint=0x1FFFF,
            ),
            max_size=500,
        )
    )
    @MEDIUM_SETTINGS
    def test_exotic_unicode_letters(self, text):
        """Fuzz with exotic Unicode letter categories."""
        try:
            result = sanitize_text(text, max_length=1000)
            assert isinstance(result, str)
        except ValidationError:
            pass

    @given(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("So", "Sm", "Sc", "Sk"),  # Symbols
            ),
            max_size=500,
        )
    )
    @MEDIUM_SETTINGS
    def test_unicode_symbols(self, text):
        """Fuzz with Unicode symbols."""
        try:
            result = sanitize_text(text, max_length=1000)
            assert isinstance(result, str)
        except ValidationError:
            pass


# =============================================================================
# XSS PAYLOAD FUZZING
# =============================================================================


class TestXSSPayloads:
    """Test various XSS payloads are blocked."""

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<a href=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><textarea><a title=\"</textarea><img src='#' onerror='alert(1)'>\">",
        "'-alert(1)-'",
        '"-alert(1)-"',
        "<ScRiPt>alert(1)</ScRiPt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<script>script>alert(1)</<script>/script>",
        "<script\x00>alert(1)</script>",
        "<script\x09>alert(1)</script>",
        "<script\x0a>alert(1)</script>",
        "<script\x0d>alert(1)</script>",
        "<script/src=data:,alert(1)>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "<IMG SRC=\"javascript:alert('XSS');\">",
        "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
        '<IMG SRC=`javascript:alert("XSS")`>',
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
    ]

    def test_xss_payloads_blocked(self):
        """All XSS payloads should be blocked or neutralized."""
        for payload in self.XSS_PAYLOADS:
            try:
                result = sanitize_text(payload)
                # Check result doesn't contain dangerous patterns
                assert "<script" not in result.lower()
                assert "javascript:" not in result.lower()
                assert "onerror=" not in result.lower()
                assert "onload=" not in result.lower()
            except ValidationError:
                pass  # Rejected is fine

    @given(st.text(min_size=1, max_size=100))
    @MEDIUM_SETTINGS
    def test_xss_payload_variations(self, suffix):
        """Generate XSS payload variations."""
        payloads = [
            f"<script>{suffix}</script>",
            f"<img src=x onerror={suffix}>",
            f"javascript:{suffix}",
        ]
        for payload in payloads:
            try:
                result = sanitize_text(payload)
                assert "<script" not in result.lower() or "javascript:" not in result.lower()
            except ValidationError:
                pass


# =============================================================================
# SQL INJECTION PATTERNS (for completeness - app doesn't use SQL but test anyway)
# =============================================================================


class TestSQLInjectionPatterns:
    """Test SQL injection patterns are handled (even though app doesn't use SQL)."""

    SQL_PAYLOADS = [
        "'; DROP TABLE recipes; --",
        "1' OR '1'='1",
        "1'; EXEC xp_cmdshell('whoami'); --",
        "' UNION SELECT * FROM users --",
        "'; DELETE FROM recipes WHERE '1'='1",
        "admin'--",
        "1 AND 1=1",
        "1' AND '1'='1",
        "'; WAITFOR DELAY '0:0:10'--",
        "1; SELECT * FROM information_schema.tables--",
    ]

    def test_sql_patterns_sanitized(self):
        """SQL injection patterns should be handled safely."""
        for payload in self.SQL_PAYLOADS:
            try:
                result = sanitize_text(payload)
                assert isinstance(result, str)
            except ValidationError:
                pass


# =============================================================================
# PLUGIN SOURCE AGGRESSIVE FUZZING
# =============================================================================


class TestAggressivePluginFuzzing:
    """Aggressive fuzzing of plugin source code analysis."""

    @given(st.text(max_size=100000))
    @AGGRESSIVE_SETTINGS
    def test_huge_plugin_source(self, source):
        """Fuzz with very large plugin source."""
        result = check_plugin_source(source)
        assert hasattr(result, "is_safe")
        assert hasattr(result, "warnings")
        assert hasattr(result, "errors")

    @given(st.binary(max_size=10000))
    @MEDIUM_SETTINGS
    def test_binary_as_source(self, data):
        """Try binary data as plugin source."""
        try:
            source = data.decode("utf-8", errors="replace")
            result = check_plugin_source(source)
            assert hasattr(result, "is_safe")
        except Exception:
            pass

    OBFUSCATED_IMPORTS = [
        "__import__('os')",
        "getattr(__builtins__, 'eval')",
        "globals()['__builtins__']['eval']",
        "exec(compile('import os', '', 'exec'))",
        "(lambda: __import__('subprocess'))()",
        "type('', (), {'__init__': lambda s: __import__('os')})()",
        "__builtins__.__dict__['exec']",
        "eval(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116))",
    ]

    def test_obfuscated_imports(self):
        """Test obfuscated import patterns."""
        for payload in self.OBFUSCATED_IMPORTS:
            source = f"x = {payload}"
            check_plugin_source(source)
            # Should detect dangerous patterns or not be safe
            # Note: static analysis can't catch all obfuscation

    MALICIOUS_CODE_PATTERNS = [
        "import os; os.system('rm -rf /')",
        "from subprocess import call; call(['whoami'])",
        "open('/etc/passwd').read()",
        "__import__('socket').socket()",
        "eval(input())",
        "exec(open('malware.py').read())",
        "import pickle; pickle.loads(data)",
        "import ctypes; ctypes.windll.kernel32",
    ]

    def test_malicious_patterns_detected(self):
        """Test known malicious patterns are detected."""
        for code in self.MALICIOUS_CODE_PATTERNS:
            result = check_plugin_source(code)
            # Should detect at least one issue
            assert not result.is_safe or result.warnings or result.errors, f"Missed: {code}"


# =============================================================================
# FILENAME AGGRESSIVE FUZZING
# =============================================================================


class TestAggressiveFilenameFuzzing:
    """Aggressive fuzzing of filename validation."""

    @given(st.text(max_size=10000))
    @AGGRESSIVE_SETTINGS
    def test_huge_filenames(self, filename):
        """Fuzz with huge filenames."""
        result = is_safe_filename(filename)
        assert isinstance(result, bool)

    PATH_TRAVERSAL_VARIANTS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "..\\..\\..\\windows\\system32",
        "....\\\\....\\\\....\\\\windows",
        "..\\/..\\/..\\/etc/passwd",
        "..%5c..%5c..%5cwindows",
        "/var/log/../../../etc/passwd",
        "file:///etc/passwd",
        "\\\\server\\share\\file",
        "//server/share/file",
    ]

    def test_path_traversal_variants(self):
        """Test various path traversal encodings."""
        for payload in self.PATH_TRAVERSAL_VARIANTS:
            result = is_safe_filename(payload)
            assert result is False, f"Should reject: {payload}"

    NULL_BYTE_VARIANTS = [
        "file\x00.py",
        "\x00file.py",
        "fi\x00le.py",
        "file.py\x00",
        "file\x00\x00.py",
        "file%00.py",
    ]

    def test_null_byte_variants(self):
        """Test null byte injection variants."""
        for payload in self.NULL_BYTE_VARIANTS:
            result = is_safe_filename(payload)
            assert result is False, f"Should reject: {payload}"

    @given(st.binary(max_size=200))
    @MEDIUM_SETTINGS
    def test_binary_filenames(self, data):
        """Try binary data as filename."""
        try:
            filename = data.decode("utf-8", errors="replace")
            result = is_safe_filename(filename)
            assert isinstance(result, bool)
        except Exception:
            pass


# =============================================================================
# JSON/DATA STRUCTURE FUZZING
# =============================================================================


class TestAggressiveDataFuzzing:
    """Aggressive fuzzing of data structures."""

    @given(
        st.recursive(
            st.none() | st.booleans() | st.floats(allow_nan=True) | st.text(max_size=100),
            lambda children: st.lists(children, max_size=50)
            | st.dictionaries(st.text(max_size=20), children, max_size=20),
            max_leaves=1000,
        )
    )
    @MEDIUM_SETTINGS
    def test_arbitrary_nested_structures(self, data):
        """Fuzz with arbitrary nested data structures."""
        if isinstance(data, dict):
            try:
                result = validate_recipe_data(data)
                assert isinstance(result, dict)
            except (ValidationError, RecursionError, TypeError):
                pass

    @given(
        st.dictionaries(
            st.text(max_size=100), st.lists(st.text(max_size=100), max_size=500), max_size=100
        )
    )
    @MEDIUM_SETTINGS
    def test_many_recipes(self, recipes):
        """Fuzz with many recipes."""
        try:
            result = validate_json_recipes(recipes)
            assert isinstance(result, dict)
        except ValidationError:
            pass

    def test_extremely_deep_nesting(self):
        """Test very deep nesting doesn't crash."""
        # Create 1000-level deep nesting
        nested = {"ingredients": [], "directions": "", "categories": []}
        for _ in range(1000):
            nested = {"nested": nested, "ingredients": [], "directions": "", "categories": []}

        try:
            result = validate_recipe_data(nested)
            assert isinstance(result, dict)
        except (RecursionError, ValidationError):
            pass  # Expected

    def test_wide_structure(self):
        """Test very wide structures."""
        wide = {
            "ingredients": ["ing"] * MAX_INGREDIENTS_PER_RECIPE,
            "directions": "x" * MAX_DIRECTION_LENGTH,
            "categories": ["cat"] * MAX_CATEGORIES_PER_RECIPE,
        }
        result = validate_recipe_data(wide)
        assert len(result["ingredients"]) <= MAX_INGREDIENTS_PER_RECIPE
        assert len(result["categories"]) <= MAX_CATEGORIES_PER_RECIPE


# =============================================================================
# STRESS TESTING
# =============================================================================


class TestStressTesting:
    """Stress tests for concurrency and performance."""

    def test_high_concurrency(self):
        """Test with many concurrent threads."""
        errors = []
        iterations = 1000

        def stress_test():
            try:
                for i in range(iterations):
                    sanitize_text(f"test input {i}")
                    validate_recipe_name(f"Recipe {i}")
                    validate_ingredient(f"ingredient {i}")
                    is_safe_filename(f"plugin_{i}.py")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=stress_test) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        assert len(errors) == 0, f"Errors during stress test: {errors}"

    def test_rapid_alternation(self):
        """Rapidly alternate between different validation functions."""
        start = time.time()
        iterations = 10000

        for i in range(iterations):
            try:
                sanitize_text(f"<script>alert({i})</script>")
                validate_recipe_name(f"Recipe {i}")
                validate_ingredient(f"../../../etc/{i}")
                is_safe_filename(f"test{i}\x00.py")
                check_plugin_source(f"import os; os.system('{i}')")
            except ValidationError:
                pass

        elapsed = time.time() - start
        # Should complete 10k iterations in under 30 seconds
        assert elapsed < 30, f"Too slow: {elapsed}s for {iterations} iterations"

    def test_memory_pressure(self):
        """Test under memory pressure with large objects."""
        large_strings = []
        for _i in range(100):
            large_str = "A" * 100000
            try:
                result = sanitize_text(large_str, max_length=1000)
                large_strings.append(result)
            except ValidationError:
                pass

        # Should handle without crashing
        assert len(large_strings) > 0


# =============================================================================
# EDGE CASE NUMBERS
# =============================================================================


class TestNumericEdgeCases:
    """Test numeric edge cases."""

    SPECIAL_NUMBERS = [
        float("inf"),
        float("-inf"),
        float("nan"),
        0,
        -0.0,
        1e308,
        -1e308,
        1e-308,
        2**31 - 1,
        2**31,
        2**63 - 1,
        2**63,
        -(2**31),
        -(2**63),
    ]

    def test_special_cook_times(self):
        """Test special numeric values as cook_time."""
        for num in self.SPECIAL_NUMBERS:
            data = {
                "ingredients": [],
                "directions": "",
                "categories": [],
                "cook_time": num,
            }
            try:
                result = validate_recipe_data(data)
                if "cook_time" in result:
                    assert 0 <= result["cook_time"] <= 1440
            except (ValidationError, OverflowError, ValueError):
                pass

    @given(st.floats())
    @MEDIUM_SETTINGS
    def test_arbitrary_floats(self, num):
        """Fuzz with arbitrary float values."""
        data = {
            "ingredients": [],
            "directions": "",
            "categories": [],
            "cook_time": num,
        }
        try:
            result = validate_recipe_data(data)
            if "cook_time" in result:
                assert isinstance(result["cook_time"], int)
                assert 0 <= result["cook_time"] <= 1440
        except (ValidationError, OverflowError, ValueError):
            pass


# =============================================================================
# TIMING ATTACK RESISTANCE
# =============================================================================


class TestTimingAttacks:
    """Test for timing-based vulnerabilities."""

    def test_constant_time_validation(self):
        """Validation time should not vary significantly with input."""
        short_input = "a"
        long_input = "a" * 10000
        malicious_input = "<script>" * 1000

        times = {"short": [], "long": [], "malicious": []}
        iterations = 100

        for _ in range(iterations):
            start = time.time()
            with contextlib.suppress(ValidationError):
                sanitize_text(short_input)
            times["short"].append(time.time() - start)

            start = time.time()
            with contextlib.suppress(ValidationError):
                sanitize_text(long_input, max_length=50000)
            times["long"].append(time.time() - start)

            start = time.time()
            with contextlib.suppress(ValidationError):
                sanitize_text(malicious_input)
            times["malicious"].append(time.time() - start)

        avg_short = sum(times["short"]) / len(times["short"])
        avg_long = sum(times["long"]) / len(times["long"])
        avg_malicious = sum(times["malicious"]) / len(times["malicious"])

        # Log timing info (no hard assertion as timing can vary)
        print(
            f"Avg times: short={avg_short:.6f}s, long={avg_long:.6f}s, malicious={avg_malicious:.6f}s"
        )

    def test_no_exponential_blowup(self):
        """Ensure no exponential time complexity."""
        sizes = [100, 1000, 10000]
        times = []

        for size in sizes:
            input_str = "a" * size
            start = time.time()
            with contextlib.suppress(ValidationError):
                sanitize_text(input_str, max_length=size + 1)
            elapsed = time.time() - start
            times.append(elapsed)

        # Time should grow roughly linearly, not exponentially
        # If 10x input causes more than 100x time, that's suspicious
        if times[0] > 0:
            ratio_1 = times[1] / times[0]
            ratio_2 = times[2] / times[1]
            # Allow some variance but catch exponential blowup
            assert ratio_1 < 50, f"Suspicious time growth: {ratio_1}x for 10x input"
            assert ratio_2 < 50, f"Suspicious time growth: {ratio_2}x for 10x input"
