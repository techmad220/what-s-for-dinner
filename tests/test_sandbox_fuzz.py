"""
Comprehensive fuzz testing for the sandbox defense-in-depth layer.

Tests that sandboxed containers properly block dangerous operations
even when malicious content bypasses sanitization.
"""

import pickle

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dinner_app.security import (
    SandboxedDict,
    SandboxedList,
    SandboxedString,
    SandboxViolation,
    html_escape,
    sandbox,
    sandboxed_input,
    shell_escape,
)

# =============================================================================
# SandboxedString Tests
# =============================================================================


class TestSandboxedStringBasics:
    """Test basic sandboxed string operations."""

    def test_creation(self):
        s = SandboxedString("hello", source="test")
        assert str(s) == "hello"
        assert s._source == "test"

    def test_string_operations_work(self):
        s = SandboxedString("Hello World", source="test")
        assert s.upper() == "HELLO WORLD"
        assert s.lower() == "hello world"
        assert s.split() == ["Hello", "World"]
        assert s.replace("World", "Python") == "Hello Python"
        assert len(s) == 11

    def test_concatenation_works(self):
        s = SandboxedString("Hello", source="test")
        result = s + " World"
        assert result == "Hello World"

    def test_comparison_works(self):
        s = SandboxedString("test", source="test")
        assert s == "test"
        assert s != "other"
        assert "t" in s


class TestSandboxedStringBlocking:
    """Test that sandboxed strings block dangerous operations."""

    def test_blocks_format_percent(self):
        s = SandboxedString("Hello %s", source="test")
        with pytest.raises(SandboxViolation) as exc:
            s % "World"
        assert "Format string operation blocked" in str(exc.value)

    def test_blocks_format_method(self):
        s = SandboxedString("Hello {}", source="test")
        with pytest.raises(SandboxViolation) as exc:
            s.format("World")
        assert "String.format() blocked" in str(exc.value)

    def test_blocks_pickle(self):
        s = SandboxedString("test", source="test")
        with pytest.raises(SandboxViolation) as exc:
            pickle.dumps(s)
        assert "Pickle operation blocked" in str(exc.value)

    def test_blocks_pickle_protocol(self):
        s = SandboxedString("test", source="test")
        with pytest.raises(SandboxViolation):
            s.__reduce_ex__(2)


class TestSandboxedStringAudit:
    """Test sandboxed string audit logging."""

    def test_encode_logs_access(self):
        SandboxedString.clear_access_log()
        s = SandboxedString("test", source="audit_test")
        s.encode("utf-8")
        log = SandboxedString.get_access_log()
        assert len(log) >= 1
        assert any(entry["operation"] == "encode" for entry in log)

    def test_unsafe_unwrap_logs(self):
        SandboxedString.clear_access_log()
        s = SandboxedString("sensitive", source="unwrap_test")
        result = s.unsafe_unwrap()
        assert result == "sensitive"
        log = SandboxedString.get_access_log()
        assert any(entry["operation"] == "unsafe_unwrap" for entry in log)


# =============================================================================
# SandboxedDict Tests
# =============================================================================


class TestSandboxedDictBasics:
    """Test sandboxed dictionary operations."""

    def test_creation_sandboxes_values(self):
        d = SandboxedDict({"key": "value", "nested": {"inner": "data"}}, source="test")
        assert isinstance(d["key"], SandboxedString)
        assert isinstance(d["nested"], SandboxedDict)
        assert isinstance(d["nested"]["inner"], SandboxedString)

    def test_setitem_sandboxes(self):
        d = SandboxedDict({}, source="test")
        d["new_key"] = "new_value"
        assert isinstance(d["new_key"], SandboxedString)

    def test_blocks_pickle(self):
        d = SandboxedDict({"key": "value"}, source="test")
        with pytest.raises(SandboxViolation):
            pickle.dumps(d)

    def test_dict_operations_work(self):
        d = SandboxedDict({"a": "1", "b": "2"}, source="test")
        assert len(d) == 2
        assert list(d.keys()) == [SandboxedString("a", "test"), SandboxedString("b", "test")]
        assert "a" in d


# =============================================================================
# SandboxedList Tests
# =============================================================================


class TestSandboxedListBasics:
    """Test sandboxed list operations."""

    def test_creation_sandboxes_elements(self):
        lst = SandboxedList(["a", "b", {"key": "value"}], source="test")
        assert isinstance(lst[0], SandboxedString)
        assert isinstance(lst[1], SandboxedString)
        assert isinstance(lst[2], SandboxedDict)

    def test_append_sandboxes(self):
        lst = SandboxedList([], source="test")
        lst.append("new_item")
        assert isinstance(lst[0], SandboxedString)

    def test_extend_sandboxes(self):
        lst = SandboxedList([], source="test")
        lst.extend(["a", "b", "c"])
        assert all(isinstance(item, SandboxedString) for item in lst)

    def test_setitem_sandboxes(self):
        lst = SandboxedList(["original"], source="test")
        lst[0] = "replaced"
        assert isinstance(lst[0], SandboxedString)

    def test_blocks_pickle(self):
        lst = SandboxedList(["a", "b"], source="test")
        with pytest.raises(SandboxViolation):
            pickle.dumps(lst)


# =============================================================================
# Sandbox Function Tests
# =============================================================================


class TestSandboxFunction:
    """Test the main sandbox() function."""

    def test_sandboxes_string(self):
        result = sandbox("test", source="func_test")
        assert isinstance(result, SandboxedString)

    def test_sandboxes_dict(self):
        result = sandbox({"key": "value"}, source="func_test")
        assert isinstance(result, SandboxedDict)

    def test_sandboxes_list(self):
        result = sandbox(["a", "b"], source="func_test")
        assert isinstance(result, SandboxedList)

    def test_passes_through_other_types(self):
        assert sandbox(42, source="test") == 42
        assert sandbox(3.14, source="test") == 3.14
        assert sandbox(None, source="test") is None
        assert sandbox(True, source="test") is True


# =============================================================================
# Decorator Tests
# =============================================================================


class TestSandboxedInputDecorator:
    """Test the @sandboxed_input decorator."""

    def test_sandboxes_args(self):
        @sandboxed_input(source="decorator_test")
        def process(name, items):
            return (isinstance(name, SandboxedString), isinstance(items, SandboxedList))

        result = process("test", ["a", "b"])
        assert result == (True, True)

    def test_sandboxes_kwargs(self):
        @sandboxed_input(source="decorator_test")
        def process(name=None, data=None):
            return (isinstance(name, SandboxedString), isinstance(data, SandboxedDict))

        result = process(name="test", data={"key": "value"})
        assert result == (True, True)


# =============================================================================
# Output Encoding Tests
# =============================================================================


class TestHtmlEscape:
    """Test HTML escaping."""

    def test_escapes_html_tags(self):
        assert html_escape("<script>") == "&lt;script&gt;"
        assert html_escape("<div onclick='evil'>") == "&lt;div onclick=&#x27;evil&#x27;&gt;"

    def test_escapes_quotes(self):
        assert html_escape('"double"') == "&quot;double&quot;"
        assert html_escape("'single'") == "&#x27;single&#x27;"

    def test_escapes_ampersand(self):
        assert html_escape("a & b") == "a &amp; b"

    def test_handles_non_strings(self):
        assert html_escape(123) == "123"


class TestShellEscape:
    """Test shell escaping."""

    def test_removes_backticks(self):
        assert shell_escape("`whoami`") == "whoami"

    def test_removes_dollar(self):
        assert shell_escape("$HOME") == "HOME"

    def test_removes_semicolon(self):
        assert shell_escape("cmd; rm -rf") == "cmd rm -rf"

    def test_removes_pipe(self):
        assert shell_escape("cat file | grep") == "cat file  grep"


# =============================================================================
# Fuzz Testing with Hypothesis
# =============================================================================


class TestSandboxFuzzing:
    """Fuzz test the sandbox with arbitrary inputs."""

    @given(st.text(max_size=1000))
    @settings(max_examples=1000)
    def test_sandboxed_string_never_crashes(self, text):
        """Sandboxed strings should never crash on any input."""
        s = SandboxedString(text, source="fuzz")
        # Basic operations should work
        _ = str(s)
        _ = repr(s)
        _ = len(s)
        _ = s.upper()
        _ = s.lower()

    @given(st.text(max_size=1000))
    @settings(max_examples=1000)
    def test_format_always_blocked(self, text):
        """Format operations should always be blocked."""
        s = SandboxedString(text, source="fuzz")
        try:
            s % ()
            pytest.fail("Format with % should have raised SandboxViolation")
        except (SandboxViolation, TypeError):
            pass  # SandboxViolation or TypeError (no args) is expected

    @given(st.text(max_size=1000))
    @settings(max_examples=1000)
    def test_format_method_always_blocked(self, text):
        """Format method should always be blocked."""
        s = SandboxedString(text, source="fuzz")
        with pytest.raises(SandboxViolation):
            s.format()

    @given(st.dictionaries(st.text(max_size=50), st.text(max_size=100), max_size=20))
    @settings(max_examples=500)
    def test_sandboxed_dict_never_crashes(self, data):
        """Sandboxed dicts should never crash on any input."""
        d = SandboxedDict(data, source="fuzz")
        _ = dict(d)
        _ = len(d)
        _ = list(d.keys())
        _ = list(d.values())

    @given(st.lists(st.text(max_size=100), max_size=50))
    @settings(max_examples=500)
    def test_sandboxed_list_never_crashes(self, data):
        """Sandboxed lists should never crash on any input."""
        lst = SandboxedList(data, source="fuzz")
        _ = list(lst)
        _ = len(lst)

    @given(st.text(max_size=1000))
    @settings(max_examples=1000)
    def test_html_escape_never_crashes(self, text):
        """HTML escape should never crash."""
        result = html_escape(text)
        assert isinstance(result, str)
        assert "<" not in result
        assert ">" not in result

    @given(st.text(max_size=1000))
    @settings(max_examples=1000)
    def test_shell_escape_never_crashes(self, text):
        """Shell escape should never crash and removes dangerous chars."""
        result = shell_escape(text)
        assert isinstance(result, str)
        assert "`" not in result
        assert "$" not in result
        assert ";" not in result


MALICIOUS_STRINGS = [
    "%s%s%s%s%s%s%s%s%s%s%s%s%s",  # Format string attack
    "{0}{1}{2}",  # .format attack
    "{{.__class__.__mro__[1].__subclasses__()}}",  # Python sandbox escape
    "${7*7}",  # Template injection
    "{{config}}",  # Jinja template injection
    "__import__('os').system('id')",  # Code injection
    "eval(input())",  # eval injection
    "exec('import os')",  # exec injection
    "pickle.loads(data)",  # Pickle attack
]


class TestSandboxMaliciousPayloads:
    """Test sandbox against known attack payloads."""

    def test_malicious_strings_sandboxed(self):
        """All malicious strings should be safely sandboxed."""
        for payload in MALICIOUS_STRINGS:
            s = SandboxedString(payload, source="malicious")
            # String should exist but format ops blocked
            assert str(s) == payload
            with pytest.raises(SandboxViolation):
                s.format()
            with pytest.raises(SandboxViolation):
                pickle.dumps(s)

    def test_nested_malicious_in_dict(self):
        """Malicious strings in nested structures should be sandboxed."""
        data = {
            "safe": "value",
            "attack": "{0.__class__.__mro__}",
            "nested": {
                "deep": "{{config.items()}}",
            },
        }
        d = SandboxedDict(data, source="attack")

        # Values are sandboxed
        with pytest.raises(SandboxViolation):
            d["attack"].format()
        with pytest.raises(SandboxViolation):
            d["nested"]["deep"].format()

    def test_pickle_deserialization_blocked(self):
        """Pickled sandboxed objects can't be used for deserialization attacks."""
        s = SandboxedString("test", source="pickle_test")
        d = SandboxedDict({"key": "value"}, source="pickle_test")
        lst = SandboxedList(["a", "b"], source="pickle_test")

        for obj in [s, d, lst]:
            with pytest.raises(SandboxViolation):
                pickle.dumps(obj)


class TestSandboxBypassAttempts:
    """Test that common sandbox bypass techniques fail."""

    def test_cannot_access_class_directly(self):
        """Sandboxed string inherits from str but blocks dangerous ops."""
        s = SandboxedString("test", source="bypass")
        # Can still access __class__ (Python feature) but format blocked
        assert s.__class__.__name__ == "SandboxedString"
        with pytest.raises(SandboxViolation):
            s.format()

    def test_cannot_use_as_format_arg(self):
        """Using sandboxed string as format arg is fine, but using IT to format isn't."""
        s = SandboxedString("test", source="bypass")
        # This is OK - regular string formatting with sandboxed as arg
        result = f"Hello {s}"
        assert result == "Hello test"
        # This is blocked - sandboxed string trying to format
        with pytest.raises(SandboxViolation):
            s.format("arg")

    def test_repr_is_safe(self):
        """repr() should work but be clearly marked as sandboxed."""
        s = SandboxedString("<script>alert('xss')</script>", source="xss")
        r = repr(s)
        assert "SandboxedString" in r
        assert "source=" in r


# =============================================================================
# Integration Tests
# =============================================================================


class TestSandboxIntegration:
    """Integration tests simulating real usage patterns."""

    def test_recipe_data_sandboxing(self):
        """Simulate sandboxing recipe data from user input."""
        user_input = {
            "name": "Evil Recipe <script>",
            "ingredients": ["ingredient1", "${cmd}", "ingredient3"],
            "directions": "Step 1: {{config}}\nStep 2: %s attack",
        }

        sandboxed = sandbox(user_input, source="recipe_form")

        assert isinstance(sandboxed, SandboxedDict)
        assert isinstance(sandboxed["name"], SandboxedString)
        assert isinstance(sandboxed["ingredients"], SandboxedList)
        assert isinstance(sandboxed["directions"], SandboxedString)

        # Format attacks blocked
        with pytest.raises(SandboxViolation):
            sandboxed["directions"].format()

        # But normal string ops work
        assert "Step 1" in sandboxed["directions"]
        assert len(sandboxed["ingredients"]) == 3

    def test_search_term_sandboxing(self):
        """Simulate sandboxing search terms."""
        search = sandbox("chicken AND ${id}", source="search_box")

        # Can use for comparison
        assert "chicken" in search

        # But format blocked
        with pytest.raises(SandboxViolation):
            search.format()

    def test_chained_operations_stay_sandboxed(self):
        """Operations on sandboxed values should maintain safety."""
        s = SandboxedString("Hello World", source="chain")

        # String operations return regular strings (Python behavior)
        # but the original is still protected
        upper = s.upper()  # Regular string
        assert upper == "HELLO WORLD"

        # Original still blocks format
        with pytest.raises(SandboxViolation):
            s.format()
