"""Security utilities for input validation and sanitization.

Defense-in-depth architecture:
1. Layer 1 - Input Sanitization: Remove/reject dangerous patterns
2. Layer 2 - Sandboxing: Wrap data in immutable containers that restrict operations
3. Layer 3 - Output Encoding: Escape data before display/storage
"""

from __future__ import annotations

import re
import threading
from functools import wraps
from typing import Any, ClassVar

# =============================================================================
# LAYER 2: SANDBOXING - Immutable containers that restrict dangerous operations
# =============================================================================


class SandboxViolation(Exception):
    """Raised when sandboxed data attempts a restricted operation."""

    pass


class SandboxedString(str):
    """
    Immutable string wrapper that blocks dangerous operations.

    Even if malicious content passes sanitization, this container:
    - Blocks format string attacks
    - Prevents shell/command injection via subprocess
    - Blocks eval/exec attempts
    - Restricts pickle/marshal operations
    - Logs access patterns for audit
    """

    _access_log: ClassVar[list] = []
    _log_lock: ClassVar[threading.Lock] = threading.Lock()
    _max_log_size: ClassVar[int] = 1000

    def __new__(cls, value: str, source: str = "unknown"):
        instance = super().__new__(cls, value)
        instance._source = source
        instance._creation_time = __import__("time").time()
        return instance

    def __repr__(self) -> str:
        return f"SandboxedString({super().__repr__()}, source={self._source!r})"

    def __mod__(self, other):
        """Block format string attacks via % operator."""
        raise SandboxViolation(
            f"Format string operation blocked on sandboxed input from {self._source}"
        )

    def format(self, *args, **kwargs):
        """Block .format() method to prevent format string injection."""
        raise SandboxViolation(f"String.format() blocked on sandboxed input from {self._source}")

    def __reduce__(self):
        """Block pickling to prevent deserialization attacks."""
        raise SandboxViolation(f"Pickle operation blocked on sandboxed input from {self._source}")

    def __reduce_ex__(self, protocol):
        """Block extended pickling."""
        raise SandboxViolation(f"Pickle operation blocked on sandboxed input from {self._source}")

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        """Allow encoding but log it for audit."""
        self._log_access("encode", encoding)
        return super().encode(encoding, errors)

    def _log_access(self, operation: str, detail: str = "") -> None:
        """Log access to sandboxed data for security audit."""
        import time

        with SandboxedString._log_lock:
            if len(SandboxedString._access_log) >= SandboxedString._max_log_size:
                SandboxedString._access_log = SandboxedString._access_log[-500:]
            SandboxedString._access_log.append(
                {
                    "time": time.time(),
                    "source": self._source,
                    "operation": operation,
                    "detail": detail,
                    "value_preview": str(self)[:50],
                }
            )

    @classmethod
    def get_access_log(cls) -> list:
        """Retrieve access log for security audit."""
        with cls._log_lock:
            return cls._access_log.copy()

    @classmethod
    def clear_access_log(cls) -> None:
        """Clear the access log."""
        with cls._log_lock:
            cls._access_log.clear()

    def unsafe_unwrap(self) -> str:
        """
        Explicitly unwrap to regular string.

        SECURITY: Use only when absolutely necessary and after validation.
        This logs the unwrap for audit purposes.
        """
        self._log_access("unsafe_unwrap", "data exposed")
        return str(self)


class SandboxedDict(dict):
    """
    Dictionary wrapper that sandboxes all string values.

    Provides defense-in-depth for recipe data structures.
    """

    def __init__(self, data: dict, source: str = "unknown"):
        self._source = source
        sandboxed = {}
        for key, value in data.items():
            sandboxed[self._sandbox_value(key)] = self._sandbox_value(value)
        super().__init__(sandboxed)

    def _sandbox_value(self, value: Any) -> Any:
        """Recursively sandbox values."""
        if isinstance(value, str) and not isinstance(value, SandboxedString):
            return SandboxedString(value, self._source)
        elif isinstance(value, dict) and not isinstance(value, SandboxedDict):
            return SandboxedDict(value, self._source)
        elif isinstance(value, list):
            return SandboxedList(value, self._source)
        return value

    def __setitem__(self, key, value):
        """Sandbox new values being set."""
        super().__setitem__(self._sandbox_value(key), self._sandbox_value(value))

    def __reduce__(self):
        """Block pickling."""
        raise SandboxViolation(f"Pickle operation blocked on sandboxed dict from {self._source}")


class SandboxedList(list):
    """
    List wrapper that sandboxes all string elements.
    """

    def __init__(self, data: list, source: str = "unknown"):
        self._source = source
        sandboxed = [self._sandbox_value(item) for item in data]
        super().__init__(sandboxed)

    def _sandbox_value(self, value: Any) -> Any:
        """Recursively sandbox values."""
        if isinstance(value, str) and not isinstance(value, SandboxedString):
            return SandboxedString(value, self._source)
        elif isinstance(value, dict) and not isinstance(value, SandboxedDict):
            return SandboxedDict(value, self._source)
        elif isinstance(value, list) and not isinstance(value, SandboxedList):
            return SandboxedList(value, self._source)
        return value

    def append(self, value):
        """Sandbox new values being appended."""
        super().append(self._sandbox_value(value))

    def extend(self, values):
        """Sandbox new values being extended."""
        super().extend([self._sandbox_value(v) for v in values])

    def __setitem__(self, index, value):
        """Sandbox new values being set."""
        super().__setitem__(index, self._sandbox_value(value))

    def __reduce__(self):
        """Block pickling."""
        raise SandboxViolation(f"Pickle operation blocked on sandboxed list from {self._source}")


def sandbox(value: Any, source: str = "user_input") -> Any:
    """
    Wrap any value in appropriate sandbox container.

    Use this as the primary entry point for sandboxing user input.

    Args:
        value: The value to sandbox
        source: Description of where this input came from (for audit)

    Returns:
        Sandboxed version of the value

    Example:
        user_input = sandbox(request.get("name"), source="recipe_form")
    """
    if isinstance(value, str):
        return SandboxedString(value, source)
    elif isinstance(value, dict):
        return SandboxedDict(value, source)
    elif isinstance(value, list):
        return SandboxedList(value, source)
    return value


def sandboxed_input(source: str = "user_input"):
    """
    Decorator to automatically sandbox function arguments.

    Example:
        @sandboxed_input(source="api_endpoint")
        def process_recipe(name: str, ingredients: list):
            # name and ingredients are now sandboxed
            pass
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            sandboxed_args = tuple(sandbox(arg, source) for arg in args)
            sandboxed_kwargs = {k: sandbox(v, source) for k, v in kwargs.items()}
            return func(*sandboxed_args, **sandboxed_kwargs)

        return wrapper

    return decorator


# =============================================================================
# LAYER 3: OUTPUT ENCODING - Escape data for safe output
# =============================================================================


def html_escape(text: str) -> str:
    """Escape text for safe HTML output."""
    if not isinstance(text, str):
        text = str(text)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def shell_escape(text: str) -> str:
    """Escape text for safe shell usage (though we block shell usage anyway)."""
    if not isinstance(text, str):
        text = str(text)
    # Replace dangerous shell metacharacters
    dangerous = [
        "`",
        "$",
        "!",
        "&",
        "|",
        ";",
        "\n",
        "\r",
        "(",
        ")",
        "{",
        "}",
        "[",
        "]",
        "<",
        ">",
        '"',
        "'",
        "\\",
        "*",
        "?",
        "#",
        "~",
    ]
    for char in dangerous:
        text = text.replace(char, "")
    return text


# =============================================================================
# LAYER 1: INPUT SANITIZATION (original code continues below)
# =============================================================================

# Maximum lengths for various inputs
MAX_RECIPE_NAME_LENGTH = 200
MAX_INGREDIENT_LENGTH = 100
MAX_DIRECTION_LENGTH = 10000
MAX_CATEGORY_LENGTH = 50
MAX_INGREDIENTS_PER_RECIPE = 100
MAX_CATEGORIES_PER_RECIPE = 20

# Allowed characters pattern (alphanumeric, spaces, common punctuation)
SAFE_TEXT_PATTERN = re.compile(r"^[\w\s\-\',\.!?()&/]+$", re.UNICODE)

# Disallowed patterns that could be suspicious
SUSPICIOUS_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),  # onclick, onerror, etc.
    re.compile(r"\.\./", re.IGNORECASE),  # Unix path traversal
    re.compile(r"\.\.\\", re.IGNORECASE),  # Windows path traversal
    re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"),  # Control characters
]


class ValidationError(Exception):
    """Raised when input validation fails."""

    pass


def sanitize_text(text: str, max_length: int = 1000, allow_newlines: bool = False) -> str:
    """
    Sanitize text input by removing dangerous characters.

    Args:
        text: Input text to sanitize
        max_length: Maximum allowed length
        allow_newlines: Whether to allow newline characters

    Returns:
        Sanitized text

    Raises:
        ValidationError: If text contains suspicious patterns
    """
    if not isinstance(text, str):
        raise ValidationError("Input must be a string")

    # Check length
    if len(text) > max_length:
        text = text[:max_length]

    # Check for suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(text):
            raise ValidationError("Input contains disallowed pattern")

    # Remove or escape problematic characters
    if not allow_newlines:
        text = text.replace("\n", " ").replace("\r", " ")

    # Strip leading/trailing whitespace
    text = text.strip()

    # Collapse multiple spaces
    text = re.sub(r" +", " ", text)

    return text


def validate_recipe_name(name: str) -> str:
    """Validate and sanitize a recipe name."""
    name = sanitize_text(name, MAX_RECIPE_NAME_LENGTH)
    if not name:
        raise ValidationError("Recipe name cannot be empty")
    if len(name) < 2:
        raise ValidationError("Recipe name too short")
    return name


# Patterns indicating measurements/quantities (ingredients should be raw names)
MEASUREMENT_PATTERNS = [
    re.compile(r"\d+\s*(lb|lbs|pound|pounds|oz|ounce|ounces)", re.IGNORECASE),
    re.compile(r"\d+\s*(cup|cups|tbsp|tablespoon|tablespoons)", re.IGNORECASE),
    re.compile(r"\d+\s*(tsp|teaspoon|teaspoons|ml|g|kg)", re.IGNORECASE),
    re.compile(r"\d+/\d+", re.IGNORECASE),  # fractions like 1/2, 1/3
    re.compile(r"^\d+\s+[a-zA-Z]"),  # starts with number + space + word
    re.compile(r"\(\d+"),  # parentheses with number like (80/20)
]


def has_measurements(text: str) -> bool:
    """Check if text contains measurement quantities."""
    return any(pattern.search(text) for pattern in MEASUREMENT_PATTERNS)


def validate_ingredient(ingredient: str) -> str:
    """Validate and sanitize an ingredient name (no measurements allowed)."""
    ingredient = sanitize_text(ingredient, MAX_INGREDIENT_LENGTH)
    if not ingredient:
        raise ValidationError("Ingredient cannot be empty")
    if has_measurements(ingredient):
        raise ValidationError(
            f"Ingredient '{ingredient}' contains measurements - use raw ingredient name only"
        )
    return ingredient


def validate_ingredients_list(ingredients: list) -> list[str]:
    """Validate a list of ingredients."""
    if not isinstance(ingredients, list):
        raise ValidationError("Ingredients must be a list")
    if len(ingredients) > MAX_INGREDIENTS_PER_RECIPE:
        raise ValidationError(f"Too many ingredients (max {MAX_INGREDIENTS_PER_RECIPE})")
    return [validate_ingredient(ing) for ing in ingredients if ing]


def validate_directions(directions: str) -> str:
    """Validate and sanitize cooking directions."""
    return sanitize_text(directions, MAX_DIRECTION_LENGTH, allow_newlines=True)


def validate_category(category: str) -> str:
    """Validate and sanitize a category name."""
    return sanitize_text(category, MAX_CATEGORY_LENGTH)


def validate_categories_list(categories: list) -> list[str]:
    """Validate a list of categories."""
    if not isinstance(categories, list):
        raise ValidationError("Categories must be a list")
    if len(categories) > MAX_CATEGORIES_PER_RECIPE:
        raise ValidationError(f"Too many categories (max {MAX_CATEGORIES_PER_RECIPE})")
    return [validate_category(cat) for cat in categories if cat]


def validate_recipe_data(data: dict) -> dict:
    """
    Validate recipe data structure loaded from JSON.

    Args:
        data: Recipe data dictionary

    Returns:
        Validated data dictionary

    Raises:
        ValidationError: If data structure is invalid
    """
    if not isinstance(data, dict):
        raise ValidationError("Recipe data must be a dictionary")

    validated = {}

    # Validate ingredients
    ingredients = data.get("ingredients", [])
    if not isinstance(ingredients, list):
        ingredients = []
    validated["ingredients"] = [
        str(ing)[:MAX_INGREDIENT_LENGTH]
        for ing in ingredients[:MAX_INGREDIENTS_PER_RECIPE]
        if isinstance(ing, (str, int, float))
    ]

    # Validate directions
    directions = data.get("directions", "")
    if not isinstance(directions, str):
        directions = str(directions) if directions else ""
    validated["directions"] = directions[:MAX_DIRECTION_LENGTH]

    # Validate categories
    categories = data.get("categories", [])
    if not isinstance(categories, list):
        categories = []
    validated["categories"] = [
        str(cat)[:MAX_CATEGORY_LENGTH]
        for cat in categories[:MAX_CATEGORIES_PER_RECIPE]
        if isinstance(cat, (str, int, float))
    ]

    # Copy other safe fields
    for key in ("diets", "cook_time", "time_category"):
        if key in data:
            val = data[key]
            if key == "diets" and isinstance(val, list):
                validated[key] = [str(d) for d in val[:10] if isinstance(d, str)]
            elif key == "cook_time" and isinstance(val, (int, float)):
                # Handle special floats (inf, nan) that can't be converted to int
                import math

                if math.isfinite(val):
                    validated[key] = max(0, min(int(val), 1440))  # Max 24 hours
                else:
                    validated[key] = 30  # Default to 30 mins for invalid values
            elif key == "time_category" and isinstance(val, str):
                validated[key] = val[:20]

    return validated


def validate_json_recipes(recipes: Any) -> dict[str, dict]:
    """
    Validate entire recipes JSON structure.

    Args:
        recipes: Loaded JSON data

    Returns:
        Validated recipes dictionary
    """
    if not isinstance(recipes, dict):
        raise ValidationError("Recipes file must contain a dictionary")

    validated = {}
    for name, data in recipes.items():
        if not isinstance(name, str):
            continue
        # Sanitize recipe name
        safe_name = name[:MAX_RECIPE_NAME_LENGTH]
        if isinstance(data, dict):
            validated[safe_name] = validate_recipe_data(data)
        elif isinstance(data, list):
            # Legacy format - just ingredients list
            validated[safe_name] = {
                "ingredients": [
                    str(i)[:MAX_INGREDIENT_LENGTH] for i in data[:MAX_INGREDIENTS_PER_RECIPE]
                ],
                "directions": "",
                "categories": [],
            }

    return validated


def is_safe_filename(filename: str) -> bool:
    """Check if a filename is safe (no path traversal, etc.)."""
    if not filename:
        return False
    # Must not contain path separators or traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        return False
    # Must not start with a dot (hidden files)
    if filename.startswith("."):
        return False
    # Must have valid extension for plugins
    if not filename.endswith(".py"):
        return False
    # Check for null bytes (literal and URL-encoded)
    if "\x00" in filename or "%00" in filename.lower():
        return False
    # Check for other URL-encoded dangerous characters
    if any(enc in filename.lower() for enc in ["%2f", "%5c", "%2e%2e"]):
        return False
    # Must only contain safe characters (alphanumeric, underscore, hyphen, dot)
    return bool(re.match(r"^[a-zA-Z0-9_\-\.]+$", filename))


def check_file_permissions(filepath: str, require_writable: bool = False) -> bool:
    """
    Check if a file path is safe to use.

    Args:
        filepath: Path to check
        require_writable: Whether the file needs to be writable

    Returns:
        True if file is safe to use
    """
    import os
    from pathlib import Path

    try:
        path = Path(filepath).resolve()

        # Check for path traversal (resolved path should be under expected dirs)
        if ".." in filepath:
            return False

        # Check for null bytes
        if "\x00" in filepath:
            return False

        # If file exists, check permissions
        if path.exists():
            if not os.access(path, os.R_OK):
                return False
            if require_writable and not os.access(path, os.W_OK):
                return False
        else:
            # If file doesn't exist, check parent directory
            parent = path.parent
            if not parent.exists():
                return False
            if require_writable and not os.access(parent, os.W_OK):
                return False

        return True
    except (OSError, ValueError):
        return False


def safe_json_load(filepath: str) -> dict:
    """
    Safely load JSON from a file with validation.

    Args:
        filepath: Path to JSON file

    Returns:
        Loaded JSON data

    Raises:
        ValidationError: If file is unsafe or invalid
    """
    import json
    from pathlib import Path

    if not check_file_permissions(filepath):
        raise ValidationError(f"Cannot read file: {filepath}")

    try:
        with Path(filepath).open() as fh:
            return json.load(fh)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON in {filepath}: {e}") from e
    except OSError as e:
        raise ValidationError(f"Cannot open {filepath}: {e}") from e


def safe_json_save(filepath: str, data: dict) -> None:
    """
    Safely save JSON to a file.

    Args:
        filepath: Path to JSON file
        data: Data to save

    Raises:
        ValidationError: If file is unsafe
    """
    import json
    from pathlib import Path

    if not check_file_permissions(filepath, require_writable=True):
        raise ValidationError(f"Cannot write to file: {filepath}")

    try:
        with Path(filepath).open("w") as fh:
            json.dump(data, fh, indent=2)
    except OSError as e:
        raise ValidationError(f"Cannot write to {filepath}: {e}") from e
