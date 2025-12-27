"""Security utilities for input validation and sanitization."""

from __future__ import annotations

import re
from typing import Any

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


def validate_ingredient(ingredient: str) -> str:
    """Validate and sanitize an ingredient name."""
    ingredient = sanitize_text(ingredient, MAX_INGREDIENT_LENGTH)
    if not ingredient:
        raise ValidationError("Ingredient cannot be empty")
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
    import re
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        return False
    return True


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
        path_str = str(path)
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
        raise ValidationError(f"Invalid JSON in {filepath}: {e}")
    except OSError as e:
        raise ValidationError(f"Cannot open {filepath}: {e}")


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
        raise ValidationError(f"Cannot write to {filepath}: {e}")
