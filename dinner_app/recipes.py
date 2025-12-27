"""Utility functions for managing dinner recipes."""

from __future__ import annotations

import json
import random
from pathlib import Path

from .security import (
    ValidationError,
    validate_categories_list,
    validate_directions,
    validate_ingredient,
    validate_ingredients_list,
    validate_json_recipes,
    validate_recipe_name,
)

RECIPES_FILE = Path(__file__).with_name("recipes.json")
EXTRA_ING_FILE = Path(__file__).with_name("extra_ingredients.json")
SELECTED_FILE = Path(__file__).with_name("selected_ingredients.json")
CRAFTABLE_FILE = Path(__file__).with_name("craftable.json")


def load_recipes() -> dict[str, dict[str, object]]:
    """Load recipes from :data:`RECIPES_FILE` with security validation."""
    try:
        with RECIPES_FILE.open() as fh:
            data = json.load(fh)
    except json.JSONDecodeError as e:
        raise ValidationError(f"Invalid JSON in recipes file: {e}") from e

    # Validate and sanitize all recipe data
    return validate_json_recipes(data)


def save_recipes(recipes: dict[str, dict[str, object]]) -> None:
    """Save recipes to :data:`RECIPES_FILE`."""

    with RECIPES_FILE.open("w") as fh:
        json.dump(recipes, fh, indent=2)


_recipes = load_recipes()

# Precompute lowercase ingredients for each recipe (optimization)
_recipe_ings_lower: dict[str, set[str]] = {}
for _name, _recipe in _recipes.items():
    _recipe_ings_lower[_name] = {ing.lower() for ing in _recipe.get("ingredients", [])}


def load_selected_ingredients() -> set[str]:
    if SELECTED_FILE.exists():
        with SELECTED_FILE.open() as fh:
            return set(json.load(fh))
    return set()


def save_selected_ingredients(selected: set[str]) -> None:
    with SELECTED_FILE.open("w") as fh:
        json.dump(sorted(selected), fh, indent=2)


def load_extra_ingredients() -> set[str]:
    if EXTRA_ING_FILE.exists():
        with EXTRA_ING_FILE.open() as fh:
            return set(json.load(fh))
    return set()


def save_extra_ingredients(ingredients: set[str]) -> None:
    with EXTRA_ING_FILE.open("w") as fh:
        json.dump(sorted(ingredients), fh, indent=2)


_extra_ingredients = load_extra_ingredients()


def get_recipes() -> dict[str, dict[str, object]]:
    """Return the in-memory recipes dictionary."""

    return _recipes


def get_recipe_ingredients(name: str) -> list[str] | None:
    """Return a list of ingredients for ``name`` if it exists."""

    recipe = _recipes.get(name)
    if recipe:
        return list(recipe.get("ingredients", []))
    return None


def get_recipe_directions(name: str) -> str | None:
    """Return cooking directions for ``name`` if they exist."""

    recipe = _recipes.get(name)
    if recipe:
        return str(recipe.get("directions", ""))
    return None


def get_recipe_categories(name: str) -> list[str] | None:
    """Return categories for ``name`` if present."""

    recipe = _recipes.get(name)
    if recipe is not None:
        return list(recipe.get("categories", []))
    return None


def add_recipe(
    name: str,
    ingredients: list[str],
    directions: str = "",
    categories: list[str] | None = None,
    *,
    persist: bool = True,
) -> None:
    """Add a recipe and optionally persist it to disk with validation."""
    # Validate all inputs
    safe_name = validate_recipe_name(name)
    safe_ingredients = validate_ingredients_list(ingredients)
    safe_directions = validate_directions(directions) if directions else ""
    safe_categories = validate_categories_list(categories) if categories else []

    _recipes[safe_name] = {
        "ingredients": safe_ingredients,
        "directions": safe_directions,
        "categories": safe_categories,
    }
    # Update precomputed lowercase cache
    _recipe_ings_lower[safe_name] = {ing.lower() for ing in safe_ingredients}
    if persist:
        save_recipes(_recipes)


def reset_recipes() -> None:
    """Reload recipes from disk, discarding in-memory changes."""

    global _recipes, _recipe_ings_lower
    _recipes = load_recipes()
    # Rebuild precomputed lowercase ingredients
    _recipe_ings_lower = {}
    for name, recipe in _recipes.items():
        _recipe_ings_lower[name] = {ing.lower() for ing in recipe.get("ingredients", [])}


def remove_recipe(name: str, *, persist: bool = True) -> None:
    """Delete a recipe if it exists."""

    if name in _recipes:
        del _recipes[name]
        if persist:
            save_recipes(_recipes)


def update_recipe(
    name: str,
    ingredients: list[str] | None = None,
    directions: str | None = None,
    categories: list[str] | None = None,
    *,
    persist: bool = True,
) -> None:
    """Modify an existing recipe with validation."""
    rec = _recipes.get(name)
    if rec is None:
        raise KeyError(name)
    if ingredients is not None:
        safe_ingredients = validate_ingredients_list(ingredients)
        rec["ingredients"] = safe_ingredients
        _recipe_ings_lower[name] = {ing.lower() for ing in safe_ingredients}
    if directions is not None:
        rec["directions"] = validate_directions(directions)
    if categories is not None:
        rec["categories"] = validate_categories_list(categories)
    if persist:
        save_recipes(_recipes)


def reset_extra_ingredients() -> None:
    """Reload extra ingredients from disk, discarding in-memory changes."""

    global _extra_ingredients
    _extra_ingredients = load_extra_ingredients()


def add_extra_ingredient(name: str, *, persist: bool = True) -> None:
    """Add an extra ingredient to the list with validation."""
    safe_name = validate_ingredient(name)
    _extra_ingredients.add(safe_name)
    if persist:
        save_extra_ingredients(_extra_ingredients)


def remove_extra_ingredient(name: str, *, persist: bool = True) -> None:
    """Remove an extra ingredient if it exists."""

    if name in _extra_ingredients:
        _extra_ingredients.remove(name)
        if persist:
            save_extra_ingredients(_extra_ingredients)


def get_extra_ingredients() -> set[str]:
    """Return the set of user-added ingredients."""

    return set(_extra_ingredients)


def get_all_categories() -> list[str]:
    """Return a sorted list of all categories in the recipes."""

    cats: set[str] = set()
    for rec in _recipes.values():
        cats.update(rec.get("categories", []))
    return sorted(cats)


def get_available_ingredients() -> set:
    """Return a set of all ingredients used in recipes and extras."""

    ingredients: set[str] = set()
    for rec in _recipes.values():
        ingredients.update(rec.get("ingredients", []))
    ingredients.update(_extra_ingredients)
    return ingredients


def possible_dinners(owned: set[str]) -> list[str]:
    """Return a list of recipes that can be made with the owned ingredients."""
    return [
        name
        for name, recipe in _recipes.items()
        if set(recipe.get("ingredients", [])).issubset(owned)
    ]


def get_all_recipe_names() -> list[str]:
    """Return a sorted list of all recipe names."""
    return sorted(_recipes.keys())


def search_recipes(
    query: str = "",
    category: str = "",
    owned_ingredients: set[str] | None = None,
    require_all_ingredients: bool = False,
) -> list[str]:
    """Search recipes with multiple filters."""
    results = []
    query_lower = query.lower()

    for name, recipe in _recipes.items():
        # Text search in name and directions
        if query_lower:
            name_match = query_lower in name.lower()
            dir_match = query_lower in recipe.get("directions", "").lower()
            if not (name_match or dir_match):
                continue

        # Category filter
        if category and category != "All":
            cats = recipe.get("categories", [])
            if category not in cats:
                continue

        # Ingredient filter
        if owned_ingredients is not None and require_all_ingredients:
            recipe_ings = set(recipe.get("ingredients", []))
            if recipe_ings and not recipe_ings.issubset(owned_ingredients):
                continue

        results.append(name)

    return sorted(results)


def choose_random_recipe(
    category: str = "",
    owned_ingredients: set[str] | None = None,
    require_all_ingredients: bool = False,
) -> str | None:
    """Pick a random recipe, optionally filtered."""
    candidates = search_recipes(
        query="",
        category=category,
        owned_ingredients=owned_ingredients,
        require_all_ingredients=require_all_ingredients,
    )
    if not candidates:
        return None
    return random.choice(candidates)


def get_missing_ingredients(recipe_name: str, owned: set[str]) -> set[str]:
    """Return ingredients missing for a recipe using fuzzy matching."""
    recipe = _recipes.get(recipe_name)
    if not recipe:
        return set()
    recipe_ings = recipe.get("ingredients", [])
    owned_lower = {o.lower() for o in owned}

    def has_ingredient(ing: str) -> bool:
        ing_lower = ing.lower()
        if ing_lower in owned_lower:
            return True
        return any(o in ing_lower or ing_lower in o for o in owned_lower)

    return {ing for ing in recipe_ings if not has_ingredient(ing)}


def find_almost_makeable(owned: set[str], max_missing: int = 4) -> list[tuple[str, set[str]]]:
    """Find recipes where we're missing at most max_missing ingredients.

    Returns list of (recipe_name, missing_ingredients) sorted by fewest missing.
    """
    results = []
    for name, recipe in _recipes.items():
        recipe_ings = set(recipe.get("ingredients", []))
        if not recipe_ings:  # Skip recipes with no ingredients listed
            continue
        missing = recipe_ings - owned
        if 0 < len(missing) <= max_missing:
            results.append((name, missing))

    # Sort by number of missing ingredients
    results.sort(key=lambda x: len(x[1]))
    return results


# Cache for ingredient matching - cleared when ingredients change
_ingredient_match_cache: dict[str, bool] = {}
_owned_lower_cache: frozenset[str] = frozenset()
_owned_ingredients_hash: int = 0
# Precomputed recipe missing counts
_recipe_missing_cache: dict[str, int] = {}
# Full search result cache
_search_cache: dict[tuple, list] = {}


def _build_owned_cache(owned_ingredients: set[str]) -> None:
    """Build optimized cache for owned ingredients."""
    global \
        _owned_ingredients_hash, \
        _ingredient_match_cache, \
        _owned_lower_cache, \
        _recipe_missing_cache, \
        _search_cache

    new_hash = hash(frozenset(owned_ingredients))
    if new_hash != _owned_ingredients_hash:
        _ingredient_match_cache.clear()
        _recipe_missing_cache.clear()
        _search_cache.clear()
        _owned_ingredients_hash = new_hash
        _owned_lower_cache = frozenset(o.lower() for o in owned_ingredients)


def _has_ingredient_fast(ing_lower: str) -> bool:
    """Fast ingredient check using pre-built cache."""
    if ing_lower in _ingredient_match_cache:
        return _ingredient_match_cache[ing_lower]

    found = False
    if ing_lower in _owned_lower_cache:
        found = True
    else:
        for o in _owned_lower_cache:
            if o in ing_lower or ing_lower in o:
                found = True
                break

    _ingredient_match_cache[ing_lower] = found
    return found


def _get_recipe_missing_count(recipe_name: str) -> int:
    """Get missing count for a recipe with caching."""
    if recipe_name in _recipe_missing_cache:
        return _recipe_missing_cache[recipe_name]

    # Use precomputed lowercase ingredients
    ings_lower = _recipe_ings_lower.get(recipe_name, set())
    missing = 0
    for ing_lower in ings_lower:
        if not _has_ingredient_fast(ing_lower):
            missing += 1

    _recipe_missing_cache[recipe_name] = missing
    return missing


def _count_missing_ingredients(recipe_ings: set[str], owned_ingredients: set[str]) -> int:
    """Count missing ingredients with caching."""
    _build_owned_cache(owned_ingredients)

    missing = 0
    for ing in recipe_ings:
        if not _has_ingredient_fast(ing.lower()):
            missing += 1
    return missing


def search_recipes_advanced(
    query: str = "",
    category: str = "",
    owned_ingredients: set[str] | None = None,
    filter_mode: str = "all",  # "all", "can_make", "almost"
    max_missing: int = 4,
    diet_filter: str = "",  # "vegan", "vegetarian", "paleo", "keto", "carnivore"
    time_filter: str = "",  # "10-min", "30-min", "60-min", "60-plus"
) -> list[tuple[str, int]]:
    """Advanced search returning (recipe_name, missing_count) tuples."""
    # Check full result cache first
    cache_key = (
        query,
        category,
        filter_mode,
        max_missing,
        diet_filter,
        time_filter,
        _owned_ingredients_hash,
    )
    if cache_key in _search_cache:
        return _search_cache[cache_key]

    # Build ingredient cache if needed
    if owned_ingredients is not None:
        _build_owned_cache(owned_ingredients)

    results = []
    query_lower = query.lower()

    for name, recipe in _recipes.items():
        # Text search in name and directions
        if query_lower:
            name_match = query_lower in name.lower()
            dir_match = query_lower in recipe.get("directions", "").lower()
            if not (name_match or dir_match):
                continue

        # Category filter
        if category and category != "All":
            cats = recipe.get("categories", [])
            if category not in cats:
                continue

        # Diet filter
        if diet_filter:
            diets = recipe.get("diets", [])
            if diet_filter not in diets:
                continue

        # Time filter
        if time_filter:
            time_cat = recipe.get("time_category", "")
            if (
                (time_filter == "10-min" and time_cat != "10-min")
                or (time_filter == "30-min" and time_cat not in ("10-min", "30-min"))
                or (time_filter == "60-min" and time_cat not in ("10-min", "30-min", "60-min"))
            ):
                continue
            # "60-plus" or empty means no time restriction

        # Ingredient filter - use recipe-level cache
        missing_count = 0

        if owned_ingredients is not None and filter_mode != "all":
            missing_count = _get_recipe_missing_count(name)

            if (filter_mode == "can_make" and missing_count > 0) or (
                filter_mode == "almost" and (missing_count == 0 or missing_count > max_missing)
            ):
                continue

        results.append((name, missing_count))

    # Sort by name, then by missing count for "almost" mode
    if filter_mode == "almost":
        results.sort(key=lambda x: (x[1], x[0]))
    else:
        results.sort(key=lambda x: x[0])

    # Store in cache before returning
    _search_cache[cache_key] = results
    return results


def get_all_diets() -> list[str]:
    """Return all available diet types."""
    return ["vegan", "vegetarian", "paleo", "keto", "carnivore"]


def get_all_time_categories() -> list[str]:
    """Return all available time categories."""
    return ["10-min", "30-min", "60-min", "60-plus"]


def get_recipe_diets(name: str) -> list[str]:
    """Return diet types for a recipe."""
    recipe = _recipes.get(name)
    if recipe:
        return list(recipe.get("diets", []))
    return []


def get_recipe_time(name: str) -> tuple[int, str]:
    """Return cook time and category for a recipe."""
    recipe = _recipes.get(name)
    if recipe:
        return (recipe.get("cook_time", 30), recipe.get("time_category", "30-min"))
    return (30, "30-min")


# ============== CRAFTABLE INGREDIENTS ==============


def load_craftable() -> list[dict]:
    """Load craftable ingredient definitions."""
    if CRAFTABLE_FILE.exists():
        with CRAFTABLE_FILE.open() as fh:
            data = json.load(fh)
            return data.get("craftable_ingredients", [])
    return []


def save_craftable(craftables: list[dict]) -> None:
    """Save craftable ingredient definitions."""
    with CRAFTABLE_FILE.open("w") as fh:
        json.dump({"craftable_ingredients": craftables}, fh, indent=2)


_craftables = load_craftable()


def get_craftable_ingredients() -> list[dict]:
    """Return all craftable ingredient definitions."""
    return _craftables


def _ingredient_match(ing: str, check: str) -> bool:
    """Check if ingredient matches (case-insensitive, partial match)."""
    ing_lower = ing.lower()
    check_lower = check.lower()
    return check_lower in ing_lower or ing_lower in check_lower


def can_craft(craftable: dict, owned: set[str]) -> tuple[bool, list[str], list[str]]:
    """
    Check if we can craft an ingredient.
    Returns (can_make, have_ingredients, missing_ingredients)
    """
    base_ings = craftable.get("base_ingredients", [])
    min_required = craftable.get("min_required", len(base_ings))

    have = []
    missing = []

    for base in base_ings:
        found = False
        for o in owned:
            if _ingredient_match(base, o):
                have.append(base)
                found = True
                break
        if not found:
            missing.append(base)

    can_make = len(have) >= min_required
    return can_make, have, missing


def get_craftable_status(owned: set[str] | None = None) -> list[dict]:
    """
    Get status of all craftable ingredients.
    Returns list of dicts with name, can_make, have, missing, directions.
    """
    if owned is None:
        owned = load_selected_ingredients()

    results = []
    for craft in _craftables:
        can_make, have, missing = can_craft(craft, owned)
        results.append(
            {
                "name": craft["name"],
                "aliases": craft.get("aliases", []),
                "can_make": can_make,
                "have": have,
                "missing": missing,
                "directions": craft.get("directions", ""),
                "min_required": craft.get("min_required", len(craft.get("base_ingredients", []))),
                "total_ingredients": len(craft.get("base_ingredients", [])),
            }
        )
    return results


def get_effective_ingredients(owned: set[str] | None = None) -> set[str]:
    """
    Get all ingredients we effectively have - owned + craftable.
    This expands our ingredient list with things we can make.
    """
    if owned is None:
        owned = load_selected_ingredients()

    effective = set(owned)

    for craft in _craftables:
        can_make, _, _ = can_craft(craft, owned)
        if can_make:
            # Add all aliases as available
            effective.add(craft["name"])
            for alias in craft.get("aliases", []):
                effective.add(alias)

    return effective


def possible_dinners_with_crafting(owned: set[str] | None = None) -> list[str]:
    """Return recipes makeable with owned ingredients + craftable ingredients."""
    effective = get_effective_ingredients(owned)
    effective_lower = {e.lower() for e in effective}

    def has_ingredient(ing: str) -> bool:
        ing_lower = ing.lower()
        if ing_lower in effective_lower:
            return True
        return any(e in ing_lower or ing_lower in e for e in effective_lower)

    return [
        name
        for name, recipe in _recipes.items()
        if all(has_ingredient(ing) for ing in recipe.get("ingredients", []))
    ]
