"""Utility functions for managing dinner recipes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

RECIPES_FILE = Path(__file__).with_name("recipes.json")
EXTRA_ING_FILE = Path(__file__).with_name("extra_ingredients.json")
SELECTED_FILE = Path(__file__).with_name("selected_ingredients.json")



def load_recipes() -> Dict[str, Dict[str, object]]:
    """Load recipes from :data:`RECIPES_FILE`."""

    with RECIPES_FILE.open() as fh:
        data = json.load(fh)

    # Support legacy format where values are just a list of ingredients
    for name, value in list(data.items()):
        if isinstance(value, list):
            data[name] = {"ingredients": value, "directions": ""}
    return data


def save_recipes(recipes: Dict[str, Dict[str, object]]) -> None:
    """Save recipes to :data:`RECIPES_FILE`."""

    with RECIPES_FILE.open("w") as fh:
        json.dump(recipes, fh, indent=2)


_recipes = load_recipes()



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


def get_recipes() -> Dict[str, Dict[str, object]]:
    """Return the in-memory recipes dictionary."""

    return _recipes


def get_recipe_ingredients(name: str) -> Optional[List[str]]:
    """Return a list of ingredients for ``name`` if it exists."""

    recipe = _recipes.get(name)
    if recipe:
        return list(recipe.get("ingredients", []))
    return None


def get_recipe_directions(name: str) -> Optional[str]:
    """Return cooking directions for ``name`` if they exist."""

    recipe = _recipes.get(name)
    if recipe:
        return str(recipe.get("directions", ""))
    return None



def get_recipe_categories(name: str) -> Optional[List[str]]:
    """Return categories for ``name`` if present."""

    recipe = _recipes.get(name)
    if recipe is not None:
        return list(recipe.get("categories", []))
    return None


def add_recipe(
    name: str,
    ingredients: List[str],
    directions: str = "",
    categories: Optional[List[str]] = None,
    *,
    persist: bool = True,
) -> None:
    """Add a recipe and optionally persist it to disk."""
    _recipes[name] = {
        "ingredients": ingredients,
        "directions": directions,
        "categories": categories or [],
    }
    if persist:
        save_recipes(_recipes)


def reset_recipes() -> None:
    """Reload recipes from disk, discarding in-memory changes."""

    global _recipes
    _recipes = load_recipes()


def remove_recipe(name: str, *, persist: bool = True) -> None:
    """Delete a recipe if it exists."""

    if name in _recipes:
        del _recipes[name]
        if persist:
            save_recipes(_recipes)


def update_recipe(
    name: str,
    ingredients: Optional[List[str]] | None = None,
    directions: Optional[str] | None = None,
    categories: Optional[List[str]] | None = None,
    *,
    persist: bool = True,
) -> None:
    """Modify an existing recipe."""

    rec = _recipes.get(name)
    if rec is None:
        raise KeyError(name)
    if ingredients is not None:
        rec["ingredients"] = list(ingredients)
    if directions is not None:
        rec["directions"] = directions
    if categories is not None:
        rec["categories"] = list(categories)
    if persist:
        save_recipes(_recipes)



def reset_extra_ingredients() -> None:
    """Reload extra ingredients from disk, discarding in-memory changes."""

    global _extra_ingredients
    _extra_ingredients = load_extra_ingredients()


def add_extra_ingredient(name: str, *, persist: bool = True) -> None:
    """Add an extra ingredient to the list."""

    _extra_ingredients.add(name)
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


import random

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
    """Return ingredients missing for a recipe."""
    recipe = _recipes.get(recipe_name)
    if not recipe:
        return set()
    recipe_ings = set(recipe.get("ingredients", []))
    return recipe_ings - owned


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
            if time_filter == "10-min" and time_cat != "10-min":
                continue
            elif time_filter == "30-min" and time_cat not in ("10-min", "30-min"):
                continue
            elif time_filter == "60-min" and time_cat not in ("10-min", "30-min", "60-min"):
                continue
            # "60-plus" or empty means no time restriction

        # Ingredient filter
        recipe_ings = set(recipe.get("ingredients", []))
        missing_count = 0

        if owned_ingredients is not None and filter_mode != "all":
            missing = recipe_ings - owned_ingredients if recipe_ings else set()
            missing_count = len(missing)

            if filter_mode == "can_make":
                if missing_count > 0:
                    continue
            elif filter_mode == "almost":
                if missing_count == 0 or missing_count > max_missing:
                    continue

        results.append((name, missing_count))

    # Sort by name, then by missing count for "almost" mode
    if filter_mode == "almost":
        results.sort(key=lambda x: (x[1], x[0]))
    else:
        results.sort(key=lambda x: x[0])

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
