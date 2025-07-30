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



def add_recipe(
    name: str, ingredients: List[str], directions: str = "", *, persist: bool = True
) -> None:
    """Add a recipe and optionally persist it to disk."""

    _recipes[name] = {"ingredients": ingredients, "directions": directions}
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
