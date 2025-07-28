"""Utility functions for managing dinner recipes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

RECIPES_FILE = Path(__file__).with_name("recipes.json")


def load_recipes() -> Dict[str, List[str]]:
    """Load recipes from :data:`RECIPES_FILE`."""
    with RECIPES_FILE.open() as fh:
        return json.load(fh)


def save_recipes(recipes: Dict[str, List[str]]) -> None:
    """Save recipes to :data:`RECIPES_FILE`."""
    with RECIPES_FILE.open("w") as fh:
        json.dump(recipes, fh, indent=2)


_recipes = load_recipes()


def get_recipes() -> Dict[str, List[str]]:
    """Return the in-memory recipes dictionary."""
    return _recipes


def get_recipe_ingredients(name: str) -> Optional[List[str]]:
    """Return a list of ingredients for ``name`` if it exists."""

    return _recipes.get(name)


def add_recipe(name: str, ingredients: List[str], *, persist: bool = True) -> None:
    """Add a recipe and optionally persist it to disk."""

    _recipes[name] = ingredients
    if persist:
        save_recipes(_recipes)


def reset_recipes() -> None:
    """Reload recipes from disk, discarding in-memory changes."""

    global _recipes
    _recipes = load_recipes()


def get_available_ingredients() -> set:
    """Return a set of all ingredients used in recipes."""

    ingredients: set[str] = set()
    for items in _recipes.values():
        ingredients.update(items)
    return ingredients


def possible_dinners(owned: set[str]) -> list[str]:
    """Return a list of recipes that can be made with the owned ingredients."""

    return [name for name, reqs in _recipes.items() if set(reqs).issubset(owned)]
