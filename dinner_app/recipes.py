"""Utility functions for managing dinner recipes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

RECIPES_FILE = Path(__file__).with_name("recipes.json")
DIRECTIONS_FILE = Path(__file__).with_name("directions.json")


def load_recipes() -> Dict[str, List[str]]:
    """Load recipes from :data:`RECIPES_FILE`."""
    with RECIPES_FILE.open() as fh:
        return json.load(fh)


def load_directions() -> Dict[str, str]:
    """Load recipe directions from :data:`DIRECTIONS_FILE`."""

    with DIRECTIONS_FILE.open() as fh:
        return json.load(fh)


def save_recipes(recipes: Dict[str, List[str]]) -> None:
    """Save recipes to :data:`RECIPES_FILE`."""
    with RECIPES_FILE.open("w") as fh:
        json.dump(recipes, fh, indent=2)


def save_directions(directions: Dict[str, str]) -> None:
    """Save directions to :data:`DIRECTIONS_FILE`."""

    with DIRECTIONS_FILE.open("w") as fh:
        json.dump(directions, fh, indent=2)


_recipes = load_recipes()
_directions = load_directions()


def get_recipes() -> Dict[str, List[str]]:
    """Return the in-memory recipes dictionary."""
    return _recipes


def get_recipe_ingredients(name: str) -> Optional[List[str]]:
    """Return a list of ingredients for ``name`` if it exists."""

    return _recipes.get(name)


def get_recipe_directions(name: str) -> Optional[str]:
    """Return the directions for ``name`` if available."""

    return _directions.get(name)


def add_recipe(
    name: str,
    ingredients: List[str],
    directions: Optional[str] = None,
    *,
    persist: bool = True,
) -> None:
    """Add a recipe and optionally persist it to disk."""

    _recipes[name] = ingredients
    if directions is not None:
        _directions[name] = directions
    if persist:
        save_recipes(_recipes)
        save_directions(_directions)


def reset_recipes() -> None:
    """Reload recipes from disk, discarding in-memory changes."""

    global _recipes, _directions
    _recipes = load_recipes()
    _directions = load_directions()


def get_available_ingredients() -> set:
    """Return a set of all ingredients used in recipes."""

    ingredients: set[str] = set()
    for items in _recipes.values():
        ingredients.update(items)
    return ingredients


def possible_dinners(owned: set[str]) -> list[str]:
    """Return a list of recipes that can be made with the owned ingredients."""

    return [name for name, reqs in _recipes.items() if set(reqs).issubset(owned)]
