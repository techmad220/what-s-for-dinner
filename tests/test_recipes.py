"""Test recipes module basic functionality."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dinner_app.recipes import get_recipes, possible_dinners


def test_possible_dinners():
    """Test that possible_dinners returns recipes that can be made."""
    # Get a recipe from the actual database
    recipes = get_recipes()
    if not recipes:
        return  # Skip if no recipes

    # Pick first recipe and get its ingredients
    recipe_name, recipe_data = next(iter(recipes.items()))
    ingredients = set(recipe_data.get("ingredients", []))

    # Should be able to make this recipe with all its ingredients
    result = possible_dinners(ingredients)
    assert recipe_name in result
