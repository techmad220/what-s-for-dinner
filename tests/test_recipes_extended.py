import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # noqa: E402

from dinner_app import recipes  # noqa: E402


def test_add_recipe_without_persist():
    recipes.reset_recipes()
    recipes.add_recipe("Test Dish", ["test ingredient"], persist=False)
    assert "Test Dish" in recipes.get_recipes()
    dinners = recipes.possible_dinners({"test ingredient"})
    assert dinners == ["Test Dish"]
    recipes.reset_recipes()


def test_get_recipe_ingredients():
    recipes.reset_recipes()
    ingredients = recipes.get_recipe_ingredients("Grilled Cheese")
    assert ingredients == ["bread", "cheese", "butter"]
