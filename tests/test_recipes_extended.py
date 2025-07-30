import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # noqa: E402

from dinner_app import recipes  # noqa: E402


def test_add_recipe_without_persist():
    recipes.reset_recipes()
    recipes.add_recipe(
        "Test Dish", ["test ingredient"], "Test directions", ["cat"], persist=False
    )
    assert "Test Dish" in recipes.get_recipes()
    dinners = recipes.possible_dinners({"test ingredient"})
    assert dinners == ["Test Dish"]
    recipes.reset_recipes()


def test_get_recipe_ingredients():
    recipes.reset_recipes()
    ingredients = recipes.get_recipe_ingredients("Grilled Cheese")
    assert ingredients == ["bread", "cheese", "butter"]


def test_get_recipe_directions():
    recipes.reset_recipes()
    directions = recipes.get_recipe_directions("Spaghetti Bolognese")
    assert "spaghetti" in directions.lower()


def test_extra_ingredients():
    recipes.reset_extra_ingredients()
    recipes.add_extra_ingredient("thing", persist=False)
    assert "thing" in recipes.get_extra_ingredients()
    recipes.remove_extra_ingredient("thing", persist=False)
    assert "thing" not in recipes.get_extra_ingredients()


def test_update_and_remove_recipe():
    recipes.reset_recipes()
    recipes.add_recipe("Temp", ["a"], "dir", ["c"], persist=False)
    recipes.update_recipe("Temp", ["b"], "new", ["d"], persist=False)
    assert recipes.get_recipe_ingredients("Temp") == ["b"]
    assert recipes.get_recipe_directions("Temp") == "new"
    assert recipes.get_recipe_categories("Temp") == ["d"]
    recipes.remove_recipe("Temp", persist=False)
    assert "Temp" not in recipes.get_recipes()


def test_selected_ingredient_persistence(tmp_path, monkeypatch):
    path = tmp_path / "sel.json"
    monkeypatch.setattr(recipes, "SELECTED_FILE", path)
    recipes.save_selected_ingredients({"a", "b"})
    loaded = recipes.load_selected_ingredients()
    assert loaded == {"a", "b"}
