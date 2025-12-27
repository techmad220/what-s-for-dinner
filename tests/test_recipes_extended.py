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
    """Test getting ingredients from an existing recipe."""
    recipes.reset_recipes()
    all_recipes = recipes.get_recipes()
    if not all_recipes:
        return  # Skip if no recipes

    # Use first available recipe
    recipe_name = next(iter(all_recipes.keys()))
    ingredients = recipes.get_recipe_ingredients(recipe_name)
    assert ingredients is not None
    assert isinstance(ingredients, list)


def test_get_recipe_directions():
    """Test getting directions from an existing recipe."""
    recipes.reset_recipes()
    all_recipes = recipes.get_recipes()
    if not all_recipes:
        return  # Skip if no recipes

    # Use first available recipe
    recipe_name = next(iter(all_recipes.keys()))
    directions = recipes.get_recipe_directions(recipe_name)
    # Directions may be empty string but not None
    assert directions is not None or directions == ""


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

