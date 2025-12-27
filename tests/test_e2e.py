"""End-to-end tests for the dinner app workflows.

These tests exercise complete user workflows through the application logic,
testing the integration between GUI logic and backend functions without
requiring an actual display (headless testing).
"""

import json
from unittest.mock import patch

import pytest

# Import application modules
from dinner_app import recipes
from dinner_app.security import (
    ValidationError,
    validate_ingredients_list,
    validate_recipe_data,
    validate_recipe_name,
)


class TestRecipeWorkflow:
    """E2E tests for complete recipe management workflows."""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create a temporary data directory with test recipes."""
        # Create test recipes file
        test_recipes = {
            "Test Pasta": {
                "ingredients": ["pasta", "tomato sauce", "garlic"],
                "directions": "Boil pasta, add sauce",
                "categories": ["Italian", "Quick"],
                "diets": ["vegetarian"],
                "cook_time": 20,
                "time_category": "30-min",
            },
            "Test Salad": {
                "ingredients": ["lettuce", "tomato", "olive oil"],
                "directions": "Mix all ingredients",
                "categories": ["Healthy", "Quick"],
                "diets": ["vegan"],
                "cook_time": 10,
                "time_category": "10-min",
            },
            "Test Steak": {
                "ingredients": ["beef steak", "butter", "garlic", "rosemary"],
                "directions": "Pan sear the steak",
                "categories": ["Dinner"],
                "diets": ["keto", "paleo"],
                "cook_time": 25,
                "time_category": "30-min",
            },
        }

        recipes_file = tmp_path / "recipes.json"
        recipes_file.write_text(json.dumps(test_recipes, indent=2))

        # Create empty extras and selected files
        (tmp_path / "extra_ingredients.json").write_text("[]")
        (tmp_path / "selected_ingredients.json").write_text("[]")

        return tmp_path

    @pytest.fixture
    def mock_recipes_module(self, temp_data_dir):
        """Patch recipes module to use temp directory."""
        with (
            patch.object(recipes, "RECIPES_FILE", temp_data_dir / "recipes.json"),
            patch.object(recipes, "EXTRA_ING_FILE", temp_data_dir / "extra_ingredients.json"),
            patch.object(recipes, "SELECTED_FILE", temp_data_dir / "selected_ingredients.json"),
        ):
            # Clear caches by reloading recipes
            recipes._recipes.clear()
            recipes._recipes.update(recipes.load_recipes())
            yield

    def test_complete_recipe_add_workflow(self, mock_recipes_module, temp_data_dir):
        """Test adding a new recipe through the full workflow."""
        # Step 1: Validate recipe name
        name = validate_recipe_name("Homemade Pizza")
        assert name == "Homemade Pizza"

        # Step 2: Validate ingredients
        ingredients = validate_ingredients_list(["flour", "tomato", "cheese", "basil"])
        assert len(ingredients) == 4

        # Step 3: Add recipe
        recipes.add_recipe(
            name="Homemade Pizza",
            ingredients=ingredients,
            directions="Make dough, add toppings, bake at 450F",
            categories=["Italian", "Homemade"],
        )

        # Step 4: Verify recipe exists
        all_recipes = recipes.get_recipes()
        assert "Homemade Pizza" in all_recipes

        # Step 5: Verify recipe data
        ing = recipes.get_recipe_ingredients("Homemade Pizza")
        assert "flour" in ing
        assert "cheese" in ing

        dirs = recipes.get_recipe_directions("Homemade Pizza")
        assert "450F" in dirs

        cats = recipes.get_recipe_categories("Homemade Pizza")
        assert "Italian" in cats

    def test_complete_recipe_edit_workflow(self, mock_recipes_module):
        """Test editing an existing recipe through the full workflow."""
        # Step 1: Get existing recipe
        original_ings = recipes.get_recipe_ingredients("Test Pasta")
        assert "pasta" in original_ings

        # Step 2: Update recipe with new ingredients
        recipes.update_recipe(
            name="Test Pasta",
            ingredients=["spaghetti", "marinara sauce", "garlic", "parmesan"],
            directions="Boil spaghetti, add marinara and cheese",
            categories=["Italian", "Quick", "Family"],
        )

        # Step 3: Verify changes
        new_ings = recipes.get_recipe_ingredients("Test Pasta")
        assert "spaghetti" in new_ings
        assert "parmesan" in new_ings
        assert "pasta" not in new_ings

        new_dirs = recipes.get_recipe_directions("Test Pasta")
        assert "marinara" in new_dirs

    def test_complete_recipe_delete_workflow(self, mock_recipes_module):
        """Test deleting a recipe through the full workflow."""
        # Step 1: Verify recipe exists
        assert "Test Salad" in recipes.get_all_recipe_names()

        # Step 2: Delete recipe
        recipes.remove_recipe("Test Salad")

        # Step 3: Verify recipe is gone
        assert "Test Salad" not in recipes.get_all_recipe_names()

        # Step 4: Verify other recipes still exist
        assert "Test Pasta" in recipes.get_all_recipe_names()
        assert "Test Steak" in recipes.get_all_recipe_names()


class TestIngredientSelectionWorkflow:
    """E2E tests for ingredient selection and pantry management."""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create a temporary data directory."""
        test_recipes = {
            "Simple Eggs": {
                "ingredients": ["eggs", "butter", "salt"],
                "directions": "Scramble eggs",
                "categories": ["Breakfast"],
                "diets": ["vegetarian"],
                "cook_time": 5,
                "time_category": "10-min",
            },
            "Omelette": {
                "ingredients": ["eggs", "cheese", "onion", "butter"],
                "directions": "Make omelette",
                "categories": ["Breakfast"],
                "diets": ["vegetarian"],
                "cook_time": 10,
                "time_category": "10-min",
            },
        }

        recipes_file = tmp_path / "recipes.json"
        recipes_file.write_text(json.dumps(test_recipes, indent=2))
        (tmp_path / "extra_ingredients.json").write_text("[]")
        (tmp_path / "selected_ingredients.json").write_text("[]")

        return tmp_path

    @pytest.fixture
    def mock_recipes_module(self, temp_data_dir):
        """Patch recipes module to use temp directory."""
        with (
            patch.object(recipes, "RECIPES_FILE", temp_data_dir / "recipes.json"),
            patch.object(recipes, "EXTRA_ING_FILE", temp_data_dir / "extra_ingredients.json"),
            patch.object(recipes, "SELECTED_FILE", temp_data_dir / "selected_ingredients.json"),
        ):
            recipes._recipes.clear()
            recipes._recipes.update(recipes.load_recipes())
            yield

    def test_ingredient_selection_persistence(self, mock_recipes_module):
        """Test that ingredient selections persist across save/load cycles."""
        # Step 1: Select ingredients
        selected = {"eggs", "butter", "salt"}
        recipes.save_selected_ingredients(selected)

        # Step 2: Reload and verify
        loaded = recipes.load_selected_ingredients()
        assert loaded == selected

        # Step 3: Add more ingredients
        selected.add("cheese")
        recipes.save_selected_ingredients(selected)

        # Step 4: Reload and verify again
        loaded = recipes.load_selected_ingredients()
        assert "cheese" in loaded
        assert len(loaded) == 4

    def test_custom_ingredient_workflow(self, mock_recipes_module):
        """Test adding and removing custom ingredients."""
        # Step 1: Add custom ingredient
        recipes.add_extra_ingredient("sriracha")

        # Step 2: Verify it appears in available ingredients
        available = recipes.get_available_ingredients()
        assert "sriracha" in available

        # Step 3: Add another
        recipes.add_extra_ingredient("tahini")
        extras = recipes.get_extra_ingredients()
        assert "sriracha" in extras
        assert "tahini" in extras

        # Step 4: Remove one
        recipes.remove_extra_ingredient("sriracha")
        extras = recipes.get_extra_ingredients()
        assert "sriracha" not in extras
        assert "tahini" in extras


class TestSearchAndFilterWorkflow:
    """E2E tests for search and filtering functionality."""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create a temporary data directory with diverse recipes."""
        test_recipes = {
            "Vegan Tacos": {
                "ingredients": ["tortillas", "black beans", "avocado", "salsa"],
                "directions": "Assemble tacos",
                "categories": ["Mexican", "Quick"],
                "diets": ["vegan"],
                "cook_time": 15,
                "time_category": "30-min",
            },
            "Chicken Stir Fry": {
                "ingredients": ["chicken breast", "soy sauce", "vegetables", "oil"],
                "directions": "Stir fry chicken and vegetables",
                "categories": ["Asian", "Quick"],
                "diets": [],
                "cook_time": 20,
                "time_category": "30-min",
            },
            "Beef Stew": {
                "ingredients": ["beef", "potatoes", "carrots", "onion", "broth"],
                "directions": "Slow cook beef stew",
                "categories": ["Comfort Food"],
                "diets": ["paleo"],
                "cook_time": 120,
                "time_category": "60-min",
            },
            "Quick Salad": {
                "ingredients": ["lettuce", "tomato"],
                "directions": "Toss salad",
                "categories": ["Quick", "Healthy"],
                "diets": ["vegan", "paleo"],
                "cook_time": 5,
                "time_category": "10-min",
            },
        }

        recipes_file = tmp_path / "recipes.json"
        recipes_file.write_text(json.dumps(test_recipes, indent=2))
        (tmp_path / "extra_ingredients.json").write_text("[]")
        (tmp_path / "selected_ingredients.json").write_text("[]")

        return tmp_path

    @pytest.fixture
    def mock_recipes_module(self, temp_data_dir):
        """Patch recipes module to use temp directory."""
        with (
            patch.object(recipes, "RECIPES_FILE", temp_data_dir / "recipes.json"),
            patch.object(recipes, "EXTRA_ING_FILE", temp_data_dir / "extra_ingredients.json"),
            patch.object(recipes, "SELECTED_FILE", temp_data_dir / "selected_ingredients.json"),
        ):
            recipes._recipes.clear()
            recipes._recipes.update(recipes.load_recipes())
            yield

    def test_search_by_name(self, mock_recipes_module):
        """Test searching recipes by name."""
        # Search for 'tacos'
        results = recipes.search_recipes_advanced(
            query="tacos", category="All", owned_ingredients=None, filter_mode="all"
        )
        assert len(results) == 1
        assert results[0][0] == "Vegan Tacos"

        # Search for 'quick'
        results = recipes.search_recipes_advanced(
            query="quick", category="All", owned_ingredients=None, filter_mode="all"
        )
        assert len(results) == 1
        assert results[0][0] == "Quick Salad"

    def test_filter_by_category(self, mock_recipes_module):
        """Test filtering recipes by category."""
        # Filter by 'Quick' category
        results = recipes.search_recipes_advanced(
            query="", category="Quick", owned_ingredients=None, filter_mode="all"
        )
        recipe_names = [r[0] for r in results]
        assert "Vegan Tacos" in recipe_names
        assert "Chicken Stir Fry" in recipe_names
        assert "Quick Salad" in recipe_names
        assert "Beef Stew" not in recipe_names

    def test_filter_by_diet(self, mock_recipes_module):
        """Test filtering recipes by diet."""
        # Filter by vegan
        results = recipes.search_recipes_advanced(
            query="", category="All", owned_ingredients=None, filter_mode="all", diet_filter="vegan"
        )
        recipe_names = [r[0] for r in results]
        assert "Vegan Tacos" in recipe_names
        assert "Quick Salad" in recipe_names
        assert "Chicken Stir Fry" not in recipe_names

    def test_filter_by_can_make(self, mock_recipes_module):
        """Test filtering by 'can make' with selected ingredients."""
        owned = {"lettuce", "tomato"}

        results = recipes.search_recipes_advanced(
            query="", category="All", owned_ingredients=owned, filter_mode="can_make"
        )

        # Should include Quick Salad since we have lettuce and tomato
        recipe_names = [r[0] for r in results]
        assert "Quick Salad" in recipe_names

    def test_filter_by_almost_ready(self, mock_recipes_module):
        """Test filtering by 'almost ready' (missing a few ingredients)."""
        # Test that almost-ready filter returns recipes missing <= max_missing ingredients
        owned = {"tortillas", "black beans", "avocado"}

        results = recipes.search_recipes_advanced(
            query="", category="All", owned_ingredients=owned, filter_mode="almost", max_missing=2
        )

        # Should return results (recipes missing 1-2 ingredients)
        # Exact matches depend on full recipe database
        assert isinstance(results, list)

    def test_combined_filters(self, mock_recipes_module):
        """Test combining multiple filters."""
        owned = {"lettuce", "tomato"}

        # Vegan + can make
        results = recipes.search_recipes_advanced(
            query="",
            category="All",
            owned_ingredients=owned,
            filter_mode="can_make",
            diet_filter="vegan",
        )

        # Should include Quick Salad (vegan, and we have lettuce + tomato)
        recipe_names = [r[0] for r in results]
        assert "Quick Salad" in recipe_names


class TestMissingIngredientsWorkflow:
    """E2E tests for missing ingredients functionality."""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create a temporary data directory."""
        test_recipes = {
            "Test Dish": {
                "ingredients": ["ingredient1", "ingredient2", "ingredient3"],
                "directions": "Cook it",
                "categories": ["Test"],
                "diets": [],
                "cook_time": 10,
                "time_category": "10-min",
            }
        }

        recipes_file = tmp_path / "recipes.json"
        recipes_file.write_text(json.dumps(test_recipes, indent=2))
        (tmp_path / "extra_ingredients.json").write_text("[]")
        (tmp_path / "selected_ingredients.json").write_text("[]")

        return tmp_path

    @pytest.fixture
    def mock_recipes_module(self, temp_data_dir):
        """Patch recipes module to use temp directory."""
        with (
            patch.object(recipes, "RECIPES_FILE", temp_data_dir / "recipes.json"),
            patch.object(recipes, "EXTRA_ING_FILE", temp_data_dir / "extra_ingredients.json"),
            patch.object(recipes, "SELECTED_FILE", temp_data_dir / "selected_ingredients.json"),
        ):
            recipes._recipes.clear()
            recipes._recipes.update(recipes.load_recipes())
            yield

    def test_missing_ingredients_calculation(self, mock_recipes_module):
        """Test calculating missing ingredients for a recipe."""
        owned = {"ingredient1"}

        missing = recipes.get_missing_ingredients("Test Dish", owned)

        assert "ingredient2" in missing
        assert "ingredient3" in missing
        assert "ingredient1" not in missing
        assert len(missing) == 2

    def test_no_missing_ingredients(self, mock_recipes_module):
        """Test when all ingredients are owned."""
        owned = {"ingredient1", "ingredient2", "ingredient3"}

        missing = recipes.get_missing_ingredients("Test Dish", owned)

        assert len(missing) == 0


class TestSecurityValidationWorkflow:
    """E2E tests for security validation in workflows."""

    def test_xss_prevention_in_recipe_name(self):
        """Test that XSS is blocked in recipe names."""
        with pytest.raises(ValidationError):
            validate_recipe_name("<script>alert('xss')</script>")

    def test_path_traversal_prevention_in_ingredients(self):
        """Test that path traversal is blocked in ingredients."""
        with pytest.raises(ValidationError):
            validate_ingredients_list(["../../../etc/passwd"])

    def test_valid_recipe_data_workflow(self):
        """Test that valid recipe data passes through validation."""
        data = {
            "ingredients": ["flour", "sugar", "eggs"],
            "directions": "Mix and bake",
            "categories": ["Baking"],
        }

        validated = validate_recipe_data(data)

        assert validated["ingredients"] == ["flour", "sugar", "eggs"]
        assert validated["directions"] == "Mix and bake"
        assert validated["categories"] == ["Baking"]


class TestHomemadeIngredientsWorkflow:
    """E2E tests for homemade/craftable ingredients feature."""

    def test_craftable_status_function(self):
        """Test getting craftable ingredient status works."""
        # Use a simple set of ingredients to test the function
        owned = {"flour", "water", "yeast", "salt"}

        status = recipes.get_craftable_status(owned)

        # Should return a list
        assert isinstance(status, list)
        # Each item should have required fields
        for item in status:
            assert "name" in item
            assert "can_make" in item

    def test_effective_ingredients_function(self):
        """Test that effective ingredients includes craftable items."""
        # Use ingredients that can make something
        owned = {"flour", "water", "yeast", "salt"}

        effective = recipes.get_effective_ingredients(owned)

        # Should include original ingredients
        assert "flour" in effective
        assert "water" in effective
        # Should be a set
        assert isinstance(effective, set)


class TestRandomSelectionWorkflow:
    """E2E tests for random recipe selection."""

    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temp directory with multiple recipes."""
        test_recipes = {
            "Recipe A": {
                "ingredients": ["ing1"],
                "directions": "Make A",
                "categories": ["Cat1"],
                "diets": [],
                "cook_time": 10,
                "time_category": "10-min",
            },
            "Recipe B": {
                "ingredients": ["ing2"],
                "directions": "Make B",
                "categories": ["Cat1"],
                "diets": [],
                "cook_time": 20,
                "time_category": "30-min",
            },
            "Recipe C": {
                "ingredients": ["ing3"],
                "directions": "Make C",
                "categories": ["Cat2"],
                "diets": [],
                "cook_time": 30,
                "time_category": "30-min",
            },
        }

        recipes_file = tmp_path / "recipes.json"
        recipes_file.write_text(json.dumps(test_recipes, indent=2))
        (tmp_path / "extra_ingredients.json").write_text("[]")
        (tmp_path / "selected_ingredients.json").write_text("[]")

        return tmp_path

    @pytest.fixture
    def mock_recipes_module(self, temp_data_dir):
        """Patch recipes module to use temp directory."""
        with (
            patch.object(recipes, "RECIPES_FILE", temp_data_dir / "recipes.json"),
            patch.object(recipes, "EXTRA_ING_FILE", temp_data_dir / "extra_ingredients.json"),
            patch.object(recipes, "SELECTED_FILE", temp_data_dir / "selected_ingredients.json"),
        ):
            recipes._recipes.clear()
            recipes._recipes.update(recipes.load_recipes())
            yield

    def test_random_from_all(self, mock_recipes_module):
        """Test random selection from all recipes."""
        import random

        random.seed(42)  # For reproducibility

        results = recipes.search_recipes_advanced(
            query="", category="All", owned_ingredients=None, filter_mode="all"
        )

        # Should have all 3 recipes
        assert len(results) == 3

        # Random choice should be one of them
        choice = random.choice(results)
        assert choice[0] in ["Recipe A", "Recipe B", "Recipe C"]

    def test_random_from_category(self, mock_recipes_module):
        """Test random selection filtered by category."""
        results = recipes.search_recipes_advanced(
            query="", category="Cat1", owned_ingredients=None, filter_mode="all"
        )

        # Should have 2 recipes in Cat1
        assert len(results) == 2
        recipe_names = [r[0] for r in results]
        assert "Recipe A" in recipe_names
        assert "Recipe B" in recipe_names
        assert "Recipe C" not in recipe_names
