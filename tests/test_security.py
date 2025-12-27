"""Security tests for the dinner app."""

import pytest

from dinner_app.security import (
    ValidationError,
    check_file_permissions,
    is_safe_filename,
    sanitize_text,
    validate_ingredient,
    validate_ingredients_list,
    validate_json_recipes,
    validate_recipe_data,
    validate_recipe_name,
)


class TestSanitizeText:
    """Tests for sanitize_text function."""

    def test_normal_text_passes(self):
        result = sanitize_text("Chicken Parmesan")
        assert result == "Chicken Parmesan"

    def test_text_with_punctuation_passes(self):
        result = sanitize_text("Mom's Best Recipe!")
        assert result == "Mom's Best Recipe!"

    def test_script_injection_blocked(self):
        with pytest.raises(ValidationError):
            sanitize_text("<script>alert(1)</script>")

    def test_javascript_injection_blocked(self):
        with pytest.raises(ValidationError):
            sanitize_text("javascript:void(0)")

    def test_event_handler_blocked(self):
        with pytest.raises(ValidationError):
            sanitize_text('onclick="evil()"')

    def test_path_traversal_blocked(self):
        with pytest.raises(ValidationError):
            sanitize_text("../../../etc/passwd")

    def test_windows_path_traversal_blocked(self):
        with pytest.raises(ValidationError):
            sanitize_text("..\\..\\windows\\system32")

    def test_control_characters_blocked(self):
        with pytest.raises(ValidationError):
            sanitize_text("test\x00null")

    def test_length_truncation(self):
        long_text = "a" * 2000
        result = sanitize_text(long_text, max_length=100)
        assert len(result) == 100

    def test_newlines_stripped_by_default(self):
        result = sanitize_text("line1\nline2")
        assert result == "line1 line2"

    def test_newlines_allowed_when_specified(self):
        result = sanitize_text("line1\nline2", allow_newlines=True)
        assert result == "line1\nline2"

    def test_whitespace_collapsed(self):
        result = sanitize_text("too    many   spaces")
        assert result == "too many spaces"

    def test_non_string_rejected(self):
        with pytest.raises(ValidationError):
            sanitize_text(123)


class TestValidateRecipeName:
    """Tests for validate_recipe_name function."""

    def test_valid_name_passes(self):
        result = validate_recipe_name("Spaghetti Carbonara")
        assert result == "Spaghetti Carbonara"

    def test_empty_name_rejected(self):
        with pytest.raises(ValidationError):
            validate_recipe_name("")

    def test_short_name_rejected(self):
        with pytest.raises(ValidationError):
            validate_recipe_name("X")

    def test_injection_blocked(self):
        with pytest.raises(ValidationError):
            validate_recipe_name("<script>alert('xss')</script>")


class TestValidateIngredient:
    """Tests for validate_ingredient function."""

    def test_valid_ingredient_passes(self):
        result = validate_ingredient("Olive Oil")
        assert result == "Olive Oil"

    def test_empty_ingredient_rejected(self):
        with pytest.raises(ValidationError):
            validate_ingredient("")

    def test_injection_blocked(self):
        with pytest.raises(ValidationError):
            validate_ingredient("../malicious")


class TestValidateIngredientsList:
    """Tests for validate_ingredients_list function."""

    def test_valid_list_passes(self):
        result = validate_ingredients_list(["Salt", "Pepper", "Garlic"])
        assert result == ["Salt", "Pepper", "Garlic"]

    def test_non_list_rejected(self):
        with pytest.raises(ValidationError):
            validate_ingredients_list("not a list")

    def test_too_many_ingredients_rejected(self):
        with pytest.raises(ValidationError):
            validate_ingredients_list(["Ingredient"] * 101)

    def test_empty_ingredients_filtered(self):
        result = validate_ingredients_list(["Salt", "", "Pepper"])
        assert result == ["Salt", "Pepper"]


class TestValidateRecipeData:
    """Tests for validate_recipe_data function."""

    def test_valid_data_passes(self):
        data = {
            "ingredients": ["Pasta", "Eggs"],
            "directions": "Cook the pasta",
            "categories": ["Italian"],
        }
        result = validate_recipe_data(data)
        assert result["ingredients"] == ["Pasta", "Eggs"]
        assert result["directions"] == "Cook the pasta"
        assert result["categories"] == ["Italian"]

    def test_non_dict_rejected(self):
        with pytest.raises(ValidationError):
            validate_recipe_data("not a dict")

    def test_missing_fields_handled(self):
        result = validate_recipe_data({})
        assert result["ingredients"] == []
        assert result["directions"] == ""
        assert result["categories"] == []

    def test_cook_time_clamped(self):
        result = validate_recipe_data({"cook_time": 99999})
        assert result["cook_time"] == 1440  # Max 24 hours

    def test_negative_cook_time_clamped(self):
        result = validate_recipe_data({"cook_time": -100})
        assert result["cook_time"] == 0


class TestIsSafeFilename:
    """Tests for is_safe_filename function."""

    def test_valid_plugin_passes(self):
        assert is_safe_filename("plugin_custom.py") is True

    def test_empty_filename_rejected(self):
        assert is_safe_filename("") is False

    def test_path_traversal_rejected(self):
        assert is_safe_filename("../plugin.py") is False

    def test_windows_path_rejected(self):
        assert is_safe_filename("..\\plugin.py") is False

    def test_hidden_file_rejected(self):
        assert is_safe_filename(".hidden.py") is False

    def test_wrong_extension_rejected(self):
        assert is_safe_filename("plugin.exe") is False

    def test_null_byte_rejected(self):
        assert is_safe_filename("plugin\x00.py") is False


class TestCheckFilePermissions:
    """Tests for check_file_permissions function."""

    def test_valid_file_passes(self, tmp_path):
        test_file = tmp_path / "test.json"
        test_file.write_text("{}")
        assert check_file_permissions(str(test_file)) is True

    def test_path_traversal_rejected(self):
        assert check_file_permissions("../../../etc/passwd") is False

    def test_null_byte_rejected(self):
        assert check_file_permissions("/tmp/test\x00.json") is False

    def test_nonexistent_parent_rejected(self):
        assert check_file_permissions("/nonexistent/path/file.json") is False


class TestValidateJsonRecipes:
    """Tests for validate_json_recipes function."""

    def test_valid_recipes_pass(self):
        recipes = {
            "Pasta": {
                "ingredients": ["Noodles", "Sauce"],
                "directions": "Cook it",
                "categories": ["Italian"],
            }
        }
        result = validate_json_recipes(recipes)
        assert "Pasta" in result

    def test_non_dict_rejected(self):
        with pytest.raises(ValidationError):
            validate_json_recipes("not a dict")

    def test_legacy_format_converted(self):
        recipes = {"Simple Dish": ["Ingredient 1", "Ingredient 2"]}
        result = validate_json_recipes(recipes)
        assert result["Simple Dish"]["ingredients"] == ["Ingredient 1", "Ingredient 2"]
        assert result["Simple Dish"]["directions"] == ""

    def test_long_names_truncated(self):
        recipes = {"A" * 300: {"ingredients": ["Test"]}}
        result = validate_json_recipes(recipes)
        keys = list(result.keys())
        assert len(keys[0]) == 200
