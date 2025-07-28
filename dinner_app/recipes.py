RECIPES = {
    "Spaghetti Bolognese": ["spaghetti", "ground beef", "tomato sauce"],
    "Grilled Cheese": ["bread", "cheese", "butter"],
    "Chicken Salad": ["chicken", "lettuce", "tomato"],
    "Veggie Stir Fry": ["broccoli", "carrot", "soy sauce"],
}


def get_available_ingredients() -> set:
    """Return a set of all ingredients used in recipes."""
    ingredients = set()
    for items in RECIPES.values():
        ingredients.update(items)
    return ingredients


def possible_dinners(owned: set) -> list:
    """Return a list of recipes that can be made with the owned ingredients."""
    return [name for name, reqs in RECIPES.items() if set(reqs).issubset(owned)]
