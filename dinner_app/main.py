import questionary
from .recipes import get_available_ingredients, possible_dinners


def main() -> None:
    ingredients = list(get_available_ingredients())
    answer = questionary.checkbox(
        "Select the ingredients you have:", choices=ingredients
    ).ask()
    if answer is None:
        print("No ingredients selected.")
        return
    owned = set(answer)
    dinners = possible_dinners(owned)
    if dinners:
        print("You can make:")
        for dinner in dinners:
            print(f"- {dinner}")
    else:
        print("No dinners match your ingredients.")


if __name__ == "__main__":
    main()
