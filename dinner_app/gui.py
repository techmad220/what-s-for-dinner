from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from .recipes import (
    add_extra_ingredient,
    add_recipe,
    get_available_ingredients,
    get_extra_ingredients,
    get_recipe_directions,
    get_recipe_ingredients,
    remove_extra_ingredient,
    possible_dinners,
)


class DinnerApp(tk.Tk):
    """Tkinter GUI for selecting ingredients and viewing possible dinners."""

    def __init__(self) -> None:
        super().__init__()
        self.title("What's for Dinner")
        self.geometry("600x400")
        self.vars: dict[str, tk.BooleanVar] = {}
        self.checkbuttons: dict[str, ttk.Checkbutton] = {}
        self._setup_ui()
        self.update_dinners()

    def _setup_ui(self) -> None:
        # Left side: ingredient checkboxes
        self.ing_frame = ttk.LabelFrame(self, text="Ingredients")
        self.ing_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        self.ing_list_frame = ttk.Frame(self.ing_frame)
        self.ing_list_frame.pack(fill="both", expand=True)
        btn_frame = ttk.Frame(self.ing_frame)
        btn_frame.pack(fill="x", pady=5)
        add_btn = ttk.Button(btn_frame, text="Add", command=self.add_ingredient)
        add_btn.pack(side="left", padx=5)
        rem_btn = ttk.Button(btn_frame, text="Remove", command=self.remove_ingredient)
        rem_btn.pack(side="left", padx=5)
        self._populate_ingredients()

        # Right side: dinners list and add recipe button
        right = ttk.Frame(self)
        right.pack(side="right", fill="both", expand=True, padx=10, pady=10)

        dinner_box = ttk.LabelFrame(right, text="Possible Dinners")
        dinner_box.pack(fill="both", expand=True)
        self.dinner_var = tk.StringVar(value=[])
        self.dinner_list = tk.Listbox(dinner_box, listvariable=self.dinner_var)
        self.dinner_list.pack(fill="both", expand=True)
        self.dinner_list.bind("<Double-1>", self.show_recipe)

        add_btn = ttk.Button(right, text="Add Recipe", command=self.add_recipe_dialog)
        add_btn.pack(pady=5)

    def _populate_ingredients(self) -> None:
        current = set(get_available_ingredients())
        # Remove checkboxes for ingredients that no longer exist
        for name in list(self.vars.keys()):
            if name not in current:
                self.vars.pop(name)
                cb = self.checkbuttons.pop(name)
                cb.destroy()

        for ing in sorted(current):
            if ing not in self.vars:
                var = tk.BooleanVar()
                self.vars[ing] = var
                cb = ttk.Checkbutton(
                    self.ing_list_frame,
                    text=ing,
                    variable=var,
                    command=self.update_dinners,
                )
                cb.pack(anchor="w")
                self.checkbuttons[ing] = cb

    def owned_ingredients(self) -> set[str]:
        return {i for i, v in self.vars.items() if v.get()}

    def update_dinners(self, *args) -> None:
        dinners = possible_dinners(self.owned_ingredients())
        self.dinner_var.set(sorted(dinners))

    def add_ingredient(self) -> None:
        name = simpledialog.askstring("Add Ingredient", "Ingredient name:", parent=self)
        if not name:
            return
        add_extra_ingredient(name)
        self._populate_ingredients()

    def remove_ingredient(self) -> None:
        name = simpledialog.askstring(
            "Remove Ingredient",
            "Ingredient name to remove:",
            parent=self,
        )
        if not name:
            return
        if name not in get_extra_ingredients():
            messagebox.showerror("Error", f"Cannot remove {name}.")
            return
        remove_extra_ingredient(name)
        self._populate_ingredients()

    def show_recipe(self, event) -> None:
        """Display the ingredients for the selected recipe."""

        selection = self.dinner_list.curselection()
        if not selection:
            return
        name = self.dinner_list.get(selection[0])
        ingredients = get_recipe_ingredients(name)
        if ingredients is None:
            messagebox.showerror("Error", f"Recipe for {name} not found.")
            return
        directions = get_recipe_directions(name) or "No directions provided."
        msg = (
            f"Ingredients for {name}:\n"
            + "\n".join(f"- {i}" for i in ingredients)
            + "\n\nDirections:\n"
            + directions
        )
        messagebox.showinfo(name, msg)

    def add_recipe_dialog(self) -> None:
        name = simpledialog.askstring("New Recipe", "Recipe name:", parent=self)
        if not name:
            return
        ingredients = simpledialog.askstring(
            "Ingredients", "Ingredients (comma separated):", parent=self
        )
        if not ingredients:
            return
        ing_list = [i.strip() for i in ingredients.split(",") if i.strip()]
        if not ing_list:
            messagebox.showerror("Error", "No ingredients given.")
            return
        directions = simpledialog.askstring(
            "Directions", "Cooking directions:", parent=self
        )
        if directions is None:
            return
        add_recipe(name, ing_list, directions, persist=True)
        self._populate_ingredients()
        self.update_dinners()
        messagebox.showinfo("Recipe Added", f"{name} has been added.")


def run_app() -> None:
    DinnerApp().mainloop()


if __name__ == "__main__":
    run_app()
