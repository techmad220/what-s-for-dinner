from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from .recipes import (
    add_recipe,
    get_available_ingredients,
    get_recipe_ingredients,
    possible_dinners,
)


class DinnerApp(tk.Tk):
    """Tkinter GUI for selecting ingredients and viewing possible dinners."""

    def __init__(self) -> None:
        super().__init__()
        self.title("What's for Dinner")
        self.geometry("600x400")
        self.vars: dict[str, tk.BooleanVar] = {}
        self._setup_ui()
        self.update_dinners()

    def _setup_ui(self) -> None:
        # Left side: ingredient checkboxes
        self.ing_frame = ttk.LabelFrame(self, text="Ingredients")
        self.ing_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
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
        for ing in sorted(get_available_ingredients()):
            if ing not in self.vars:
                var = tk.BooleanVar()
                self.vars[ing] = var
                cb = ttk.Checkbutton(
                    self.ing_frame,
                    text=ing,
                    variable=var,
                    command=self.update_dinners,
                )
                cb.pack(anchor="w")

    def owned_ingredients(self) -> set[str]:
        return {i for i, v in self.vars.items() if v.get()}

    def update_dinners(self, *args) -> None:
        dinners = possible_dinners(self.owned_ingredients())
        self.dinner_var.set(sorted(dinners))

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
        msg = f"Ingredients for {name}:\n" + "\n".join(f"- {i}" for i in ingredients)
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
        add_recipe(name, ing_list, persist=True)
        self._populate_ingredients()
        self.update_dinners()
        messagebox.showinfo("Recipe Added", f"{name} has been added.")


def run_app() -> None:
    DinnerApp().mainloop()


if __name__ == "__main__":
    run_app()
