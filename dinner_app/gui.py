from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, ttk, messagebox, simpledialog

from .recipes import (
    add_extra_ingredient,
    add_recipe,
    get_all_categories,
    get_available_ingredients,
    get_extra_ingredients,
    get_recipe_categories,
    get_recipe_directions,
    get_recipe_ingredients,
    load_selected_ingredients,
    get_recipe_directions,
    get_recipe_ingredients,
    remove_extra_ingredient,
    possible_dinners,
    remove_extra_ingredient,
    remove_recipe,
    save_selected_ingredients,
    update_recipe,
)


class DinnerApp(tk.Tk):
    """Tkinter GUI for selecting ingredients and viewing possible dinners."""

    def __init__(self) -> None:
        super().__init__()
        self.title("What's for Dinner")
        self.geometry("600x400")
        self.vars: dict[str, tk.BooleanVar] = {}
        self.checkbuttons: dict[str, ttk.Checkbutton] = {}
        self.selected: set[str] = load_selected_ingredients()
        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar(value="All")

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
        search = ttk.Entry(dinner_box, textvariable=self.search_var)
        search.pack(fill="x", padx=5, pady=2)
        cat_opts = ["All"] + get_all_categories()
        self.category_cb = ttk.Combobox(
            dinner_box,
            textvariable=self.category_var,
            values=cat_opts,
            state="readonly",
        )
        self.category_cb.pack(fill="x", padx=5, pady=2)
        self.category_cb.bind("<<ComboboxSelected>>", self.update_dinners)
        self.dinner_var = tk.StringVar(value=[])
        self.dinner_list = tk.Listbox(dinner_box, listvariable=self.dinner_var)
        self.dinner_list.pack(fill="both", expand=True)
        self.dinner_list.bind("<Double-1>", self.show_recipe)

        btns = ttk.Frame(right)
        btns.pack(pady=5)
        add_btn = ttk.Button(btns, text="Add Recipe", command=self.add_recipe_dialog)
        add_btn.pack(side="left", padx=2)
        edit_btn = ttk.Button(btns, text="Edit", command=self.edit_recipe_dialog)
        edit_btn.pack(side="left", padx=2)
        del_btn = ttk.Button(btns, text="Delete", command=self.delete_recipe)
        del_btn.pack(side="left", padx=2)

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
                var = tk.BooleanVar(value=ing in self.selected)
                self.vars[ing] = var
                cb = ttk.Checkbutton(
                    self.ing_list_frame,
                    text=ing,
                    variable=var,
                    command=self.update_dinners,
                )
                cb.pack(anchor="w")
                self.checkbuttons[ing] = cb
            else:
                self.vars[ing].set(ing in self.selected)

    def owned_ingredients(self) -> set[str]:
        return {i for i, v in self.vars.items() if v.get()}

    def update_dinners(self, *args) -> None:
        self.selected = self.owned_ingredients()
        save_selected_ingredients(self.selected)
        dinners = possible_dinners(self.selected)
        term = self.search_var.get().lower()
        if term:
            dinners = [d for d in dinners if term in d.lower()]
        cat = self.category_var.get()
        if cat and cat != "All":
            dinners = [d for d in dinners if cat in (get_recipe_categories(d) or [])]
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
        missing = set(ingredients) - self.selected
        if missing and messagebox.askyesno(
            "Export Shopping List", "Export missing ingredients to file?"
        ):
            path = filedialog.asksaveasfilename(
                title="Save Shopping List", defaultextension=".txt"
            )
            if path:
                with open(path, "w") as fh:
                    fh.write(f"Shopping list for {name}:\n")
                    for item in sorted(missing):
                        fh.write(f"- {item}\n")
                messagebox.showinfo("Saved", f"Shopping list saved to {path}")

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
        categories = simpledialog.askstring(
            "Categories", "Categories (comma separated):", parent=self
        )
        cat_list = (
            [c.strip() for c in categories.split(",") if c.strip()]
            if categories
            else []
        )
        add_recipe(name, ing_list, directions, cat_list, persist=True)

        self._populate_ingredients()
        self.update_dinners()
        messagebox.showinfo("Recipe Added", f"{name} has been added.")

    def edit_recipe_dialog(self) -> None:
        selection = self.dinner_list.curselection()
        if not selection:
            messagebox.showerror("Error", "No recipe selected.")
            return
        name = self.dinner_list.get(selection[0])
        ingredients = get_recipe_ingredients(name) or []
        directions = get_recipe_directions(name) or ""
        categories = get_recipe_categories(name) or []
        ing = simpledialog.askstring(
            "Ingredients",
            "Ingredients (comma separated):",
            initialvalue=", ".join(ingredients),
            parent=self,
        )
        if ing is None:
            return
        new_dirs = simpledialog.askstring(
            "Directions", "Cooking directions:", initialvalue=directions, parent=self
        )
        if new_dirs is None:
            return
        cat_str = simpledialog.askstring(
            "Categories",
            "Categories (comma separated):",
            initialvalue=", ".join(categories),
            parent=self,
        )
        cat_list = (
            [c.strip() for c in cat_str.split(",") if c.strip()]
            if cat_str
            else []
        )
        update_recipe(
            name,
            [i.strip() for i in ing.split(",") if i.strip()],
            new_dirs,
            cat_list,
        )
        self._populate_ingredients()
        self.update_dinners()

    def delete_recipe(self) -> None:
        selection = self.dinner_list.curselection()
        if not selection:
            messagebox.showerror("Error", "No recipe selected.")
            return
        name = self.dinner_list.get(selection[0])
        if messagebox.askyesno("Delete", f"Delete {name}?"):
            remove_recipe(name)
            self._populate_ingredients()
            self.update_dinners()


def run_app() -> None:
    DinnerApp().mainloop()


if __name__ == "__main__":
    run_app()
