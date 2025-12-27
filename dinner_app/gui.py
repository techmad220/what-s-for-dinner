from __future__ import annotations

import customtkinter as ctk
from tkinter import messagebox, filedialog
import random

from .logging_config import setup_logging, get_logger
from .recipes import (
    add_extra_ingredient,
    add_recipe,
    get_all_categories,
    get_all_diets,
    get_all_recipe_names,
    get_all_time_categories,
    get_available_ingredients,
    get_craftable_status,
    get_effective_ingredients,
    get_extra_ingredients,
    get_missing_ingredients,
    get_recipe_categories,
    get_recipe_diets,
    get_recipe_directions,
    get_recipe_ingredients,
    get_recipe_time,
    load_selected_ingredients,
    remove_extra_ingredient,
    remove_recipe,
    save_selected_ingredients,
    search_recipes_advanced,
    update_recipe,
)
from .security import ValidationError

# Initialize logging
logger = setup_logging()

# Set appearance and theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class DinnerApp(ctk.CTk):
    """Modern GUI for What's for Dinner app using CustomTkinter."""

    def __init__(self) -> None:
        super().__init__()
        self.title("What's for Dinner?")
        self.geometry("1400x900")
        self.minsize(1200, 800)

        # Variables
        self.search_var = ctk.StringVar()
        self.ing_search_var = ctk.StringVar()
        self.category_var = ctk.StringVar(value="All")
        self.diet_var = ctk.StringVar(value="All")
        self.time_var = ctk.StringVar(value="All")
        self.filter_mode_var = ctk.StringVar(value="all")
        self.max_missing_var = ctk.IntVar(value=4)
        self.include_homemade_var = ctk.BooleanVar(value=True)
        self.selected_ingredients: set[str] = load_selected_ingredients()

        # Ingredient checkbox vars
        self.ing_vars: dict[str, ctk.BooleanVar] = {}
        self.ing_checkboxes: list[ctk.CTkCheckBox] = []

        # Debounce timer for search
        self._search_timer = None
        self._ing_search_timer = None

        # Cache
        self._all_ingredients: list[str] = []
        self._categories_cache: list[str] = []
        self._current_results: list[tuple[str, int]] = []
        self._visible_start: int = 0
        self._visible_count: int = 20
        self._recipe_frames: list = []

        self._setup_ui()
        self._load_initial_data()

    def _load_initial_data(self) -> None:
        """Load data once at startup."""
        self._all_ingredients = sorted(get_available_ingredients())
        self._categories_cache = self._get_category_options()
        self.category_menu.configure(values=self._categories_cache)
        self._populate_ingredients()
        self._refresh_recipes()

    def _setup_ui(self) -> None:
        # Configure grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # === LEFT SIDEBAR ===
        self.sidebar = ctk.CTkFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(4, weight=1)

        # App title
        self.logo_label = ctk.CTkLabel(
            self.sidebar,
            text="What's for\nDinner?",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 20))

        # Pantry section
        self.pantry_label = ctk.CTkLabel(
            self.sidebar,
            text="My Pantry",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.pantry_label.grid(row=1, column=0, padx=20, pady=(10, 5), sticky="w")

        # Ingredient search
        self.ing_search_entry = ctk.CTkEntry(
            self.sidebar,
            placeholder_text="Search ingredients...",
            textvariable=self.ing_search_var,
            width=240
        )
        self.ing_search_entry.grid(row=2, column=0, padx=20, pady=(5, 10))
        self.ing_search_var.trace_add("write", self._on_ing_search_change)

        # Quick action buttons
        self.action_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.action_frame.grid(row=3, column=0, padx=20, pady=5, sticky="ew")

        self.select_all_btn = ctk.CTkButton(
            self.action_frame,
            text="Select All",
            width=110,
            command=self._select_all_visible
        )
        self.select_all_btn.pack(side="left", padx=(0, 5))

        self.clear_btn = ctk.CTkButton(
            self.action_frame,
            text="Clear All",
            width=110,
            fg_color="transparent",
            border_width=1,
            command=self._clear_ingredients
        )
        self.clear_btn.pack(side="right")

        # Scrollable ingredient list
        self.ing_scroll_frame = ctk.CTkScrollableFrame(
            self.sidebar,
            label_text="Ingredients",
            width=240,
            height=400
        )
        self.ing_scroll_frame.grid(row=4, column=0, padx=20, pady=10, sticky="nsew")

        # Selected count
        self.count_label = ctk.CTkLabel(
            self.sidebar,
            text="0 selected",
            font=ctk.CTkFont(size=14)
        )
        self.count_label.grid(row=5, column=0, padx=20, pady=5)

        # Homemade toggle
        self.homemade_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.homemade_frame.grid(row=6, column=0, padx=20, pady=(5, 5), sticky="ew")

        self.homemade_switch = ctk.CTkSwitch(
            self.homemade_frame,
            text="Include Homemade",
            variable=self.include_homemade_var,
            command=self._on_homemade_toggle,
            font=ctk.CTkFont(size=12)
        )
        self.homemade_switch.pack(side="left")

        self.homemade_info_btn = ctk.CTkButton(
            self.homemade_frame,
            text="?",
            width=25,
            height=25,
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            border_width=1,
            command=self._show_homemade_info
        )
        self.homemade_info_btn.pack(side="right")

        # Add/Remove buttons
        self.custom_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.custom_frame.grid(row=7, column=0, padx=20, pady=(5, 20), sticky="ew")

        ctk.CTkButton(
            self.custom_frame,
            text="+ Add",
            width=110,
            command=self._add_ingredient
        ).pack(side="left", padx=(0, 5))

        ctk.CTkButton(
            self.custom_frame,
            text="- Remove",
            width=110,
            fg_color="transparent",
            border_width=1,
            command=self._remove_ingredient
        ).pack(side="right")

        # === MAIN CONTENT ===
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        # === TOP SECTION: SEARCH & FILTERS ===
        self.filter_frame = ctk.CTkFrame(self.main_frame)
        self.filter_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        self.filter_frame.grid_columnconfigure(1, weight=1)

        # Search
        ctk.CTkLabel(
            self.filter_frame,
            text="Search Recipes",
            font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")

        self.search_entry = ctk.CTkEntry(
            self.filter_frame,
            placeholder_text="Type to search recipes...",
            textvariable=self.search_var,
            height=40
        )
        self.search_entry.grid(row=0, column=1, padx=(10, 20), pady=(15, 5), sticky="ew")
        self.search_var.trace_add("write", self._on_search_change)

        # Filter dropdowns frame
        self.dropdowns_frame = ctk.CTkFrame(self.filter_frame, fg_color="transparent")
        self.dropdowns_frame.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="ew")

        # Category dropdown
        ctk.CTkLabel(
            self.dropdowns_frame,
            text="Category",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left", padx=(0, 5))

        self.category_menu = ctk.CTkOptionMenu(
            self.dropdowns_frame,
            values=["All"],  # Will be populated later
            variable=self.category_var,
            command=lambda _: self._refresh_recipes(),
            width=140
        )
        self.category_menu.pack(side="left", padx=(0, 15))

        # Diet dropdown
        ctk.CTkLabel(
            self.dropdowns_frame,
            text="Diet",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left", padx=(0, 5))

        self.diet_menu = ctk.CTkOptionMenu(
            self.dropdowns_frame,
            values=["All", "Vegan", "Vegetarian", "Paleo", "Keto", "Carnivore"],
            variable=self.diet_var,
            command=lambda _: self._refresh_recipes(),
            width=120
        )
        self.diet_menu.pack(side="left", padx=(0, 15))

        # Time dropdown
        ctk.CTkLabel(
            self.dropdowns_frame,
            text="Time",
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left", padx=(0, 5))

        self.time_menu = ctk.CTkOptionMenu(
            self.dropdowns_frame,
            values=["All", "≤10 min", "≤30 min", "≤60 min"],
            variable=self.time_var,
            command=lambda _: self._refresh_recipes(),
            width=100
        )
        self.time_menu.pack(side="left", padx=(0, 15))

        # Filter mode
        self.filter_mode_frame = ctk.CTkFrame(self.filter_frame, fg_color="transparent")
        self.filter_mode_frame.grid(row=2, column=0, columnspan=2, padx=20, pady=(5, 10), sticky="w")

        ctk.CTkLabel(
            self.filter_mode_frame,
            text="Show:",
            font=ctk.CTkFont(size=13)
        ).pack(side="left", padx=(0, 15))

        self.radio_all = ctk.CTkRadioButton(
            self.filter_mode_frame,
            text="All Recipes",
            variable=self.filter_mode_var,
            value="all",
            command=self._refresh_recipes
        )
        self.radio_all.pack(side="left", padx=10)

        self.radio_can_make = ctk.CTkRadioButton(
            self.filter_mode_frame,
            text="Can Make",
            variable=self.filter_mode_var,
            value="can_make",
            command=self._refresh_recipes
        )
        self.radio_can_make.pack(side="left", padx=10)

        self.radio_almost = ctk.CTkRadioButton(
            self.filter_mode_frame,
            text="Almost Ready",
            variable=self.filter_mode_var,
            value="almost",
            command=self._refresh_recipes
        )
        self.radio_almost.pack(side="left", padx=10)

        # Missing ingredients slider
        self.missing_frame = ctk.CTkFrame(self.filter_frame, fg_color="transparent")
        self.missing_frame.grid(row=3, column=0, columnspan=2, padx=20, pady=(0, 15), sticky="w")

        ctk.CTkLabel(
            self.missing_frame,
            text="Max missing ingredients:",
            font=ctk.CTkFont(size=12)
        ).pack(side="left", padx=(0, 10))

        self.missing_slider = ctk.CTkSlider(
            self.missing_frame,
            from_=1,
            to=10,
            number_of_steps=9,
            variable=self.max_missing_var,
            width=200,
            command=self._on_slider_change
        )
        self.missing_slider.pack(side="left", padx=5)

        self.missing_label = ctk.CTkLabel(
            self.missing_frame,
            text="4",
            font=ctk.CTkFont(size=14, weight="bold"),
            width=30
        )
        self.missing_label.pack(side="left", padx=5)

        # === CHOOSE FOR ME SECTION ===
        self.choose_frame = ctk.CTkFrame(self.main_frame)
        self.choose_frame.grid(row=1, column=0, sticky="ew", pady=(0, 15))

        ctk.CTkLabel(
            self.choose_frame,
            text="Choose For Me!",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(15, 10))

        self.random_btn_frame = ctk.CTkFrame(self.choose_frame, fg_color="transparent")
        self.random_btn_frame.pack(pady=(0, 15))

        ctk.CTkButton(
            self.random_btn_frame,
            text="Random Any",
            width=150,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            command=lambda: self._choose_random("all")
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            self.random_btn_frame,
            text="From My Pantry",
            width=150,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#10b981",
            hover_color="#059669",
            command=lambda: self._choose_random("can_make")
        ).pack(side="left", padx=10)

        ctk.CTkButton(
            self.random_btn_frame,
            text="Almost Ready",
            width=150,
            height=45,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#f59e0b",
            hover_color="#d97706",
            command=lambda: self._choose_random("almost")
        ).pack(side="left", padx=10)

        # === RECIPE LIST ===
        self.recipe_frame = ctk.CTkFrame(self.main_frame)
        self.recipe_frame.grid(row=2, column=0, sticky="nsew")
        self.recipe_frame.grid_columnconfigure(0, weight=1)
        self.recipe_frame.grid_rowconfigure(1, weight=1)

        # Header with count
        self.recipe_header = ctk.CTkFrame(self.recipe_frame, fg_color="transparent")
        self.recipe_header.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 10))

        ctk.CTkLabel(
            self.recipe_header,
            text="Recipes",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left")

        self.recipe_count_label = ctk.CTkLabel(
            self.recipe_header,
            text="0 recipes",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.recipe_count_label.pack(side="right")

        # Scrollable recipe list
        self.recipe_scroll = ctk.CTkScrollableFrame(
            self.recipe_frame,
            fg_color="transparent"
        )
        self.recipe_scroll.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.recipe_scroll.grid_columnconfigure(0, weight=1)

        # Action buttons
        self.action_btn_frame = ctk.CTkFrame(self.recipe_frame, fg_color="transparent")
        self.action_btn_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(5, 15))

        ctk.CTkButton(
            self.action_btn_frame,
            text="Add Recipe",
            width=120,
            command=self._add_recipe_dialog
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            self.action_btn_frame,
            text="Edit Selected",
            width=120,
            fg_color="transparent",
            border_width=1,
            command=self._edit_recipe_dialog
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            self.action_btn_frame,
            text="Delete Selected",
            width=120,
            fg_color="transparent",
            border_width=1,
            hover_color="#ef4444",
            command=self._delete_recipe
        ).pack(side="left", padx=5)

        # Store recipe buttons for selection
        self.recipe_buttons: list[ctk.CTkButton] = []
        self.selected_recipe: str | None = None

    def _get_category_options(self) -> list[str]:
        cats = get_all_categories()
        return ["All"] + sorted(cats) if cats else ["All"]

    def _on_slider_change(self, value: float) -> None:
        """Update slider label and refresh if in almost mode."""
        val = int(value)
        self.missing_label.configure(text=str(val))
        if self.filter_mode_var.get() == "almost":
            self._refresh_recipes()

    def _on_search_change(self, *args) -> None:
        """Debounced search for recipes."""
        if self._search_timer:
            self.after_cancel(self._search_timer)
        self._search_timer = self.after(150, self._refresh_recipes)

    def _on_ing_search_change(self, *args) -> None:
        """Debounced search for ingredients."""
        if self._ing_search_timer:
            self.after_cancel(self._ing_search_timer)
        self._ing_search_timer = self.after(150, self._filter_ingredients)

    def _populate_ingredients(self) -> None:
        """Populate ingredient checkboxes - optimized."""
        # Clear existing
        for widget in self.ing_scroll_frame.winfo_children():
            widget.destroy()
        self.ing_vars.clear()
        self.ing_checkboxes.clear()

        search_term = self.ing_search_var.get().lower()

        # Filter ingredients
        if search_term:
            filtered = [ing for ing in self._all_ingredients if search_term in ing.lower()]
        else:
            filtered = self._all_ingredients

        # Limit display for performance (show first 200)
        display_list = filtered[:200]

        for ing in display_list:
            var = ctk.BooleanVar(value=ing in self.selected_ingredients)
            self.ing_vars[ing] = var

            cb = ctk.CTkCheckBox(
                self.ing_scroll_frame,
                text=ing,
                variable=var,
                command=lambda i=ing: self._on_single_ingredient_toggle(i),
                font=ctk.CTkFont(size=12),
                height=25
            )
            cb.pack(anchor="w", pady=1)
            self.ing_checkboxes.append(cb)

        if len(filtered) > 200:
            ctk.CTkLabel(
                self.ing_scroll_frame,
                text=f"...and {len(filtered) - 200} more (search to find)",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(anchor="w", pady=5)

        self._update_selected_count()

    def _filter_ingredients(self) -> None:
        """Filter ingredient list."""
        self._populate_ingredients()

    def _update_selected_count(self) -> None:
        count = len(self.selected_ingredients)
        self.count_label.configure(text=f"{count} selected")

    def _on_single_ingredient_toggle(self, ingredient: str) -> None:
        """Handle single ingredient toggle - faster than full rebuild."""
        if ingredient in self.ing_vars:
            if self.ing_vars[ingredient].get():
                self.selected_ingredients.add(ingredient)
            else:
                self.selected_ingredients.discard(ingredient)

        save_selected_ingredients(self.selected_ingredients)
        self._update_selected_count()

        if self.filter_mode_var.get() != "all":
            # Debounce recipe refresh
            if self._search_timer:
                self.after_cancel(self._search_timer)
            self._search_timer = self.after(200, self._refresh_recipes)

    def _select_all_visible(self) -> None:
        for ing, var in self.ing_vars.items():
            var.set(True)
            self.selected_ingredients.add(ing)
        save_selected_ingredients(self.selected_ingredients)
        self._update_selected_count()
        if self.filter_mode_var.get() != "all":
            self._refresh_recipes()

    def _clear_ingredients(self) -> None:
        for var in self.ing_vars.values():
            var.set(False)
        self.selected_ingredients.clear()
        save_selected_ingredients(self.selected_ingredients)
        self._update_selected_count()
        if self.filter_mode_var.get() != "all":
            self._refresh_recipes()

    def _on_homemade_toggle(self) -> None:
        """Handle homemade ingredients toggle."""
        self._refresh_recipes()

    def _show_homemade_info(self) -> None:
        """Show info popup about homemade ingredients."""
        status = get_craftable_status(self.selected_ingredients)
        can_make = [s for s in status if s['can_make']]

        popup = ctk.CTkToplevel(self)
        popup.title("Homemade Ingredients")
        popup.geometry("500x500")
        popup.transient(self)
        popup.after(100, lambda: self._safe_grab(popup))

        content = ctk.CTkScrollableFrame(popup, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        ctk.CTkLabel(
            content,
            text="Homemade Ingredients",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(pady=(0, 10))

        ctk.CTkLabel(
            content,
            text="When enabled, recipes that need these ingredients\ncount as 'makeable' since you can make them!",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(pady=(0, 15))

        ctk.CTkLabel(
            content,
            text=f"You can make {len(can_make)} ingredients:",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(10, 5))

        for s in can_make:
            frame = ctk.CTkFrame(content, fg_color="#1f2937", corner_radius=8)
            frame.pack(fill="x", pady=3)

            ctk.CTkLabel(
                frame,
                text=f"✓ {s['name'].title()}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#10b981"
            ).pack(anchor="w", padx=10, pady=(8, 2))

            ctk.CTkLabel(
                frame,
                text=f"From: {', '.join(s['have'][:5])}{'...' if len(s['have']) > 5 else ''}",
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(anchor="w", padx=10, pady=(0, 8))

        ctk.CTkButton(
            content,
            text="Close",
            width=100,
            command=popup.destroy
        ).pack(pady=15)

    def _get_effective_ingredients(self) -> set[str]:
        """Get ingredients including homemade if enabled."""
        if self.include_homemade_var.get():
            return get_effective_ingredients(self.selected_ingredients)
        return self.selected_ingredients

    def _refresh_recipes(self) -> None:
        """Refresh recipe list - optimized with virtual scrolling."""
        query = self.search_var.get()
        category = self.category_var.get()
        filter_mode = self.filter_mode_var.get()
        max_missing = self.max_missing_var.get()

        # Convert diet filter
        diet_raw = self.diet_var.get()
        diet_filter = "" if diet_raw == "All" else diet_raw.lower()

        # Convert time filter
        time_raw = self.time_var.get()
        time_map = {"All": "", "≤10 min": "10-min", "≤30 min": "30-min", "≤60 min": "60-min"}
        time_filter = time_map.get(time_raw, "")

        # Use effective ingredients (includes homemade if enabled)
        effective_ings = self._get_effective_ingredients()

        self._current_results = search_recipes_advanced(
            query=query,
            category=category,
            owned_ingredients=effective_ings,
            filter_mode=filter_mode,
            max_missing=max_missing,
            diet_filter=diet_filter,
            time_filter=time_filter
        )

        # Reset scroll position
        self._visible_start = 0
        self.selected_recipe = None

        # Render visible items
        self._render_visible_recipes()

        total = len(get_all_recipe_names())
        self.recipe_count_label.configure(text=f"{len(self._current_results)} of {total} recipes")

    def _render_visible_recipes(self) -> None:
        """Render only the visible portion of recipes for performance."""
        # Clear existing
        for widget in self.recipe_scroll.winfo_children():
            widget.destroy()
        self.recipe_buttons.clear()
        self._recipe_frames.clear()

        filter_mode = self.filter_mode_var.get()

        # Only render visible items (batch of 50 for smooth scrolling)
        visible_batch = 50
        start = self._visible_start
        end = min(start + visible_batch, len(self._current_results))

        for i, (recipe_name, missing_count) in enumerate(self._current_results[start:end]):
            frame = ctk.CTkFrame(self.recipe_scroll, fg_color="transparent", height=45)
            frame.grid(row=i, column=0, sticky="ew", pady=1)
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_propagate(False)

            # Recipe button
            btn = ctk.CTkButton(
                frame,
                text=recipe_name,
                anchor="w",
                height=38,
                fg_color="transparent",
                hover_color="#374151",
                font=ctk.CTkFont(size=13),
                command=lambda n=recipe_name: self._select_recipe(n)
            )
            btn.grid(row=0, column=0, sticky="ew", padx=(0, 5))

            # Badge for missing count
            if filter_mode == "almost" and missing_count > 0:
                badge = ctk.CTkLabel(
                    frame,
                    text=f"-{missing_count}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    fg_color="#f59e0b",
                    corner_radius=6,
                    width=35,
                    height=24
                )
                badge.grid(row=0, column=1, padx=5)

            # View button
            view_btn = ctk.CTkButton(
                frame,
                text="View",
                width=55,
                height=30,
                font=ctk.CTkFont(size=11),
                command=lambda n=recipe_name: self._show_recipe_popup(n)
            )
            view_btn.grid(row=0, column=2, padx=(0, 5))

            self.recipe_buttons.append(btn)
            self._recipe_frames.append(frame)

        # Add load more button if there are more results
        if end < len(self._current_results):
            remaining = len(self._current_results) - end
            load_more_btn = ctk.CTkButton(
                self.recipe_scroll,
                text=f"Load more ({remaining} remaining)",
                height=40,
                command=self._load_more_recipes
            )
            load_more_btn.grid(row=len(self._recipe_frames), column=0, sticky="ew", pady=10)

        # Update category menu if needed
        if not self._categories_cache or len(self._categories_cache) < 2:
            self._categories_cache = self._get_category_options()
            self.category_menu.configure(values=self._categories_cache)

    def _load_more_recipes(self) -> None:
        """Load more recipes into the list."""
        self._visible_start += 50
        self._render_visible_recipes()

    def _select_recipe(self, name: str) -> None:
        self.selected_recipe = name
        for btn in self.recipe_buttons:
            if btn.cget("text") == name:
                btn.configure(fg_color="#3b82f6")
            else:
                btn.configure(fg_color="transparent")

    def _choose_random(self, mode: str = "all") -> None:
        category = self.category_var.get()
        max_missing = self.max_missing_var.get()
        effective_ings = self._get_effective_ingredients()

        # Get diet and time filters
        diet_raw = self.diet_var.get()
        diet_filter = "" if diet_raw == "All" else diet_raw.lower()
        time_raw = self.time_var.get()
        time_map = {"All": "", "≤10 min": "10-min", "≤30 min": "30-min", "≤60 min": "60-min"}
        time_filter = time_map.get(time_raw, "")

        if mode == "all":
            results = search_recipes_advanced(query="", category=category, owned_ingredients=None, filter_mode="all", diet_filter=diet_filter, time_filter=time_filter)
        elif mode == "can_make":
            results = search_recipes_advanced(query="", category=category, owned_ingredients=effective_ings, filter_mode="can_make", diet_filter=diet_filter, time_filter=time_filter)
        else:
            results = search_recipes_advanced(query="", category=category, owned_ingredients=effective_ings, filter_mode="almost", max_missing=max_missing, diet_filter=diet_filter, time_filter=time_filter)

        if not results:
            messages = {
                "can_make": "No recipes can be made with your current ingredients.\n\nTry adding more ingredients!",
                "almost": "No recipes found that you're close to making.\n\nTry selecting ingredients or increasing max missing!",
                "all": "No recipes match your filters!"
            }
            messagebox.showinfo("No Recipes", messages.get(mode, messages["all"]))
            return

        choice = random.choice(results)
        self._show_recipe_popup(choice[0], is_random=True, random_mode=mode)

    def _safe_grab(self, window) -> None:
        """Safely grab focus for a window."""
        try:
            window.grab_set()
            window.focus_force()
        except Exception:
            pass

    def _show_recipe_popup(self, name: str, is_random: bool = False, random_mode: str = "all") -> None:
        ingredients = get_recipe_ingredients(name) or []
        directions = get_recipe_directions(name) or "No directions yet - add your own!"
        categories = get_recipe_categories(name) or []
        diets = get_recipe_diets(name)
        cook_time, time_cat = get_recipe_time(name)
        effective_ings = self._get_effective_ingredients()
        missing = get_missing_ingredients(name, effective_ings)

        # Create popup
        popup = ctk.CTkToplevel(self)
        popup.title(f"{'Random: ' if is_random else ''}{name}")
        popup.geometry("650x650")
        popup.transient(self)
        popup.after(100, lambda: self._safe_grab(popup))

        # Content
        content = ctk.CTkScrollableFrame(popup, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=30, pady=30)

        if is_random:
            ctk.CTkLabel(
                content,
                text="Tonight's dinner is...",
                font=ctk.CTkFont(size=14),
                text_color="gray"
            ).pack(pady=(0, 10))

        # Title
        ctk.CTkLabel(
            content,
            text=name,
            font=ctk.CTkFont(size=24, weight="bold"),
            wraplength=580
        ).pack(pady=(0, 10))

        # Time badge
        time_text = f"~{cook_time} min" if cook_time < 60 else f"~{cook_time // 60}h {cook_time % 60}m" if cook_time % 60 else f"~{cook_time // 60}h"
        ctk.CTkLabel(
            content,
            text=f"⏱ {time_text}",
            font=ctk.CTkFont(size=12),
            text_color="#9ca3af"
        ).pack(pady=(0, 10))

        # Tags row (categories + diets)
        tags_frame = ctk.CTkFrame(content, fg_color="transparent")
        tags_frame.pack(pady=(0, 15))

        # Categories
        for cat in categories[:4]:
            ctk.CTkLabel(
                tags_frame,
                text=cat,
                font=ctk.CTkFont(size=11),
                fg_color="#3b82f6",
                corner_radius=10,
                padx=10,
                pady=3
            ).pack(side="left", padx=2)

        # Diet badges
        diet_colors = {
            "vegan": "#22c55e",
            "vegetarian": "#84cc16",
            "paleo": "#f97316",
            "keto": "#8b5cf6",
            "carnivore": "#ef4444"
        }
        for diet in diets[:3]:
            ctk.CTkLabel(
                tags_frame,
                text=diet.capitalize(),
                font=ctk.CTkFont(size=11),
                fg_color=diet_colors.get(diet, "#6b7280"),
                corner_radius=10,
                padx=10,
                pady=3
            ).pack(side="left", padx=2)

        # Ingredients first
        if ingredients:
            ctk.CTkLabel(
                content,
                text="Ingredients",
                font=ctk.CTkFont(size=15, weight="bold")
            ).pack(anchor="w", pady=(10, 5))

            ing_text = " • ".join(ingredients)
            ctk.CTkLabel(
                content,
                text=ing_text,
                font=ctk.CTkFont(size=12),
                wraplength=580,
                justify="left"
            ).pack(anchor="w", pady=(0, 10))

            # Missing ingredients
            if missing:
                missing_frame = ctk.CTkFrame(content, fg_color="#7f1d1d", corner_radius=8)
                missing_frame.pack(fill="x", pady=8)
                ctk.CTkLabel(
                    missing_frame,
                    text=f"Missing ({len(missing)}): {', '.join(sorted(missing))}",
                    font=ctk.CTkFont(size=11),
                    text_color="#fca5a5",
                    wraplength=550
                ).pack(padx=12, pady=8)
            else:
                success_frame = ctk.CTkFrame(content, fg_color="#064e3b", corner_radius=8)
                success_frame.pack(fill="x", pady=8)
                ctk.CTkLabel(
                    success_frame,
                    text="You have all the ingredients!",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color="#6ee7b7"
                ).pack(padx=12, pady=8)

        # Directions/How to Make It after ingredients
        ctk.CTkLabel(
            content,
            text="How to Make It",
            font=ctk.CTkFont(size=15, weight="bold")
        ).pack(anchor="w", pady=(10, 5))

        dir_box = ctk.CTkTextbox(content, height=150, font=ctk.CTkFont(size=12))
        dir_box.insert("1.0", directions)
        dir_box.configure(state="disabled")
        dir_box.pack(fill="x", pady=(0, 15))

        # Buttons
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(pady=15)

        if is_random:
            ctk.CTkButton(
                btn_frame,
                text="Pick Another",
                width=120,
                command=lambda m=random_mode: [popup.destroy(), self._choose_random(m)]
            ).pack(side="left", padx=5)

        if missing:
            ctk.CTkButton(
                btn_frame,
                text="Copy Shopping List",
                width=140,
                fg_color="#f59e0b",
                hover_color="#d97706",
                command=lambda: self._copy_to_clipboard(missing)
            ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="Close",
            width=80,
            fg_color="transparent",
            border_width=1,
            command=popup.destroy
        ).pack(side="left", padx=5)

    def _copy_to_clipboard(self, items: set[str]) -> None:
        text = "\n".join(f"• {item}" for item in sorted(items))
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied!", "Shopping list copied to clipboard!")

    def _add_ingredient(self) -> None:
        dialog = ctk.CTkInputDialog(text="Enter ingredient name:", title="Add Ingredient")
        name = dialog.get_input()
        if name and name.strip():
            try:
                add_extra_ingredient(name.strip())
                self.selected_ingredients.add(name.strip())
                save_selected_ingredients(self.selected_ingredients)
                self._all_ingredients = sorted(get_available_ingredients())
                self._populate_ingredients()
                self._refresh_recipes()
                logger.info(f"Added custom ingredient: {name.strip()}")
            except ValidationError as e:
                logger.warning(f"Invalid ingredient rejected: {name.strip()} - {e}")
                messagebox.showerror("Invalid Input", str(e))

    def _remove_ingredient(self) -> None:
        extras = get_extra_ingredients()
        if not extras:
            messagebox.showinfo("No Custom Ingredients", "No custom ingredients to remove.")
            return
        dialog = ctk.CTkInputDialog(
            text=f"Enter ingredient to remove:\n\n{', '.join(sorted(extras))}",
            title="Remove Ingredient"
        )
        name = dialog.get_input()
        if name and name in extras:
            remove_extra_ingredient(name)
            self.selected_ingredients.discard(name)
            save_selected_ingredients(self.selected_ingredients)
            self._all_ingredients = sorted(get_available_ingredients())
            self._populate_ingredients()
            self._refresh_recipes()

    def _add_recipe_dialog(self) -> None:
        dialog = ctk.CTkInputDialog(text="Recipe name:", title="New Recipe")
        name = dialog.get_input()
        if not name:
            return

        dialog = ctk.CTkInputDialog(text="Cooking directions:", title="Directions")
        directions = dialog.get_input()
        if directions is None:
            return

        dialog = ctk.CTkInputDialog(text="Ingredients (comma separated):", title="Ingredients")
        ingredients = dialog.get_input()
        ing_list = [i.strip() for i in (ingredients or "").split(",") if i.strip()]

        dialog = ctk.CTkInputDialog(text="Categories (comma separated):", title="Categories")
        categories = dialog.get_input()
        cat_list = [c.strip() for c in (categories or "").split(",") if c.strip()]

        try:
            add_recipe(name, ing_list, directions or "", cat_list)
            self._all_ingredients = sorted(get_available_ingredients())
            self._categories_cache = self._get_category_options()
            self._populate_ingredients()
            self._refresh_recipes()
            self.category_menu.configure(values=self._categories_cache)
            logger.info(f"Added recipe: {name}")
            messagebox.showinfo("Success!", f"Recipe '{name}' added!")
        except ValidationError as e:
            logger.warning(f"Invalid recipe rejected: {name} - {e}")
            messagebox.showerror("Invalid Input", str(e))

    def _edit_recipe_dialog(self) -> None:
        if not self.selected_recipe:
            messagebox.showinfo("Select Recipe", "Please click a recipe to select it first.")
            return

        name = self.selected_recipe
        current_ings = get_recipe_ingredients(name) or []
        current_dirs = get_recipe_directions(name) or ""
        current_cats = get_recipe_categories(name) or []

        dialog = ctk.CTkInputDialog(text="Cooking directions:", title="Edit Directions")
        new_dirs = dialog.get_input()
        if new_dirs is None:
            return

        dialog = ctk.CTkInputDialog(text=f"Ingredients (current: {', '.join(current_ings)}):", title="Edit Ingredients")
        new_ings = dialog.get_input()
        if new_ings is None:
            return
        ing_list = [i.strip() for i in new_ings.split(",") if i.strip()] if new_ings else current_ings

        dialog = ctk.CTkInputDialog(text=f"Categories (current: {', '.join(current_cats)}):", title="Edit Categories")
        new_cats = dialog.get_input()
        cat_list = [c.strip() for c in (new_cats or "").split(",") if c.strip()] if new_cats else current_cats

        try:
            update_recipe(name, ing_list, new_dirs or current_dirs, cat_list)
            self._all_ingredients = sorted(get_available_ingredients())
            self._categories_cache = self._get_category_options()
            self._populate_ingredients()
            self._refresh_recipes()
            self.category_menu.configure(values=self._categories_cache)
            logger.info(f"Updated recipe: {name}")
            messagebox.showinfo("Success!", f"Recipe '{name}' updated!")
        except ValidationError as e:
            logger.warning(f"Invalid recipe update rejected: {name} - {e}")
            messagebox.showerror("Invalid Input", str(e))

    def _delete_recipe(self) -> None:
        if not self.selected_recipe:
            messagebox.showinfo("Select Recipe", "Please click a recipe to select it first.")
            return

        if messagebox.askyesno("Delete Recipe", f"Delete '{self.selected_recipe}'?"):
            recipe_name = self.selected_recipe
            remove_recipe(self.selected_recipe)
            self.selected_recipe = None
            self._refresh_recipes()
            logger.info(f"Deleted recipe: {recipe_name}")
            messagebox.showinfo("Deleted", "Recipe deleted.")


def run_app() -> None:
    logger.info("Starting What's for Dinner application")
    try:
        app = DinnerApp()
        app.mainloop()
    except Exception as e:
        logger.error(f"Application crashed: {e}", exc_info=True)
        raise
    finally:
        logger.info("Application shutdown")


if __name__ == "__main__":
    run_app()
