# What's for Dinner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Fuzz Tested](https://img.shields.io/badge/fuzz%20tested-3.7M%2B%20payloads-green.svg)](tests/test_kitchen_sink_fuzz.py)
[![Security Gate](https://github.com/techmad220/what-s-for-dinner/actions/workflows/security.yml/badge.svg)](https://github.com/techmad220/what-s-for-dinner/actions/workflows/security.yml)

A recipe manager that helps you discover what you can cook with the ingredients you have. Features 1300+ recipes, smart ingredient matching, and a plugin system for extensibility.

## Quick Start

### Option 1: Download Pre-built Binary (Recommended)

Download the latest release for your platform from the [Releases](https://github.com/techmad220/what-s-for-dinner/releases) page:

- `WhatsForDinner-linux-x64` - Linux
- `WhatsForDinner-windows-x64.exe` - Windows
- `WhatsForDinner-macos-x64` - macOS

**Requirements:** Python 3.11+ with dependencies installed:
```bash
pip install customtkinter Pillow
```

Then double-click the binary to run!

### Option 2: Build from Source

```bash
# One-line build
./build.sh
```

This will:
1. Check for Python 3 and Rust
2. Install Python dependencies from `requirements.txt`
3. Build the Rust launcher
4. Output the binary to `releases/`

### Option 3: Run Python Directly

```bash
pip install -r requirements.txt
python -m dinner_app.gui
```

## Features

- **Smart Ingredient Matching**: Fuzzy matching finds recipes even with slight ingredient variations
- **Pantry Mode**: See what you can make with just the ingredients you have
- **Category Filtering**: Browse by cuisine type, meal category, or cooking method
- **Craftable Ingredients**: Mark items like sauces or doughs as "homemade" to count their components
- **Random Recipe**: Get a random suggestion from recipes you can make
- **Shopping List Export**: See what ingredients you're missing for any recipe

## Architecture

```
what-s-for-dinner/
├── dinner_app/          # Python application (the actual app)
│   ├── gui.py           # GUI implementation (CustomTkinter)
│   ├── recipes.py       # Recipe database and logic
│   └── *.json           # Data files
├── launcher/            # Rust wrapper (PyO3)
│   ├── Cargo.toml       # Rust dependencies
│   └── src/main.rs      # Embeds Python, loads plugins
├── releases/            # Pre-built binaries
├── build.sh             # One-line build script
└── requirements.txt     # Python dependencies
```

### How the Launcher Works

The Rust launcher uses [PyO3](https://pyo3.rs) to embed Python:

1. **Compile time**: The `dinner_app/` folder is embedded into the binary
2. **Runtime**: Extracts files to `~/.local/share/WhatsForDinner/`
3. **Plugins**: Loads any `plugin_*.py` files from the plugins folder
4. **Execution**: Calls `dinner_app.gui.run_app()` via PyO3

Benefits over PyInstaller:
- Smaller binaries (~2MB vs 50MB+)
- Plugin system for extensibility
- More reliable than Python-to-exe converters

## Plugins

Extend the app with Python plugins. No Rust knowledge required!

**Plugin location:** `~/.local/share/WhatsForDinner/plugins/`

### Example: Add Custom Recipes

```python
# plugin_my_recipes.py
from dinner_app.recipes import _recipes

_recipes["My Secret Recipe"] = {
    "ingredients": ["Ingredient 1", "Ingredient 2"],
    "instructions": "1. Do this\n2. Do that",
    "category": "Dinner"
}
print("Loaded my custom recipes!")
```

### Example: Auto-backup

```python
# plugin_backup.py
import shutil
from pathlib import Path
from datetime import datetime

data_dir = Path.home() / ".local/share/WhatsForDinner"
backup_dir = data_dir / "backups"
backup_dir.mkdir(exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
src = data_dir / "dinner_app/selected_ingredients.json"
if src.exists():
    shutil.copy(src, backup_dir / f"ingredients_{timestamp}.json")
```

## Development

### Prerequisites

- Python 3.11+
- Rust (install from [rustup.rs](https://rustup.rs))
- Python development headers (`python3-dev` on Linux)

### Building

```bash
# Build for current platform
./build.sh

# Or manually:
pip install -r requirements.txt
cd launcher && cargo build --release
```

### Running Tests

```bash
python -m pytest
```

## Security

We take security seriously. This application implements:

- **Input Validation**: All user inputs sanitized (XSS, injection prevention)
- **Path Traversal Protection**: Safe file handling with validation
- **Plugin Security**: Static analysis before loading plugins
- **Secure Logging**: Rotating logs without sensitive data

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Please report via [GitHub Security Advisories](https://github.com/techmad220/what-s-for-dinner/security/advisories)
or see [SECURITY.md](SECURITY.md) for our full Vulnerability Disclosure Policy.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

### Quick Start for Contributors

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Set up pre-commit hooks (required)
pre-commit install

# Run quality checks
ruff check dinner_app/ tests/
bandit -r dinner_app/ -ll
pytest tests/ -v
```

### What You Can Contribute

1. **Add recipes**: Edit `dinner_app/recipes.json`
2. **Create plugins**: Add `plugin_*.py` to extend functionality
3. **Improve the app**: Submit PRs for `dinner_app/` (Python) or `launcher/` (Rust)

All PRs must pass:
- Linting (ruff)
- Security scan (bandit)
- Secrets detection
- All tests

## License

MIT Non-Commercial - See [LICENSE](LICENSE) for details.

---

## Disclaimer of Warranty and Limitation of Liability

**IMPORTANT: BY DOWNLOADING, INSTALLING, USING, OR OTHERWISE ACCESSING THIS SOFTWARE, YOU ACKNOWLEDGE THAT YOU HAVE READ, UNDERSTOOD, AND AGREE TO BE BOUND BY THE FOLLOWING TERMS:**

### NO WARRANTY

THIS SOFTWARE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH YOU.

THE AUTHOR(S) AND COPYRIGHT HOLDER(S) MAKE NO REPRESENTATIONS OR WARRANTIES THAT:
- The software will meet your requirements
- The software will be uninterrupted, timely, secure, or error-free
- The results obtained from the software will be accurate or reliable
- Any errors in the software will be corrected
- The software is free of viruses or other harmful components

### LIMITATION OF LIABILITY

IN NO EVENT SHALL THE AUTHOR(S), COPYRIGHT HOLDER(S), OR ANY CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, CONSEQUENTIAL, OR PUNITIVE DAMAGES (INCLUDING BUT NOT LIMITED TO PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; BUSINESS INTERRUPTION; PERSONAL INJURY; PROPERTY DAMAGE; OR ANY OTHER PECUNIARY LOSS) ARISING OUT OF OR IN CONNECTION WITH THE USE OR INABILITY TO USE THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

THIS LIMITATION APPLIES TO:
- Claims based on contract, tort (including negligence), strict liability, or any other legal theory
- Claims arising from recipe accuracy, ingredient information, dietary restrictions, or food safety
- Claims arising from data loss, corruption, or unauthorized access
- Claims arising from plugin behavior or third-party code

### ASSUMPTION OF RISK

You expressly acknowledge and agree that:
1. Use of this software is entirely at your own risk
2. You are solely responsible for any damage to your computer system or loss of data
3. Recipe information is provided for convenience only and should not be relied upon for dietary, medical, or safety decisions
4. You should always verify ingredient safety, allergens, and cooking instructions from authoritative sources
5. This software is not intended as a substitute for professional culinary, nutritional, or medical advice

### BINDING AGREEMENT

By using this software, you acknowledge that you have read this disclaimer, understand it, and agree to be bound by its terms. If you do not agree to these terms, you must not use, download, or install this software.

### SEVERABILITY

If any provision of this disclaimer is held to be unenforceable or invalid, such provision shall be modified to the minimum extent necessary to make it enforceable, and the remaining provisions shall continue in full force and effect.

### GOVERNING LAW

This disclaimer shall be governed by and construed in accordance with applicable law, without regard to conflicts of law principles.
