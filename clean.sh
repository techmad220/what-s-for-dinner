#!/bin/bash
# Clean up build artifacts and development files
# Keeps only what's needed to run the pre-built binary

set -e

echo "=== What's for Dinner - Cleanup Script ==="
echo ""
echo "This will remove build artifacts and dev files."
echo "The pre-built binary in releases/ will be kept."
echo ""

# Check if binary exists
if [ ! -f "releases/WhatsForDinner-linux-x64" ] && \
   [ ! -f "releases/WhatsForDinner-windows-x64.exe" ] && \
   [ ! -f "releases/WhatsForDinner-macos-x64" ]; then
    echo "WARNING: No pre-built binary found in releases/"
    echo "Run ./build.sh first, or download from GitHub releases."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "Removing..."

# Rust build artifacts (largest)
if [ -d "launcher/target" ]; then
    echo "  - launcher/target/ (Rust build cache)"
    rm -rf launcher/target
fi

# Python cache
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
echo "  - Python cache files"

# Virtual environment
if [ -d ".venv" ]; then
    echo "  - .venv/ (Python virtual environment)"
    rm -rf .venv
fi

# Cargo lock (will regenerate on next build)
if [ -f "launcher/Cargo.lock" ]; then
    echo "  - launcher/Cargo.lock"
    rm -f launcher/Cargo.lock
fi

echo ""
echo "=== Cleanup Complete ==="
echo ""

# Show remaining size
TOTAL=$(du -sh . 2>/dev/null | cut -f1)
echo "Remaining project size: $TOTAL"
echo ""
echo "To run the app, use the binary in releases/"
echo "To rebuild, run ./build.sh"
