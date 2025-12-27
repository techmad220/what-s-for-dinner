#!/bin/bash
set -e

echo "=== What's for Dinner - Build Script ==="
echo ""

# Detect OS
OS="unknown"
case "$(uname -s)" in
    Linux*)  OS="linux";;
    Darwin*) OS="macos";;
    MINGW*|MSYS*|CYGWIN*) OS="windows";;
esac

ARCH="$(uname -m)"
if [ "$ARCH" = "x86_64" ]; then
    ARCH="x64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
fi

echo "Detected: $OS-$ARCH"
echo ""

# Check dependencies
echo "Checking dependencies..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is required but not installed."
    echo "Install it from https://python.org or your package manager."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "  Python $PYTHON_VERSION found"

# Check Rust
if ! command -v cargo &> /dev/null; then
    echo "ERROR: Rust/Cargo is required but not installed."
    echo "Install it from https://rustup.rs"
    exit 1
fi

RUST_VERSION=$(rustc --version | cut -d' ' -f2)
echo "  Rust $RUST_VERSION found"

# Check for python-dev headers
echo ""
echo "Checking Python development headers..."
if [ "$OS" = "linux" ]; then
    if ! python3 -c "import sysconfig; exit(0 if sysconfig.get_path('include') else 1)" 2>/dev/null; then
        echo "WARNING: Python dev headers may be missing."
        echo "Install with: sudo apt-get install python3-dev"
    fi
fi

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip3 install -r requirements.txt --quiet

# Build Rust launcher
echo ""
echo "Building Rust launcher (release mode)..."
cd launcher
cargo build --release

# Copy binary to releases folder
echo ""
echo "Copying binary to releases folder..."
cd ..
mkdir -p releases

if [ "$OS" = "windows" ]; then
    BINARY_NAME="WhatsForDinner-windows-$ARCH.exe"
    cp launcher/target/release/WhatsForDinner.exe "releases/$BINARY_NAME"
elif [ "$OS" = "macos" ]; then
    BINARY_NAME="WhatsForDinner-macos-$ARCH"
    cp launcher/target/release/WhatsForDinner "releases/$BINARY_NAME"
    chmod +x "releases/$BINARY_NAME"
else
    BINARY_NAME="WhatsForDinner-linux-$ARCH"
    cp launcher/target/release/WhatsForDinner "releases/$BINARY_NAME"
    chmod +x "releases/$BINARY_NAME"
fi

echo ""
echo "=== Build Complete ==="
echo "Binary: releases/$BINARY_NAME"
echo ""
echo "To run: ./releases/$BINARY_NAME"
echo ""
