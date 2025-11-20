#!/usr/bin/env bash
set -euo pipefail

# Build a standalone executable using PyInstaller
# Usage: ./scripts/build_pyinstaller.sh

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENVDIR="$ROOT_DIR/.venv"

if [ ! -f "$VENVDIR/bin/activate" ]; then
  echo "Virtualenv not found. Create it first: python3 -m venv .venv && source .venv/bin/activate"
  exit 1
fi

echo "Activating venv..."
source "$VENVDIR/bin/activate"

echo "Installing PyInstaller into virtualenv..."
pip install -U pip
pip install pyinstaller

APP_NAME="pab_scanner"
SRC_SCRIPT="$ROOT_DIR/Projekt AB Skaner Portów.py"
DIST_DIR="$ROOT_DIR/dist"
BUILD_DIR="$ROOT_DIR/build"

echo "Cleaning previous build artifacts..."
rm -rf "$DIST_DIR" "$BUILD_DIR" "${APP_NAME}.spec"

echo "Running PyInstaller (this may take a while)..."

# Include data with colon-separated path for Unix (format: src:dest)
DATA_ARGS=(--add-data "$ROOT_DIR/docs/_static/screenshots:docs/_static/screenshots")

# Hidden imports and collect-all for PySide6 to ensure all Qt plugins are packaged
HIDDEN_ARGS=(--hidden-import scapy.all --hidden-import scapy --collect-all PySide6 --collect-all scapy)

pyinstaller --onefile --noconfirm --clean --name "$APP_NAME" "${HIDDEN_ARGS[@]}" "${DATA_ARGS[@]}" "$SRC_SCRIPT"

if [ -f "$DIST_DIR/$APP_NAME" ]; then
  echo "Build complete: $DIST_DIR/$APP_NAME"
  echo "You can run it: $DIST_DIR/$APP_NAME"
else
  echo "Build failed; check pyinstaller logs in $BUILD_DIR for details."
  exit 1
fi
