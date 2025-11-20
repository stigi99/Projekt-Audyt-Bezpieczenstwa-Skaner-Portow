#!/usr/bin/env bash
set -euo pipefail

# Build a standalone executable using Nuitka
# Usage: ./scripts/build_nuitka.sh

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENVDIR="$ROOT_DIR/.venv"

if [ ! -f "$VENVDIR/bin/activate" ]; then
  echo "Virtualenv not found. Create it first: python3 -m venv .venv && source .venv/bin/activate"
  exit 1
fi

echo "Activating venv..."
source "$VENVDIR/bin/activate"

echo "Installing Nuitka into virtualenv..."
pip install -U pip
pip install nuitka

APP_NAME="pab_scanner_nuitka"
SRC_SCRIPT="$ROOT_DIR/run_scanner.py"
DIST_DIR="$ROOT_DIR/dist_nuitka"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "Running Nuitka (this may take a while)..."
# --standalone is necessary to include dependencies, --onefile for a single executable
python -m nuitka --standalone --onefile --output-dir="$DIST_DIR" --python-flag=no_site --enable-plugin=pyside --include-package=scapy --include-package=PySide6 "$SRC_SCRIPT"

echo "Nuitka build complete: check $DIST_DIR for the produced executable."
