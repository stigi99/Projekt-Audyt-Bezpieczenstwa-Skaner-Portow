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

echo "Installing PyInstaller and runtime dependencies into virtualenv..."
pip install -U pip
pip install -r "$ROOT_DIR/requirements.txt"
pip install -r "$ROOT_DIR/requirements-dev.txt"
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

# Try to include Qt plugins (platforms and imageformats) for PySide6 if present
PLUGIN_DIR=$("$VENVDIR/bin/python" - <<'PY'
import PySide6, os
p = os.path.join(os.path.dirname(PySide6.__file__), 'Qt', 'plugins')
print(p)
PY
)
if [ -d "$PLUGIN_DIR" ]; then
  echo "Found PySide6 plugin dir: $PLUGIN_DIR"
  # include only the platforms and imageformats directories to avoid heavier optional plugins (sql/qml)
  if [ -d "$PLUGIN_DIR/platforms" ]; then
    DATA_ARGS+=(--add-binary "$PLUGIN_DIR/platforms:PySide6/Qt/plugins/platforms")
  fi
  if [ -d "$PLUGIN_DIR/imageformats" ]; then
    DATA_ARGS+=(--add-binary "$PLUGIN_DIR/imageformats:PySide6/Qt/plugins/imageformats")
  fi
fi

# Hidden imports and collect-all for PySide6 to ensure all Qt plugins are packaged
HIDDEN_ARGS=(--hidden-import=scapy.all --hidden-import=scapy)

# Exclude optional PySide6 modules that require external frameworks (Postgres, mimer) or QML
EXCLUDE_ARGS=(--exclude-module=PySide6.QtQuick --exclude-module=PySide6.QtQml --exclude-module=PySide6.QtSql --exclude-module=PySide6.QtQuickWidgets)

if [ "${CREATE_APP_BUNDLE:-false}" = "true" ]; then
  echo "Building macOS .app bundle via PyInstaller"
  pyinstaller --onefile --windowed --noconfirm --clean --name "$APP_NAME.app" "${HIDDEN_ARGS[@]}" "${EXCLUDE_ARGS[@]}" "${DATA_ARGS[@]}" "$SRC_SCRIPT"
  BUNDLE_PATH="$DIST_DIR/$APP_NAME.app"
else
  pyinstaller --onefile --noconfirm --clean --name "$APP_NAME" "${HIDDEN_ARGS[@]}" "${EXCLUDE_ARGS[@]}" "${DATA_ARGS[@]}" "$SRC_SCRIPT"
  BUNDLE_PATH="$DIST_DIR/$APP_NAME"
fi

if [ -e "$BUNDLE_PATH" ]; then
  echo "Build complete: $BUNDLE_PATH"
  echo "You can run it: $BUNDLE_PATH"
else
  echo "Build failed; check pyinstaller logs in $BUILD_DIR for details."
  exit 1
fi

# Optionally create a DMG for macOS and sign the binary
if [ "${CREATE_DMG:-false}" = "true" ]; then
  if [[ "$(uname)" != "Darwin" ]]; then
    echo "CREATE_DMG is macOS-only; skipping DMG creation on non-Darwin host."
  else
  echo "CREATE_DMG requested. Creating DMG..."
  BIN_PATH="$BUNDLE_PATH"
  SIGN_IDENTITY="${SIGN_IDENTITY:-}"
  if [ -n "${CI_SIGNING_P12:-}" ] && [ -n "${CI_SIGNING_PASSWORD:-}" ]; then
    echo "CI signing credentials provided; importing certificate to temporary keychain"
    KEYCHAIN_NAME="build_ci_keychain"
    security create-keychain -p "" "$KEYCHAIN_NAME"
    security set-keychain-settings -lut 21600 "$KEYCHAIN_NAME"
    echo "$CI_SIGNING_P12" | base64 --decode > /tmp/ci_signing.p12
    security import /tmp/ci_signing.p12 -k "$KEYCHAIN_NAME" -P "$CI_SIGNING_PASSWORD" -T /usr/bin/codesign
    security list-keychains -s "$KEYCHAIN_NAME"
    security unlock-keychain -p "" "$KEYCHAIN_NAME"
    SIGN_IDENTITY=$(security find-identity -p codesigning -v | awk -F '"' 'NR==1{print $2}')
  fi

  chmod +x scripts/create_dmg.sh
  scripts/create_dmg.sh "$BIN_PATH" --name "$APP_NAME" --sign "$SIGN_IDENTITY"

  # Clean up temporary CI keychain if created
  if [ -n "${KEYCHAIN_NAME:-}" ]; then
    echo "Cleaning up temporary keychain $KEYCHAIN_NAME"
    security delete-keychain "$KEYCHAIN_NAME" || true
  fi
  fi
fi
