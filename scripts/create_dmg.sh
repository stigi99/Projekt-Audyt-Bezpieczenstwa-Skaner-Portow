#!/usr/bin/env bash
set -euo pipefail

# Create a DMG from a built macOS executable
# Usage: scripts/create_dmg.sh <path-to-binary> [--name NAME] [--sign SIGN_IDENTITY]

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <path-to-binary> [--name NAME] [--sign SIGN_IDENTITY]"
  exit 1
fi

BIN_PATH="$1"
shift

VOLUME_NAME="PAB Scanner"
SIGN_IDENTITY=""

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --name)
      VOLUME_NAME="$2"
      shift; shift
      ;;
    --sign)
      SIGN_IDENTITY="$2"
      shift; shift
      ;;
    *)
      echo "Unknown option $1"
      exit 1
      ;;
  esac
done

if [ ! -f "$BIN_PATH" ]; then
  echo "Binary not found: $BIN_PATH"
  exit 1
fi

if [[ "$(uname)" != "Darwin" ]]; then
  echo "DMG creation is only supported on macOS (Darwin). Skipping."
  exit 0
fi

OUT_DIR="$(dirname "$BIN_PATH")/dmg"
mkdir -p "$OUT_DIR"

APP_NAME="$(basename "$BIN_PATH")"
DMG_NAME="$OUT_DIR/${APP_NAME%.app}.dmg"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Copy binary
mkdir -p "$TMPDIR/$VOLUME_NAME"
cp -R "$BIN_PATH" "$TMPDIR/$VOLUME_NAME/"

# Optionally codesign the binary before packing
if [ -n "$SIGN_IDENTITY" ]; then
  echo "Codesigning binary with identity: $SIGN_IDENTITY"
  # On macOS, ensure code signing runtime flags
  codesign --deep --force --verbose --options runtime -s "$SIGN_IDENTITY" "$TMPDIR/$VOLUME_NAME/$APP_NAME"
fi

# Create the DMG
echo "Creating DMG: $DMG_NAME"
hdiutil create -volname "$VOLUME_NAME" -srcfolder "$TMPDIR/$VOLUME_NAME" -ov -format UDZO "$DMG_NAME"

# Optionally sign the DMG as well
if [ -n "$SIGN_IDENTITY" ]; then
  echo "Codesigning DMG: $DMG_NAME"
  codesign --force --sign "$SIGN_IDENTITY" "$DMG_NAME"
fi

ls -lh "$DMG_NAME"
echo "DMG created at: $DMG_NAME"
exit 0
