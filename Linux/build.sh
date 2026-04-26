#!/usr/bin/env bash
# build.sh — Build the Linux VPN binary with PyInstaller.
#
# Usage (from project root or Linux/ folder):
#   bash Linux/build.sh
#
# Requirements:
#   pip install pyinstaller cryptography h2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APP_EXE_NAME="VPN"
ASSETS_DIR="$SCRIPT_DIR/assets"
ICON="$ASSETS_DIR/vpn.ico"
CONFIG_EXAMPLE="$SCRIPT_DIR/config.example.json"

mkdir -p "$ASSETS_DIR"

cd "$SCRIPT_DIR"

pyinstaller \
    --noconfirm \
    --clean \
    --onefile \
    --noconsole \
    --name "$APP_EXE_NAME" \
    --icon "$ICON" \
    --hidden-import cryptography \
    --hidden-import h2 \
    --add-data "$CONFIG_EXAMPLE:." \
    gui_app_linux.py

echo "Build successful. Output: $SCRIPT_DIR/dist/$APP_EXE_NAME"
