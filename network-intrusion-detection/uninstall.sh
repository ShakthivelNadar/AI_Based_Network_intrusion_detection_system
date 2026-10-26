#!/usr/bin/env bash
set -euo pipefail
rm -f "$HOME/.local/bin/network-intrusion-detection"
rm -f "$HOME/.local/share/applications/network-intrusion-detection.desktop"
echo "Launcher removed. Project files and local incident database were not deleted."
echo "To remove the database manually, delete ~/.local/share/network-intrusion-detection/"
