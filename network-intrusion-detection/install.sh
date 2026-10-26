#!/usr/bin/env bash
set -euo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$APP_DIR/.venv"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="$HOME/.local/share/applications"
echo "[1/5] Checking OS packages..."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip python3-dev build-essential git
echo "[2/5] Creating isolated Python environment..."
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip wheel
echo "[3/5] Installing Python dependencies..."
"$VENV/bin/pip" install -r "$APP_DIR/requirements.txt"
echo "[4/5] Installing launcher command..."
mkdir -p "$BIN_DIR" "$DESKTOP_DIR"
cat > "$BIN_DIR/network-intrusion-detection" <<EOF
#!/usr/bin/env bash
APP_DIR="$APP_DIR"
exec "\$APP_DIR/.venv/bin/streamlit" run "\$APP_DIR/app.py" --server.address 127.0.0.1 --browser.gatherUsageStats false "\$@"
EOF
chmod +x "$BIN_DIR/network-intrusion-detection"
cat > "$DESKTOP_DIR/network-intrusion-detection.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Network Intrusion Detection
Comment=AI-based network security monitoring console
Exec=$BIN_DIR/network-intrusion-detection
Terminal=true
Categories=Security;Development;
EOF
echo "[5/5] Done."
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "Add this line to ~/.bashrc if the command is not found:"
  echo 'export PATH="$HOME/.local/bin:$PATH"'
  echo "Then run: source ~/.bashrc"
fi
echo
echo "Launch with: network-intrusion-detection"
echo "The dashboard will open in your browser at http://127.0.0.1:8501"
