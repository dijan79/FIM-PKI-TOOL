#!/usr/bin/env bash
# =============================================================================
# setup.sh — One-command environment setup for FIM-PKI Sentinel
# Author: Dijan Ghale
#
# What this does:
#   1. Checks for Python 3.10+
#   2. Creates a virtual environment (./venv)
#   3. Installs dependencies from requirements.txt
#   4. Creates required runtime folders (keys/certs/logs/CSV_logs/data)
#   5. Optionally launches the application
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
# =============================================================================

set -e

echo "============================================================"
echo "  FIM-PKI Sentinel — Setup"
echo "  Author: Dijan Ghale"
echo "============================================================"

# --- 1. Check Python -------------------------------------------------------
if ! command -v python3 &> /dev/null; then
    echo "❌ python3 not found. Please install Python 3.10+ and re-run this script."
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
echo "✔ Found Python $PY_VERSION"

# --- 2. Check Tkinter availability -----------------------------------------
if ! python3 -c "import tkinter" &> /dev/null; then
    echo "⚠ Tkinter is not installed for this Python interpreter."
    echo "  Linux:   sudo apt install python3-tk"
    echo "  macOS:   tkinter ships with python.org installers (reinstall Python from python.org if needed)"
    echo "  Windows: tkinter ships with the official Python installer by default"
    echo "  Continuing setup, but the GUI will not launch until this is resolved."
fi

# --- 3. Create virtual environment ------------------------------------------
if [ ! -d "venv" ]; then
    echo "→ Creating virtual environment in ./venv ..."
    python3 -m venv venv
else
    echo "✔ Virtual environment already exists."
fi

# shellcheck disable=SC1091
source venv/bin/activate

# --- 4. Install dependencies ------------------------------------------------
echo "→ Installing dependencies from requirements.txt ..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "✔ Dependencies installed."

# --- 5. Create runtime directories ------------------------------------------
echo "→ Preparing runtime directories ..."
mkdir -p keys certs logs CSV_logs data
echo "✔ Directories ready: keys/ certs/ logs/ CSV_logs/ data/"

# --- 6. Done -----------------------------------------------------------------
echo "============================================================"
echo "  Setup complete."
echo "============================================================"
echo ""
read -r -p "Launch FIM-PKI Sentinel now? [y/N] " choice
case "$choice" in
    y|Y )
        python fim_gui.py
        ;;
    * )
        echo "You can launch it later with:"
        echo "    source venv/bin/activate"
        echo "    python fim_gui.py"
        ;;
esac
