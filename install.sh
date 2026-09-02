#!/usr/bin/env bash
# LANShare installer for Linux / macOS.
#
# Modern distributions (Arch, Debian 12+, Ubuntu 23.04+, Fedora 38+) mark the
# system Python as "externally managed" (PEP 668) and refuse `pip install`.
# That is deliberate and worth respecting, so this script installs into a
# project-local virtual environment instead. The venv is created with
# --system-site-packages, so if your distro already ships PySide6 or
# cryptography those are reused rather than downloaded again -- which on Arch
# also gets you Qt that matches your system Wayland stack.
#
#   ./install.sh              # CLI + desktop GUI
#   ./install.sh --cli-only   # no GUI toolkit
#   ./install.sh --desktop    # also add a .desktop launcher entry

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

WANT_GUI=1
WANT_DESKTOP=0
for arg in "$@"; do
    case "$arg" in
        --cli-only) WANT_GUI=0 ;;
        --desktop)  WANT_DESKTOP=1 ;;
        -h|--help)  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }

PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[ -n "$PY" ] || { echo "No python3 found. Install Python 3.8 or newer." >&2; exit 1; }

if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "Python 3.8+ required; found $("$PY" --version 2>&1)" >&2
    exit 1
fi

# --- offer the native packages first, where they exist ----------------------
# On Arch the distro packages integrate better with the system Qt/Wayland than
# the PyPI wheels do, and they keep everything under the package manager.
if [ "$WANT_GUI" -eq 1 ] && command -v pacman >/dev/null 2>&1; then
    missing=()
    "$PY" -c 'import PySide6'      2>/dev/null || missing+=("pyside6")
    "$PY" -c 'import cryptography' 2>/dev/null || missing+=("python-cryptography")
    if [ "${#missing[@]}" -gt 0 ]; then
        say "Arch detected. The smoothest install uses your package manager:"
        echo
        echo "    sudo pacman -S --needed ${missing[*]} qt6-wayland"
        echo
        echo "  Then just run:  python -m lanshare gui"
        echo "  (qt6-wayland is what lets Qt run natively under Hyprland/Sway.)"
        echo
        read -r -p "Continue with a local virtual environment instead? [y/N] " reply
        case "$reply" in [yY]*) ;; *) exit 0 ;; esac
    fi
fi

# --- virtual environment ----------------------------------------------------
VENV="$HERE/.venv"
if [ ! -d "$VENV" ]; then
    say "Creating virtual environment in .venv (reusing system packages where present)"
    "$PY" -m venv --system-site-packages "$VENV" \
        || { echo "venv creation failed. On Debian/Ubuntu: sudo apt install python3-venv" >&2; exit 1; }
fi

VPY="$VENV/bin/python"
say "Installing dependencies"
"$VPY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
if [ "$WANT_GUI" -eq 1 ]; then
    "$VPY" -m pip install --quiet -e ".[gui]"
else
    "$VPY" -m pip install --quiet -e .
fi

# --- optional desktop entry -------------------------------------------------
if [ "$WANT_DESKTOP" -eq 1 ] && [ "$WANT_GUI" -eq 1 ]; then
    APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    mkdir -p "$APPS"
    cat > "$APPS/lanshare.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=LANShare
Comment=Send files to devices on your local network
Exec=$VENV/bin/lanshare gui
Icon=network-transmit-receive
Terminal=false
Categories=Network;FileTransfer;Utility;
Keywords=file;share;transfer;lan;network;
EOF
    command -v update-desktop-database >/dev/null 2>&1 \
        && update-desktop-database "$APPS" >/dev/null 2>&1 || true
    say "Desktop entry installed (search 'LANShare' in your launcher)"
fi

# --- done -------------------------------------------------------------------
echo
say "Installed."
echo
echo "  Run it:"
echo "      $VENV/bin/lanshare gui        # desktop app"
echo "      $VENV/bin/lanshare --help     # command line"
echo
echo "  Or put it on your PATH for this shell:"
echo "      source $VENV/bin/activate && lanshare gui"
echo

if [ "$WANT_GUI" -eq 1 ] && [ -n "${WAYLAND_DISPLAY:-}" ]; then
    if ! "$VPY" -c 'import PySide6' 2>/dev/null; then
        warn "PySide6 is not importable; the GUI will not start."
    else
        echo "  Wayland session detected. If the window fails to open with a"
        echo "  'could not load the Qt platform plugin' error, either install"
        echo "  qt6-wayland, or fall back to XWayland with:"
        echo "      QT_QPA_PLATFORM=xcb $VENV/bin/lanshare gui"
        echo
    fi
fi
