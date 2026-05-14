#!/usr/bin/env bash
# Gatecrash one-shot installer — clones the repo into /opt and runs setup.sh.
# Designed to be invoked by DietPi's AUTO_SETUP_CUSTOM_SCRIPT_EXEC, but works
# anywhere as a fresh install.
#
# Usage on DietPi: set in /boot/dietpi.txt (one line, no continuations):
#   AUTO_SETUP_CUSTOM_SCRIPT_EXEC=https://raw.githubusercontent.com/HoratioConkerhead/gatecrash/master/install.sh

set -euo pipefail

REPO_OWNER="HoratioConkerhead"
REPO_NAME="gatecrash"
# Repo lives separately from /opt/gatecrash (the install target). setup.sh
# copies runtime bits from REPO_DIR into /opt/gatecrash; if they were the
# same path, cp would fail with "are the same file".
REPO_DIR="/opt/gatecrash-src"
BRANCH="${GATECRASH_BRANCH:-master}"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root (sudo bash install.sh)." >&2
    exit 1
fi

echo "=== Gatecrash installer ==="

CLONE_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"

# git is required — install if missing
if ! command -v git >/dev/null 2>&1; then
    echo "Installing git..."
    apt-get update -q
    apt-get install -y git
fi

# Clone (or update) the repo
if [[ -d "$REPO_DIR/.git" ]]; then
    echo "Repo already exists at $REPO_DIR — pulling latest."
    git -C "$REPO_DIR" fetch --depth=1 origin "$BRANCH"
    git -C "$REPO_DIR" reset --hard "origin/$BRANCH"
else
    echo "Cloning $REPO_OWNER/$REPO_NAME ($BRANCH) into $REPO_DIR..."
    git clone --depth=1 -b "$BRANCH" "$CLONE_URL" "$REPO_DIR"
fi

# Hand off to setup.sh — it copies the runtime bits into /opt/gatecrash
echo "Running setup.sh..."
bash "$REPO_DIR/setup.sh"

echo ""
echo "=== Gatecrash install complete ==="
echo "Open the web UI at http://gatecrash.local to finish configuration."

# On DietPi first-boot, AUTO_SETUP_CUSTOM_SCRIPT_EXEC runs this script as root,
# and DietPi's automated install leaves an auto-login root session on tty1.
# Reboot to close that session. Only fires on DietPi (detected by /boot/dietpi.txt)
# so manual invocations on other systems don't get a surprise reboot.
# Override with GATECRASH_NO_REBOOT=1.
if [[ -f /boot/dietpi.txt && "${GATECRASH_NO_REBOOT:-0}" != "1" ]]; then
    echo ""
    echo "DietPi first-boot detected — rebooting in 10s to clear the root auto-login."
    echo "Set GATECRASH_NO_REBOOT=1 to skip. Ctrl+C to cancel."
    sleep 10
    systemctl reboot
fi
