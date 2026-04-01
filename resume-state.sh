#!/bin/bash
# Resume Gatecrash/WireGuard based on last known state before shutdown.
# Only acts when boot mode is "resume" in boot_state.json.

STATE_FILE="/opt/gatecrash/boot_state.json"

if [ ! -f "$STATE_FILE" ]; then
    exit 0
fi

MODE=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('mode',''))" 2>/dev/null)
if [ "$MODE" != "resume" ]; then
    exit 0
fi

WG_RUNNING=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('wg_running', False))" 2>/dev/null)
GC_RUNNING=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('gc_running', False))" 2>/dev/null)

if [ "$WG_RUNNING" = "True" ]; then
    echo "Resuming WireGuard..."
    wg-quick up wg0 2>&1 || true
fi

if [ "$GC_RUNNING" = "True" ]; then
    echo "Resuming Gatecrash..."
    systemctl start gatecrash 2>&1 || true
fi
