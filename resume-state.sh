#!/bin/bash
# Resume Gatecrash/WireGuard based on last known state before shutdown.
# Only acts when boot mode is "resume" in boot_state.json.

STATE_FILE="/opt/gatecrash/boot_state.json"
LOG="/var/log/gatecrash.log"

log() { printf '%s  %-5s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >> "$LOG"; }

if [ ! -f "$STATE_FILE" ]; then
    exit 0
fi

MODE=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('mode',''))" 2>/dev/null)
if [ "$MODE" != "resume" ]; then
    log INFO "SERVICE resume-state.sh: invoked (boot mode: noresume)"
    exit 0
fi

log INFO "SERVICE resume-state.sh: invoked (boot mode: resume)"

WG_RUNNING=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('wg_running', False))" 2>/dev/null)
GC_RUNNING=$(python3 -c "import json; print(json.load(open('$STATE_FILE')).get('gc_running', False))" 2>/dev/null)

if [ "$WG_RUNNING" = "true" ]; then
    echo "Resuming WireGuard..."
    log INFO "SERVICE resume-state.sh: Resuming WireGuard (was running before shutdown)"
    wg-quick up wg0 2>&1 || true
else
    log INFO "SERVICE resume-state.sh: WireGuard was not running before shutdown, skipping"
fi

if [ "$GC_RUNNING" = "true" ]; then
    echo "Resuming Gatecrash..."
    log INFO "SERVICE resume-state.sh: Resuming Gatecrash (was running before shutdown)"
    systemctl start gatecrash 2>&1 || true
else
    log INFO "SERVICE resume-state.sh: Gatecrash was not running before shutdown, skipping"
fi
