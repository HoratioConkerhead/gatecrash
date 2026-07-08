#!/usr/bin/env bash
# Shared logging helper for Gatecrash shell scripts.
# Source this file: source "$(dirname "$0")/log.sh"

# Persistent path (NOT /var/log): on DietPi /var/log is a RAM tmpfs that
# Dietpi-RAMlog clears hourly and on reboot, which wiped the audit log. The
# high-volume arpspoof/DNS logs stay in /var/log by design (SD-card wear).
LOG="/opt/gatecrash/gatecrash.log"

log() { printf '%s  %-5s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >> "$LOG"; }
