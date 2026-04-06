#!/usr/bin/env bash
# Shared logging helper for Gatecrash shell scripts.
# Source this file: source "$(dirname "$0")/log.sh"

LOG="/var/log/gatecrash.log"

log() { printf '%s  %-5s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >> "$LOG"; }
