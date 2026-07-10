#!/usr/bin/env python3
"""JsonSettings — one JSON-backed settings store with defaults + atomic writes.

Replaces four near-identical load_*/save_* pairs in app.py. Pure except for the
file I/O, so it's unit-tested in tests/test_settings.py with a tmp path.

- load() returns the defaults with any on-disk values merged over them, and
  falls back to a copy of the defaults if the file is missing or corrupt.
- save() writes to a temp file then os.replace()s it into place, so a power-cut
  mid-write can't leave a truncated JSON file — the plain truncating open() the
  old savers used could. Same atomic-rename pattern stats.py already uses.
"""

import json
import os


class JsonSettings:
    def __init__(self, path, defaults):
        self.path = path
        self.defaults = defaults

    def load(self):
        """Return {**defaults, **on_disk}; defaults copy on missing/corrupt file."""
        try:
            with open(self.path) as f:
                return {**self.defaults, **json.load(f)}
        except (FileNotFoundError, json.JSONDecodeError):
            return dict(self.defaults)

    def save(self, data):
        """Atomically write `data` as JSON (temp file + os.replace)."""
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)
