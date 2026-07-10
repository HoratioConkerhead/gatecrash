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
        """Atomically and durably write `data` as JSON.

        Temp file + os.replace() gives *atomicity* — a reader (or a crash) never
        sees a half-written file. The fsyncs give *durability* — without them the
        write lives only in the SD card's write-back cache and a power-cut can
        lose it, which is exactly how a freshly-copied file once came back 0
        bytes after a plug-pull. fsync the data, replace, then fsync the
        directory so the rename itself survives too."""
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        # Best-effort directory fsync (makes the rename durable). Not supported
        # on every platform — e.g. Windows can't fsync a directory — so guard it.
        try:
            dir_fd = os.open(os.path.dirname(self.path) or ".", os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
