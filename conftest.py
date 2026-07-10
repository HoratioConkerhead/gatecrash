# Put webui/ on sys.path so tests can `import validators` (and other pure
# webui modules) without installing the package or importing the whole Flask
# app. pytest auto-loads this file before collecting tests.
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "webui"))
