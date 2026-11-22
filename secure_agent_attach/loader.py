"""Read-only import of the original project (core module and the CLI module)."""
import importlib
import sys

from . import pin

_cache: dict = {}


def load_original():
    """Return the original `src.core` module. Bytecode is never written into the original."""
    if "core" not in _cache:
        sys.dont_write_bytecode = True
        root = str(pin.original_root())
        if root not in sys.path:
            sys.path.insert(0, root)
        _cache["core"] = importlib.import_module("src.core")
    return _cache["core"]


def load_main():
    """Return the original CLI module `main` (its globals are rebound by the attach layer, the file is not edited)."""
    load_original()
    if "main" not in _cache:
        _cache["main"] = importlib.import_module("main")
    return _cache["main"]
