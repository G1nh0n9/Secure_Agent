"""Attach layer for Secure_Agent.

The original project is imported read-only and never edited.
Everything here sits outside the original repository: observation and
guards are added by subclassing and by rebinding names at run time.
Every run records the pin of the original (commit and file hashes).
"""

import sys

sys.dont_write_bytecode = (
    True  # never write __pycache__ into the original project
)
