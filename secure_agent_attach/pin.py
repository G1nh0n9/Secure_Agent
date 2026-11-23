"""Pin of the original project.

The attach layer never edits the original; every run records whether
the pinned files are unchanged and the pinned commit is still part of
the history.  The original is either a sibling directory or the
repository that contains this project as a subdirectory.
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN_FILE = ROOT / "pin" / "ORIGINAL.json"


def load_pin() -> dict:
    """Return the pin record (commit and file hashes)."""
    return json.loads(PIN_FILE.read_text(encoding="utf-8"))


def original_root() -> Path:
    """Return the directory of the original project.

    ``SECURE_AGENT_ORIGINAL`` wins.  Otherwise the first of the pin's
    ``locations`` (relative to this project) that holds ``src/core.py``
    and ``main.py`` is used.

    Raises:
        FileNotFoundError: If no location holds the original.
    """
    env = os.environ.get("SECURE_AGENT_ORIGINAL")
    if env:
        return Path(env)
    for place in load_pin()["locations"]:
        root = (ROOT / place).resolve()
        if (root / "src" / "core.py").exists() and (root / "main.py").exists():
            return root
    raise FileNotFoundError("the original project was not found")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    ).stdout.strip()


def _is_ancestor(root: Path, commit: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(root), "merge-base", "--is-ancestor", commit]
            + ["HEAD"],
            capture_output=True,
        ).returncode
        == 0
    )


def _inside(root: Path) -> str | None:
    """Return this project's path below ``root``, or None."""
    try:
        return ROOT.relative_to(root).as_posix()
    except ValueError:
        return None


def check() -> dict:
    """Say whether the original is still exactly the pinned version."""
    pin, root = load_pin(), original_root()
    now = {
        "commit": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(
            _git(root, "status", "--porcelain", "--", *pin["sha256"])
        ),
        "sha256": {
            rel: hashlib.sha256((root / rel).read_bytes()).hexdigest()
            for rel in pin["sha256"]
        },
    }
    problems = []
    if not _is_ancestor(root, pin["commit"]):
        problems.append("the pinned commit is not in the history")
    if now["dirty"]:
        problems.append("a pinned file has uncommitted changes")
    problems += [
        f"{rel} differs from the pin"
        for rel, h in pin["sha256"].items()
        if now["sha256"][rel] != h
    ]
    return {
        "ok": not problems,
        "problems": problems,
        "pinned_commit": pin["commit"],
        "now": now,
        "root": str(root),
    }


def untouched() -> dict:
    """Check after a run that the original is unchanged.

    It must have no changes and no bytecode caches left by us.  This
    project's own directory is left out when it sits inside the
    original repository.
    """
    root = original_root()
    own = _inside(root)
    caches = [
        str(p.relative_to(root))
        for p in root.rglob("__pycache__")
        if ".git" not in p.parts and not (own and p.is_relative_to(ROOT))
    ]
    exclude = [f":(exclude){own}"] if own else []
    status = _git(root, "status", "--porcelain", "--", ".", *exclude)
    return {
        "ok": not status and not caches,
        "git_status": status,
        "pycache": caches,
    }


def vendor_check() -> dict:
    """Check that the vendored FRET scripts are still the copied files.

    The hashes are in ``pin/VENDOR.json``.
    """
    want = json.loads(
        (ROOT / "pin" / "VENDOR.json").read_text(encoding="utf-8")
    )["sha256"]
    bad = [
        rel
        for rel, h in want.items()
        if hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() != h
    ]
    return {"ok": not bad, "changed": bad}
