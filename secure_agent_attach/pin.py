"""Pin of the original project. The attach layer never edits the original; every run records whether it is still the pinned version."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN_FILE = ROOT / "pin" / "ORIGINAL.json"


def load_pin() -> dict:
    return json.loads(PIN_FILE.read_text(encoding="utf-8"))


def original_root() -> Path:
    return Path(os.environ.get("SECURE_AGENT_ORIGINAL") or load_pin()["path"])


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True).stdout.strip()


def check() -> dict:
    """Is the original still exactly the pinned version?"""
    pin, root = load_pin(), original_root()
    now = {
        "commit": _git(root, "rev-parse", "HEAD"),
        "dirty": bool(_git(root, "status", "--porcelain")),
        "sha256": {rel: hashlib.sha256((root / rel).read_bytes()).hexdigest() for rel in pin["sha256"]},
    }
    problems = []
    if now["commit"] != pin["commit"]:
        problems.append("commit differs from the pin")
    if now["dirty"]:
        problems.append("working tree is not clean")
    problems += [f"{rel} differs from the pin" for rel, h in pin["sha256"].items() if now["sha256"][rel] != h]
    return {"ok": not problems, "problems": problems, "pinned_commit": pin["commit"], "now": now, "root": str(root)}


def untouched() -> dict:
    """After a run: the original must have no changes and no bytecode caches left by us."""
    root = original_root()
    caches = [str(p.relative_to(root)) for p in root.rglob("__pycache__") if ".git" not in p.parts]
    status = _git(root, "status", "--porcelain")
    return {"ok": not status and not caches, "git_status": status, "pycache": caches}


def vendor_check() -> dict:
    """The FRET helper scripts vendored into this package must still be the files that were copied from nl2fret_tool (pin/VENDOR.json)."""
    want = json.loads((ROOT / "pin" / "VENDOR.json").read_text(encoding="utf-8"))["sha256"]
    bad = [rel for rel, h in want.items() if hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() != h]
    return {"ok": not bad, "changed": bad}
