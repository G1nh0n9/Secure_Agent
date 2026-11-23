"""FRETish to ``ltl_pt`` with the official FRET parser, then NuSMV.

Both run in the docker image fret-lab.  The parser is FRET's own
``FretSemantics.compile``, run by a small script copied unchanged into
``vendor/fretjs``.  NuSMV runs one specification per file, because it
prints several results in an order that differs from the declaration
order.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import ptl

ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
IMAGE = os.environ.get("FRET_LAB_IMAGE", "fret-lab:latest")

# Reachability checks: the triggers of the requirements must be
# reachable, otherwise "holds" would be vacuous.
VACUITY = {
    "V1_blocked_start_reachable": "G !blocked_start",
    "V2_denied_turn_reachable": "G !(turn_over & denial_seen)",
    "V3_extra_tool_issue_reachable": "G !(issue & c = 1)",
    "V4_evaluate_reachable": "G !(st = EVALUATE)",
}


def load_requirements() -> dict:
    """Return the first layer's requirements and signal vocabulary."""
    return json.loads(
        (ROOT / "requirements" / "core_requirements.json").read_text(
            encoding="utf-8"
        )
    )


def compile_requirements(
    reqs: list[dict], out_name: str = "compiled.json"
) -> list[dict]:
    """Run the official FRET parser on every FRETish sentence.

    The result is written to ``runs/<out_name>``.
    """
    RUNS.mkdir(exist_ok=True)
    inp = RUNS / "fret_in.json"
    inp.write_text(
        json.dumps([r["fretish"] for r in reqs], ensure_ascii=False),
        encoding="utf-8",
    )
    js = ROOT / "vendor" / "fretjs"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--cpus",
        "1",
        "--entrypoint",
        "node",
        "-e",
        "NODE_PATH=/stub:/opt/fret/fret-electron/app/node_modules",
        "-v",
        f"{js}:/tools:ro",
        "-v",
        f"{js / 'stub'}:/stub:ro",
        "-v",
        f"{inp}:/in.json:ro",
        IMAGE,
        "/tools/fret_parse_full.js",
        "/in.json",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    try:
        res = json.loads(r.stdout)
    except json.JSONDecodeError:
        raise SystemExit(
            f"FRET parser run failed: rc={r.returncode} "
            f"stderr={r.stderr[-400:]!r}"
        )
    out = [
        {
            "id": q["id"],
            "fretish": q["fretish"],
            "ok": bool(x.get("ok")),
            "error": x.get("error"),
            "ltl_pt": x.get("ltl_pt"),
            "ltl_ft": x.get("ltl_ft"),
        }
        for q, x in zip(reqs, res)
    ]
    (RUNS / out_name).write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return out


def load_compiled() -> list[dict]:
    """Return the result of the last ``compile`` run."""
    p = RUNS / "compiled.json"
    if not p.exists():
        raise SystemExit(
            "runs/compiled.json is missing: run the `compile` command first"
        )
    return json.loads(p.read_text(encoding="utf-8"))


def run_nusmv(files: dict[str, str], workdir: Path) -> dict[str, str]:
    """files: name -> SMV text. Returns name -> NuSMV output."""
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    for name, text in files.items():
        (workdir / f"{name}.smv").write_text(text, encoding="utf-8")
    cmd = [
        "docker",
        "run",
        "--rm",
        "--cpus",
        "1",
        "-v",
        f"{workdir}:/w:ro",
        "--entrypoint",
        "sh",
        IMAGE,
        "-c",
        'for f in /w/*.smv; do echo "@@@ $(basename "$f" .smv)"; '
        'NuSMV "$f" 2>&1; done',
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    parts = re.split(r"@@@ (\S+)\n", r.stdout)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}


def verdict(out: str):
    """Read the verdict of one NuSMV specification from its output."""
    m = re.search(r"-- specification .* is (true|false)", out)
    return None if not m else m.group(1) == "true"


def parse_trace(out: str) -> list[dict]:
    """Parse a NuSMV counterexample into full states.

    NuSMV prints only the variables that changed after the first
    state; the valuation of every state is completed here.
    """
    states, cur = [], None
    for line in out.splitlines():
        m = re.match(r"\s*-> State: (\S+) <-", line)
        if m:
            cur = dict(cur) if cur else {}
            states.append(cur)
            continue
        m = re.match(r"\s+([A-Za-z_][A-Za-z0-9_.]*) = (\S+)\s*$", line)
        if m and cur is not None:
            cur[m.group(1)] = m.group(2)
    return states


def model_check(
    compiled: list[dict],
    template: str = "core_turn.smv.tpl",
    vacuity: dict | None = None,
    trace_keys: tuple = (
        "st",
        "steps",
        "ticket",
        "ttl_over",
        "plan_ok",
        "denial_seen",
        "c",
    ),
) -> dict:
    """Check every requirement on both variants of the model.

    Guard FALSE is the original, TRUE is the original with the guards.
    """
    vacuity = VACUITY if vacuity is None else vacuity
    tpl = (ROOT / "model" / template).read_text(encoding="utf-8")
    files = {}
    for guard in ("FALSE", "TRUE"):
        base = tpl.replace("@GUARD@", guard)
        for c in compiled:
            files[f"{c['id']}_g{guard}"] = (
                base + f"\nLTLSPEC G {ptl.to_smv(ptl.parse(c['ltl_pt']))}\n"
            )
        for name, spec in vacuity.items():
            files[f"{name}_g{guard}"] = base + f"\nLTLSPEC {spec}\n"
    outs = run_nusmv(files, RUNS / "mc")
    result = {}
    for name in files:
        rid, g = name.rsplit("_g", 1)
        out = outs.get(name, "")
        holds = verdict(out)
        entry = {"holds": holds}
        if holds is False:
            tr = parse_trace(out)
            entry["n_states"] = len(tr)
            entry["trace"] = [{k: s.get(k) for k in trace_keys} for s in tr]
        if holds is None:
            entry["raw"] = out.strip()[-300:]
        result.setdefault(rid, {})[
            "original" if g == "FALSE" else "guarded"
        ] = entry
    return result
