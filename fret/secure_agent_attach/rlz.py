"""FRET realizability (Kind2) of the core requirement catalog.

One FRET project per component, so the check of a component never
sees the requirements of another.  The inputs are every signal marked
Input (the attacker's channels plus the core's own state, all
unconstrained); the outputs are what the core decides.  A realizable
result means that some implementation satisfies every requirement of
the component for EVERY input sequence.

The sensitivity check adds to a component one requirement that states
the ORIGINAL behaviour of a known gap.  The result must be
unrealizable, otherwise a realizable verdict would say little.  The
container call follows ``fret_rlz.run_batch`` of nl2fret_tool
(``fretCLI realizability <project> <component> --solver kind2`` in the
image fret-lab), written again here so that this package has no
dependency on nl2fret_tool.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time

from . import fret_nusmv as fn
from . import spec as sp

WORK = fn.RUNS / "rlz" / "work"


def variable_table(spec: dict, cname: str, sems: list[dict]) -> dict:
    """Return role, type and constant of every identifier in ``sems``.

    The roles come from the catalog and are never guessed.
    """
    sig = spec["components"][cname]["signals"]
    out = {}
    for sem in sems:
        for v in sem.get("variables") or []:
            if v in out:
                continue
            if v in spec["constants"]:
                out[v] = {
                    "role": "Internal",
                    "dataType": "integer",
                    "constant": spec["constants"][v],
                }
            else:
                out[v] = {"role": sig[v][0], "dataType": sig[v][1]}
    return out


def docs_for(
    project: str, comp: str, items: list[tuple], table: dict
) -> tuple[list, list]:
    """Return FRET project documents, as the FRET GUI stores them.

    ``items`` are triples ``(reqid, fretish, sem)``.
    """
    reqs, uses = [], {}
    for reqid, text, sem in items:
        rid = f"req_{project}_{reqid}"
        reqs.append(
            {
                "_id": rid,
                "reqid": reqid,
                "parent_reqid": "",
                "project": project,
                "rationale": "",
                "fulltext": text,
                "status": "completed",
                "input": text,
                "semantics": sem,
            }
        )
        for v in sem.get("variables", []):
            uses.setdefault(v, []).append(rid)
    vdocs = []
    for v, rids in uses.items():
        t = table[v]
        d = {
            "_id": f"{project}{comp}{v}",
            "project": project,
            "component_name": comp,
            "variable_name": v,
            "reqs": sorted(set(rids)),
            "dataType": t["dataType"],
            "idType": t["role"],
            "moduleName": "",
            "description": "",
            "assignment": "",
            "copilotAssignment": "",
            "smvAssignment": "",
            "modeRequirement": "",
            "modeldoc": False,
            "modelComponent": "",
            "modeldoc_id": "",
            "completed": True,
            "r2u2Completed": False,
            "smvCompleted": False,
            "file_path": "preloaded",
        }
        if t["role"] == "Internal":
            d["assignment"] = str(t["constant"])
        vdocs.append(d)
    return reqs, vdocs


def _seconds(t):
    m = re.match(r"\s*([0-9.]+)\s*sec", str(t or ""))
    return float(m.group(1)) if m else None


def summarize(body: str, rc: int, wall: int) -> dict:
    """Read the verdict of one Kind2 run from the CLI output."""
    i = body.find("{")
    out = {"rc": rc, "wall_s": wall}
    if i < 0:
        out.update(
            result="unknown",
            detail="no JSON in the CLI output",
            tail=body.strip()[-500:],
        )
        return out
    try:
        j = json.loads(body[i : body.rfind("}") + 1])
    except Exception:  # noqa: BLE001
        out.update(
            result="unknown",
            detail="unparseable CLI JSON",
            tail=body.strip()[-500:],
        )
        return out
    sc = j["systemComponents"][0]
    comp, mono = sc.get("compositional"), sc.get("monolithic")
    if comp and comp.get("result") not in (None, "UNCHECKED"):
        out["mode"] = "compositional"
        out["raw_result"] = comp.get("result")
        out["n_cc"] = len(comp.get("connectedComponents", []))
        out["cc_results"] = [
            x.get("result") for x in comp.get("connectedComponents", [])
        ]
        out["cc_sizes"] = [
            len(x.get("requirements", []))
            for x in comp.get("connectedComponents", [])
        ]
        times = [
            _seconds(x.get("time"))
            for x in comp.get("connectedComponents", [])
        ]
        out["time_s"] = (
            round(sum(t for t in times if t is not None), 2)
            if any(t is not None for t in times)
            else None
        )
        out["error"] = [
            x.get("error")
            for x in comp.get("connectedComponents", [])
            if x.get("error")
        ] or None
        out["diagnosis"] = [
            x.get("diagnosisReport") or x.get("diagnosis")
            for x in comp.get("connectedComponents", [])
            if x.get("diagnosisReport") or x.get("diagnosis")
        ] or None
    elif mono and mono.get("result") not in (None, "UNCHECKED"):
        out["mode"] = "monolithic"
        out["raw_result"] = mono.get("result")
        out["time_s"] = mono.get("time")
        out["error"] = mono.get("error")
        out["diagnosis"] = mono.get("diagnosisReport") or mono.get("diagnosis")
    else:
        out["raw_result"] = None
        out["error"] = (comp or {}).get("error") or (mono or {}).get("error")
    rr = (out.get("raw_result") or "").upper()
    out["result"] = {
        "REALIZABLE": "realizable",
        "UNREALIZABLE": "unrealizable",
    }.get(rr, "unknown")
    if out["result"] == "unknown":
        out["tail"] = body.strip()[-500:]
    return out


def run_batch(
    batch: str,
    jobs: list[dict],
    timeout_each: int = 300,
    kind2_timeout: int = 120,
) -> dict:
    """Run the jobs one after another in ONE container with one CPU.

    A job is a dict ``(project, comp, reqs, vdocs, diagnose)``.
    """
    WORK.mkdir(parents=True, exist_ok=True)
    home = WORK / f"home_{batch}"
    shutil.rmtree(home, ignore_errors=True)
    (home / "Documents").mkdir(parents=True)
    (WORK / f"{batch}_reqs.json").write_text(
        json.dumps([r for j in jobs for r in j["reqs"]], ensure_ascii=False),
        encoding="utf-8",
    )
    (WORK / f"{batch}_vars.json").write_text(
        json.dumps([v for j in jobs for v in j["vdocs"]], ensure_ascii=False),
        encoding="utf-8",
    )
    (WORK / f"{batch}_jobs.txt").write_text(
        "".join(
            f"{j['project']} {j['comp']} "
            f"{'--diagnose' if j.get('diagnose') else ''}\n"
            for j in jobs
        ),
        encoding="utf-8",
    )
    script = (
        f"node /tools/fret_import.js /work/{batch}_reqs.json "
        f"/work/{batch}_vars.json 2>&1 | tail -2; "
        f"cd /opt/fret/fret-electron/app; "
        f'while read p c f; do echo "@@@START $p"; S=$(date +%s); '
        f"timeout {timeout_each} node cli/fretCLI.main.js realizability "
        f'"$p" "$c" $f '
        f"--solver kind2 --timeout {kind2_timeout} --json 2>&1; "
        f'echo "@@@END $p rc=$? wall=$(( $(date +%s) - S ))"; '
        f"done < /work/{batch}_jobs.txt"
    )
    cmd = [
        "docker",
        "run",
        "--rm",
        "--cpus",
        "1",
        "--entrypoint",
        "sh",
        "-e",
        "NODE_PATH=/opt/fret/fret-electron/app/node_modules",
        "-v",
        f"{fn.ROOT / 'vendor' / 'fretjs'}:/tools:ro",
        "-v",
        f"{WORK}:/work",
        "-v",
        f"{home / 'Documents'}:/root/Documents",
        fn.IMAGE,
        "-c",
        script,
    ]
    t0 = time.time()
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=max(3600, timeout_each * len(jobs) + 600),
    )
    out = r.stdout + r.stderr
    (WORK / f"{batch}_container.log").write_text(out, encoding="utf-8")
    res = {}
    for m in re.finditer(
        r"@@@START (\S+)\n(.*?)@@@END \S+ rc=(\d+) wall=(\d+)", out, re.S
    ):
        res[m.group(1)] = summarize(
            m.group(2), int(m.group(3)), int(m.group(4))
        )
    res["_batch_wall_s"] = round(time.time() - t0, 1)
    shutil.rmtree(home, ignore_errors=True)
    return res


def _job(
    spec: dict,
    comp: dict,
    cname: str,
    project: str,
    extra: list[tuple] | None = None,
    diagnose: bool = False,
    exclude: tuple = (),
) -> dict:
    items = [
        (r["id"], r["expanded"], comp[r["expanded"]]["sem"])
        for r in spec["components"][cname]["requirements"]
        if r["id"] not in exclude
    ]
    items += extra or []
    table = variable_table(spec, cname, [sem for _, _, sem in items])
    reqs, vdocs = docs_for(project, cname, items, table)
    return {
        "project": project,
        "comp": cname,
        "reqs": reqs,
        "vdocs": vdocs,
        "diagnose": diagnose,
    }


def run(
    spec: dict,
    comp: dict,
    only: list[str] | None = None,
    mutants: bool = True,
    timeout_each: int = 300,
    kind2_timeout: int = 120,
) -> dict:
    """Check realizability of every component and the sensitivity."""
    names = [c for c in spec["components"] if not only or c in only]
    jobs = [_job(spec, comp, c, f"SA_{c}") for c in names]
    muts = [m for m in spec["mutants"] if mutants and m["component"] in names]
    for m in muts:
        base = f"SA_{m['component']}_{m['id'].replace('-', '_')}"
        extra = [(m["id"], m["expanded"], comp[m["expanded"]]["sem"])]
        jobs.append(_job(spec, comp, m["component"], base, extra=extra))
        if m.get("check") == "attribution":
            # Attribution: without the requirements it should conflict
            # with, the same component must be realizable again.
            jobs.append(
                _job(
                    spec,
                    comp,
                    m["component"],
                    base + "_minus",
                    extra=extra,
                    exclude=tuple(m["conflicts_with"]),
                )
            )
    first = run_batch("core1", jobs, timeout_each, kind2_timeout)
    unknown = {"result": "unknown", "detail": "no output"}
    out = {
        "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        "image": fn.IMAGE,
        "solver": "kind2",
        "kind2_timeout_s": kind2_timeout,
        "components": {c: first.get(f"SA_{c}", unknown) for c in names},
        "mutants": {},
    }
    for m in muts:
        base = f"SA_{m['component']}_{m['id'].replace('-', '_')}"
        v = dict(first.get(base, unknown))
        v["origin"] = m.get("origin")
        if m.get("check") == "attribution":
            v["without_expected"] = first.get(base + "_minus", unknown)
            v["attributed"] = (
                v["result"] == "unrealizable"
                and v["without_expected"]["result"] == "realizable"
            )
        out["mutants"][m["id"]] = v
    # Conflicting requirements are asked for only where the verdict
    # is unrealizable.
    again = [
        (c, v)
        for c, v in out["components"].items()
        if v["result"] == "unrealizable"
    ]
    again_m = [
        (m, v)
        for m, v in out["mutants"].items()
        if v["result"] == "unrealizable" and v.get("origin") == "as_is"
    ]  # the explanation is asked for only for the known gaps
    if again or again_m:
        jobs2 = [
            _job(spec, comp, c, f"SA_{c}", diagnose=True) for c, _ in again
        ]
        for mid, _ in again_m:
            m = next(x for x in spec["mutants"] if x["id"] == mid)
            jobs2.append(
                _job(
                    spec,
                    comp,
                    m["component"],
                    f"SA_{m['component']}_{mid.replace('-', '_')}",
                    extra=[(mid, m["expanded"], comp[m["expanded"]]["sem"])],
                    diagnose=True,
                )
            )
        second = run_batch("core2", jobs2, timeout_each, kind2_timeout)
        for c, _ in again:
            out["components"][c]["diagnosis_run"] = second.get(f"SA_{c}")
        for mid, _ in again_m:
            m = next(x for x in spec["mutants"] if x["id"] == mid)
            out["mutants"][mid]["diagnosis_run"] = second.get(
                f"SA_{m['component']}_{mid.replace('-', '_')}"
            )
    out["batch_wall_s"] = first.get("_batch_wall_s")
    return out
