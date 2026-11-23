"""Requirement catalog of the core (``requirements/core_spec.json``).

Functions:

* ``load``: read the catalog and expand the ``{MACRO}`` shorthand of
  every requirement.
* ``compile_texts``: run the official FRET parser (docker image
  fret-lab); results are cached in ``runs/spec_compile_cache.json``.
* ``validate``: declared signals, role and type use, an Output in every
  response, unique ids.
* ``coverage``: every statement of the pinned core.py is cited by a
  requirement or by an explained exclusion (AST, read-only).
* ``render_doc``: ``docs/CORE_SPEC.md`` and ``docs/core_spec.csv``, a
  readable summary of the catalog, the coverage and the latest results.
"""

from __future__ import annotations

import ast
import csv
import json
import os
import re
import subprocess
from pathlib import Path

from . import fret_nusmv as fn
from . import pin, ptl

ROOT = fn.ROOT
RUNS = fn.RUNS
SPEC_FILE = ROOT / "requirements" / "core_spec.json"
CACHE = RUNS / "spec_compile_cache.json"
DOCS = ROOT / "docs"
MACRO = re.compile(r"\{([A-Z][A-Z0-9_]*)\}")
BOOL_OPS = {"&", "|", "->", "<->"}
CMP_OPS = set(ptl.CMP)
ARI_OPS = {"+", "-", "*"}


# ---------------------------------------------------------------- load


def _expand(text: str, macros: dict, where: str, seen: tuple = ()) -> str:
    def rep(m):
        name = m.group(1)
        if name not in macros:
            raise SystemExit(f"{where}: unknown macro {{{name}}}")
        if name in seen:
            raise SystemExit(f"{where}: macro {name} refers to itself")
        return _expand(macros[name], macros, where, seen + (name,))

    out = MACRO.sub(rep, text)
    if "{" in out or "}" in out:
        raise SystemExit(f"{where}: unexpanded brace in {out!r}")
    return out


def load() -> dict:
    """Read the catalog and expand the macros of every requirement."""
    spec = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
    for cname, comp in spec["components"].items():
        macros = comp.get("macros", {})
        for r in comp["requirements"]:
            r["component"] = cname
            r["expanded"] = _expand(r["text"], macros, r["id"])
    for m in spec["mutants"]:
        m["expanded"] = _expand(
            m["text"],
            spec["components"][m["component"]].get("macros", {}),
            m["id"],
        )
    return spec


def requirements(spec: dict) -> list[dict]:
    """Return every requirement of every component."""
    return [
        r for comp in spec["components"].values() for r in comp["requirements"]
    ]


# ------------------------------------ compile (official FRET parser)


def compile_texts(texts: list[str]) -> dict[str, dict]:
    """Compile FRETish sentences with the official parser (cached)."""
    RUNS.mkdir(exist_ok=True)
    cache = (
        json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    )
    todo = list(dict.fromkeys(t for t in texts if t not in cache))
    if todo:
        inp = RUNS / "spec_fret_in.json"
        inp.write_text(json.dumps(todo, ensure_ascii=False), encoding="utf-8")
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
            fn.IMAGE,
            "/tools/fret_parse_full.js",
            "/in.json",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        try:
            res = json.loads(r.stdout)
        except json.JSONDecodeError:
            raise SystemExit(
                f"FRET parser run failed: rc={r.returncode} "
                f"stderr={r.stderr[-400:]!r}"
            )
        if len(res) != len(todo):
            raise SystemExit(
                "FRET parser returned a different number of results"
            )
        for t, x in zip(todo, res):
            cache[t] = {
                "ok": bool(x.get("ok")),
                "error": x.get("error"),
                "ltl_ft": x.get("ltl_ft"),
                "ltl_pt": x.get("ltl_pt"),
                "sem": x.get("sem"),
            }
        CACHE.write_text(
            json.dumps(cache, ensure_ascii=False), encoding="utf-8"
        )
        inp.unlink(missing_ok=True)
    return {t: cache[t] for t in texts}


# ------------------------------------------------------- validate


def signal_types(spec: dict, cname: str) -> dict[str, str]:
    """Return the type of every signal and constant of a component."""
    types = {n: "integer" for n in spec["constants"]}
    types.update(
        {n: s[1] for n, s in spec["components"][cname]["signals"].items()}
    )
    return types


def _ctx(node, want: str, types: dict, errors: list, where: str) -> str:
    """Type-check a formula tree and return the type of the node.

    ``want`` is ``bool`` or ``num``.
    """
    k = node[0]
    if k == "var":
        t = "bool" if types.get(node[1]) == "boolean" else "num"
        if node[1] not in types:
            errors.append(f"{where}: undeclared signal {node[1]}")
        elif t != want:
            errors.append(
                f"{where}: {node[1]} is {types[node[1]]} but is used as "
                f"{'a truth value' if want == 'bool' else 'a number'}"
            )
        return t
    if k == "num":
        if want != "num":
            errors.append(f"{where}: number {node[1]} used as a truth value")
        return "num"
    if k == "const":
        if want != "bool":
            errors.append(f"{where}: TRUE or FALSE used as a number")
        return "bool"
    if k == "!":
        _ctx(node[1], "bool", types, errors, where)
        return "bool"
    if k in BOOL_OPS:
        _ctx(node[1], "bool", types, errors, where)
        _ctx(node[2], "bool", types, errors, where)
        return "bool"
    if k in CMP_OPS:
        _ctx(node[1], "num", types, errors, where)
        _ctx(node[2], "num", types, errors, where)
        return "bool"
    if k in ARI_OPS:
        _ctx(node[1], "num", types, errors, where)
        _ctx(node[2], "num", types, errors, where)
        return "num"
    if k == "neg":
        _ctx(node[1], "num", types, errors, where)
        return "num"
    if k in ("H", "O", "Y", "Z"):
        _ctx(node[1], "bool", types, errors, where)
        return "bool"
    errors.append(
        f"{where}: operator {k} is not expected in a state requirement"
    )
    return want


def _response_side(body):
    """Return the part of a requirement the component must make true.

    That is the right side of an implication, else the whole formula.
    """
    return body[2] if body[0] == "->" else body


def _conjuncts(node) -> list:
    """Split FRET's top-level conjunction of H formulas.

    FRET writes ``always satisfy (A & B)`` that way.
    """
    return (
        _conjuncts(node[1]) + _conjuncts(node[2]) if node[0] == "&" else [node]
    )


def validate(spec: dict, comp: dict[str, dict]) -> dict:
    """Check the catalog and return its errors and warnings."""
    errors, warnings = [], []
    consts = spec["constants"]
    seen_ids, seen_sig = set(), {}
    for cname, c in spec["components"].items():
        for key in ("title", "tick", "signals", "requirements"):
            if key not in c:
                errors.append(f"{cname}: missing {key}")
        for n, s in c["signals"].items():
            if (
                len(s) != 4
                or s[0] not in ("Input", "Output")
                or s[1] not in ("boolean", "integer")
            ):
                errors.append(
                    f"{cname}.{n}: signal entry must be [Input|Output, "
                    f"boolean|integer, text, code]"
                )
            if n in seen_sig:
                errors.append(
                    f"signal {n} is declared in {seen_sig[n]} and {cname}"
                )
            seen_sig[n] = cname
            if n in consts:
                errors.append(f"{cname}.{n}: signal name equals a constant")
        types = signal_types(spec, cname)
        used, positive = set(), set()
        for r in c["requirements"]:
            where = r["id"]
            if where in seen_ids:
                errors.append(f"duplicate id {where}")
            seen_ids.add(where)
            if r["kind"] not in ("SEC", "FUN"):
                errors.append(f"{where}: kind must be SEC or FUN")
            if r.get("asis") not in ("ok", "gap"):
                errors.append(f"{where}: asis must be ok or gap")
            if r.get("asis") == "gap" and not r.get("asis_desc"):
                errors.append(f"{where}: a gap needs asis_desc")
            if r.get("guard") not in (None, "pending"):
                errors.append(f"{where}: guard must be 'pending' when present")
            if r.get("guard") == "pending" and r.get("asis") != "gap":
                errors.append(f"{where}: guard pending needs asis gap")
            if not r["text"].startswith(f"{cname} shall "):
                errors.append(
                    f"{where}: text must start with '{cname} shall '"
                )
            if not r.get("code"):
                errors.append(f"{where}: no code reference")
            if not r.get("desc"):
                errors.append(f"{where}: no description")
            res = comp[r["expanded"]]
            if not res["ok"]:
                errors.append(
                    f"{where}: the FRET parser rejected the text: "
                    f"{res['error']}"
                )
                continue
            sem_vars = set(res["sem"].get("variables") or [])
            for v in sem_vars:
                if v not in types:
                    errors.append(f"{where}: undeclared signal {v}")
                elif v in c["signals"]:
                    used.add(v)
            try:
                ast_ = ptl.parse(res["ltl_pt"])
            except Exception as e:  # noqa: BLE001
                errors.append(
                    f"{where}: the evaluator cannot read ltl_pt: {e}"
                )
                continue
            for part in _conjuncts(ast_):
                if part[0] != "H":
                    errors.append(
                        f"{where}: expected a state requirement (always), got "
                        f"{part[0]}"
                    )
                    continue
                body = part[1]
                _ctx(body, "bool", types, errors, where)
                outputs = {
                    v
                    for v in ptl.variables(body)
                    if v in c["signals"] and c["signals"][v][0] == "Output"
                }
                if not outputs:
                    errors.append(
                        f"{where}: the formula mentions no Output signal (it "
                        f"would only constrain the environment)"
                    )
                positive |= {
                    v
                    for v in ptl.variables(_response_side(body))
                    if v in c["signals"] and c["signals"][v][0] == "Output"
                }
        for n, s in c["signals"].items():
            if n not in used:
                warnings.append(
                    f"{cname}.{n}: declared but used by no requirement"
                )
            elif s[0] == "Output" and n not in positive:
                warnings.append(
                    f"{cname}.{n}: this Output appears only as a condition, "
                    f"so the spec is satisfied by never producing it (add a "
                    f"requirement that demands it)"
                )
    for kind in (
        "assumptions",
        "advisory",
        "observations",
        "security_functions",
    ):
        ids = [x["id"] for x in spec[kind]]
        if len(ids) != len(set(ids)):
            errors.append(f"duplicate id in {kind}")
    classified = set()
    for sf in spec["security_functions"]:
        for rid in sf["reqs"]:
            if rid not in seen_ids:
                errors.append(f"{sf['id']}: unknown requirement {rid}")
            classified.add(rid)
    for c in spec["components"].values():
        for r in c["requirements"]:
            if r["kind"] == "SEC" and r["id"] not in classified:
                errors.append(
                    f"{r['id']}: a security requirement that belongs to no "
                    f"security function"
                )
    for m in spec["mutants"]:
        if not comp[m["expanded"]]["ok"]:
            errors.append(f"{m['id']}: the FRET parser rejected the text")
        for rid in m["conflicts_with"]:
            if rid not in seen_ids:
                errors.append(
                    f"{m['id']}: conflicts_with names unknown requirement "
                    f"{rid}"
                )
    return {"errors": errors, "warnings": warnings}


# ------------------------------------------- coverage of the code


def _ranges(items) -> set[int]:
    out: set[int] = set()
    for item in items:
        for part in str(item).split(","):
            m = re.fullmatch(r"\s*L(\d+)(?:-(\d+))?\s*", part)
            if not m:
                raise SystemExit(f"bad code reference {part!r}")
            a, b = int(m.group(1)), int(m.group(2) or m.group(1))
            out.update(range(a, b + 1))
    return out


def coverage(spec: dict) -> dict:
    """Return how many statements of core.py the catalog cites."""
    p = pin.check()
    core_hash = p["now"]["sha256"]["src/core.py"]
    pinned = pin.load_pin()["sha256"]["src/core.py"]
    path = pin.original_root() / spec["source"]["file"]
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    tree = ast.parse(text)
    stmts = sorted(
        {n.lineno for n in ast.walk(tree) if isinstance(n, ast.stmt)}
    )
    by_req: dict[int, list[str]] = {}
    for r in requirements(spec):
        for ln in _ranges(r["code"]):
            by_req.setdefault(ln, []).append(r["id"])
    excl: dict[int, str] = {}
    for e in spec["exclusions"]:
        for ln in _ranges([e["lines"]]):
            excl[ln] = e["reason"]
    covered = [ln for ln in stmts if ln in by_req]
    excluded = [ln for ln in stmts if ln not in by_req and ln in excl]
    uncovered = [ln for ln in stmts if ln not in by_req and ln not in excl]
    beyond = sorted(ln for ln in by_req if ln > len(lines))
    funcs = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = [s for s in stmts if n.lineno <= s <= n.end_lineno]
            funcs.append(
                {
                    "name": n.name,
                    "lines": [n.lineno, n.end_lineno],
                    "statements": len(inner),
                    "covered": sum(1 for s in inner if s in by_req),
                    "excluded": sum(
                        1 for s in inner if s not in by_req and s in excl
                    ),
                }
            )
    funcs.sort(key=lambda f: f["lines"][0])
    return {
        "core_sha256_matches_pin": core_hash == pinned,
        "statements": len(stmts),
        "covered_by_requirement": len(covered),
        "covered_by_exclusion": len(excluded),
        "uncovered": [
            {"line": ln, "text": lines[ln - 1].strip()[:100]}
            for ln in uncovered
        ],
        "references_beyond_file_end": beyond,
        "functions": funcs,
        "n_lines": len(lines),
    }


# -------------------------------------------- readable document


def _link(code: list[str]) -> str:
    base = Path(
        os.path.relpath(pin.original_root() / "src" / "core.py", DOCS)
    ).as_posix()
    out = []
    for c in code:
        m = re.fullmatch(r"L(\d+)(?:-(\d+))?", c.strip())
        if m:
            a, b = m.group(1), m.group(2)
            out.append(
                f"[{c}]({base}#L{a}"
                + (f"-L{b}" if b else "")
                + ")"
            )
        else:
            out.append(c)
    return ", ".join(out)


def _load_json(path: Path):
    return (
        json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    )


def _mutant_row(mid: str, result: dict) -> str:
    """Return the table row of one code or guard mutant."""
    found = ", ".join(result.get("violated", []))
    if not found and result.get("crash"):
        found = (
            "(no requirement violated, the probe stopped on an error: "
            + result["crash"][:60]
            + ")"
        )
    caught = "yes" if result.get("caught") else "**no**"
    return f"| {mid} | {result['desc']} | {caught} | {found} |"


def _calls_section(calls: dict | None) -> list[str]:
    """Return the document lines about the tool-call monitor."""
    from .callcheck import attack_events

    if not calls:
        return []
    kinds = {
        "authorization": "privilege escalation",
        "exfiltration": "exfiltration chain",
        "resources": "resource exhaustion",
        "completion": "false completion",
    }
    req = json.loads(
        (ROOT / "requirements" / "call_requirements.json").read_text(
            encoding="utf-8"
        )
    )["requirements"]
    out = ["", "## Attacker controls the model (call monitor, FRET + NuSMV)\n"]
    out.append(
        "Every output of the model is chosen by the attacker (any next "
        "event, any plan, any extra grant from the verifier, any clock "
        "jump), and the requirements are checked against that. The model "
        "columns are the result of NuSMV over all behaviours of the "
        "abstract model; the session columns are the result of "
        "evaluating the same formulas on what the real system did in "
        "generated sessions. The counterexample of a violation is the "
        "attack that the formal method found.\n"
    )
    out.append(
        "| Requirement | Attack | FRETish | Model: original | "
        "Model: guarded | Sessions: original | Sessions: guarded |\n"
        "|---|---|---|---|---|---|---|"
    )
    sessions = calls["sessions"]
    for r in req:
        m = calls["model"][r["id"]]
        word = {True: "holds", False: "**violated**"}
        so = sessions["original"]["violations"].get(r["id"], 0)
        sg = sessions["guarded"]["violations"].get(r["id"], 0)
        note = (
            " (by construction)"
            if r["model"] == "by_construction"
            else ""
        )
        out.append(
            f"| {r['id']} | {kinds[r['class']]} | `{r['fretish']}` | "
            f"{word[m['original']['holds']]}{note} | "
            f"{word[m['guarded']['holds']]} | "
            f"{so} of {sessions['original']['runs']} violated | "
            f"{sg} of {sessions['guarded']['runs']} violated |"
        )
    rz = calls.get("realizability")
    if rz:
        defects = rz["mutants"]
        attributed = sum(1 for v in defects.values() if v["attributed"])
        out.append(
            f"\nRealizability of the five requirements (Kind2, every input "
            f"unconstrained): **{rz['components']['Monitor']['result']}**. "
            f"All {len(defects)} planted defects (the original behaviour "
            f"written as a requirement) became unrealizable; {attributed} "
            f"became realizable again when the conflicting requirement "
            f"was removed."
        )
    out.append("")
    for r in req:
        m = calls["model"][r["id"]]["original"]
        if m["holds"] is not False:
            continue
        chain = attack_events(r["id"], m["trace"])
        events = " -> ".join(chain)
        out.append(
            f"- **{r['id']}** {r['title']}: attack found by NuSMV on the "
            f"original ({len(chain)} events): `{events}`"
        )
    return out


def render_doc(spec: dict, cov: dict, check: dict | None = None) -> None:
    """Write the readable document and the CSV from the latest runs."""
    DOCS.mkdir(exist_ok=True)
    rlz = _load_json(RUNS / "rlz" / "latest.json")
    probe = _load_json(RUNS / "probe" / "latest.json")
    cmut = _load_json(RUNS / "probe" / "mutants.json")
    calls = _load_json(RUNS / "calls" / "latest.json")
    traces = (_load_json(RUNS / "latest.json") or {}).get("traces") or {}
    guarded = (probe or {}).get("guarded") or {}
    closed = set(guarded.get("closed_gaps") or [])

    def sr_status(sr):
        if (
            not traces
            or not sr
            or any(sr not in r["original"] for r in traces.values())
        ):
            return ""
        orig = [n for n, r in traces.items() if not r["original"][sr]["ok"]]
        guard = [n for n, r in traces.items() if not r["guarded"][sr]["ok"]]
        return (
            f"; {sr} in {len(traces)} end-to-end scenarios: original "
            + (f"violated in {', '.join(orig)}" if orig else "holds in all")
            + ", guarded "
            + (f"violated in {', '.join(guard)}" if guard else "holds in all")
        )

    reqs = requirements(spec)
    n_sec = sum(1 for r in reqs if r["kind"] == "SEC")
    gaps = [r for r in reqs if r["asis"] == "gap"]
    obs = lambda cname, rid: (
        (probe or {})
        .get("components", {})
        .get(cname, {})
        .get("requirements", {})
        .get(rid)
    )  # noqa: E731
    L: list[str] = []
    L.append(f"# {spec['title']}\n")
    L.append(
        "Generated by `python -m secure_agent_attach doc` from "
        "`requirements/core_spec.json` and the latest results (`runs/`). "
        "Do not edit.\n"
    )
    L.append("## How to read\n")
    L.append(spec["how_to_read"] + "\n")
    L.append(spec["role_policy"] + "\n")
    L.append(spec["constants_note"] + "\n")
    L.append("## Summary\n")
    L.append(
        f"- {len(reqs)} requirements (SEC {n_sec}, FUN "
        f"{len(reqs) - n_sec}), {len(spec['components'])} components, "
        f"{len(spec['security_functions'])} security functions"
    )
    pend = [r for r in gaps if r.get("guard") == "pending"]
    L.append(
        f"- Requirements the original violates (gap): {len(gaps)}: "
        + ", ".join(r["id"] for r in gaps)
    )
    if pend:
        L.append(
            f"  - of these without a guard yet (guard: pending): "
            f"{len(pend)}: " + ", ".join(r["id"] for r in pend)
        )
    else:
        L.append("  - all closed by the attach guards (no guard: pending)")
    L.append(
        f"- core.py statements: {cov['statements']}, cited by a "
        f"requirement {cov['covered_by_requirement']}, excluded with a "
        f"reason {cov['covered_by_exclusion']}, uncovered "
        f"{len(cov['uncovered'])}"
    )
    if check:
        L.append(
            f"- Catalog check: {len(check['errors'])} errors, "
            f"{len(check['warnings'])} warnings"
        )
    if rlz:
        res = rlz["components"]
        L.append(
            f"- Realizability (Kind2, every input unconstrained): "
            f"{sum(v['result'] == 'realizable' for v in res.values())}"
            f"/{len(res)} components realizable"
        )
        mut = rlz.get("mutants") or {}
        if mut:
            L.append(
                f"- Requirement-level mutants (defects written as "
                f"requirements): "
                f"{sum(v['result'] == 'unrealizable' for v in mut.values())}"
                f"/{len(mut)} became unrealizable"
            )
    if probe:
        ec = probe.get("exec_coverage") or {}
        pc = probe["counts"]
        n_probe = sum(
            len(v["requirements"]) for v in probe["components"].values()
        )
        L.append(
            f"- Probes on the real code: {pc['ticks']} observations; of "
            f"{n_probe} requirements {pc['holds']} hold on every "
            f"observation, {pc['violated']} are violated, "
            f"{pc['not_checked']} were not observed, "
            f"{len(probe['mismatch'])} differ from the asis column of "
            f"the catalog"
        )
        if ec:
            L.append(
                f"- core.py function-body statements executed by the "
                f"probes: "
                f"{ec['executed']}/{ec['statements_in_function_bodies']}"
            )
        if guarded:
            n_g = sum(
                len(v["requirements"]) for v in guarded["components"].values()
            )
            L.append(
                f"- Probes on the guarded stack (GuardedStages, "
                f"TrustedHistory): of {n_g} requirements "
                f"{len(guarded['still_violated'])} violated; "
                f"{len(closed)} requirements that the original violates "
                f"hold ({', '.join(sorted(closed))}). TRN-13 and TRN-14 "
                f"are checked on whole turns with the real stages and the "
                f"real loop, TRN-09 and TRN-10 in the end-to-end "
                f"scenarios"
            )
    if cmut:
        n_caught = sum(1 for v in cmut.values() if v.get("caught"))
        L.append(
            f"- Code-level mutants (one defect at a time in a copy of "
            f"the original): {n_caught}/{len(cmut)} caught by the probes"
        )
    if calls:
        L.append(
            "- Call monitor (attacker controls the model): "
            f"{len(calls['compiled'])} requirements checked with NuSMV "
            "over all environment behaviours; see the section "
            "'Attacker controls the model' below"
        )
    L.extend(_calls_section(calls))
    L.append("")
    L.append("## Security functions and requirements\n")
    L.append(
        "| Security function | Description | Requirements | "
        "Violated by the original |\n|---|---|---|---|"
    )
    gapset = {r["id"] for r in gaps}
    for sf in spec["security_functions"]:
        L.append(
            f"| {sf['id']} {sf['name']} | {sf['desc']} | "
            f"{', '.join(sf['reqs'])} | "
            f"{', '.join(x for x in sf['reqs'] if x in gapset) or 'none'} |"
        )
    L.append("\n## Assumptions (to be guaranteed outside the Core)\n")
    for a in spec["assumptions"]:
        L.append(f"- **{a['id']}** {a['desc']}")
    L.append("\n## Advisory controls, not enforced (prompt text)\n")
    for a in spec["advisory"]:
        L.append(f"- **{a['id']}** ({_link([a['code']])}) {a['desc']}")
    L.append("\n## Observations (facts not made into requirements)\n")
    for a in spec["observations"]:
        code = f" ({_link(a['code'].split(', '))})" if a.get("code") else ""
        L.append(f"- **{a['id']}**{code} {a['desc']}")
    L.append("\n## Requirements by component\n")
    for cname, c in spec["components"].items():
        L.append(f"### {cname}: {c['title']}\n")
        L.append(f"Tick = {c['tick']}\n")
        if rlz and cname in rlz["components"]:
            v = rlz["components"][cname]
            L.append(
                f"realizability: **{v['result']}** ({v.get('time_s', '?')} "
                f"s)\n"
            )
        L.append(
            "| Signal | Role | Type | Meaning | Code |\n|---|---|---|---|---|"
        )
        for n, s_ in c["signals"].items():
            L.append(f"| `{n}` | {s_[0]} | {s_[1]} | {s_[2]} | {s_[3]} |")
        if c.get("macros"):
            L.append("\nMacros (`{NAME}` in a requirement is replaced by):\n")
            for k, v in c["macros"].items():
                L.append(f"- `{{{k}}}` = `{v}`")
        L.append("")
        for r in c["requirements"]:
            tag = f"{r['kind']}" + (f", {r['sr']}" if r.get("sr") else "")
            asis = "original complies"
            if r["asis"] != "ok":
                asis = (
                    "**original violates**: "
                    + r["asis_desc"]
                    + (
                        "; **guard missing**"
                        if r.get("guard") == "pending"
                        else ""
                    )
                )
            o = obs(cname, r["id"])
            seen = (
                ""
                if not o
                else (
                    f"; all {o['checked']} observations on the real code hold"
                    if o["status"] == "holds"
                    else (
                        f"; {o['violations']} of {o['checked']} observations "
                        f"on the real code violate it"
                        if o["status"] == "violated"
                        else "; not observed"
                    )
                )
            )
            closed_note = (
                "; holds in the probes with the guards on"
                if r["id"] in closed
                else ""
            )
            L.append(
                f"- **{r['id']}** ({tag}; "
                f"{asis}{seen}{closed_note}{sr_status(r.get('sr'))}) "
                f"{r['desc']}  "
            )
            L.append(f"  `{r['text']}`  ")
            L.append(f"  Code: {_link(r['code'])}")
        L.append("")
    L.append("## Code coverage (every statement of core.py)\n")
    L.append(
        f"{cov['statements']} statements: cited by a requirement "
        f"{cov['covered_by_requirement']}, excluded "
        f"{cov['covered_by_exclusion']}, uncovered "
        f"{len(cov['uncovered'])}\n"
    )
    L.append(
        "| Function | Lines | Statements | Cited | Excluded |\n"
        "|---|---|---|---|---|"
    )
    for f in cov["functions"]:
        L.append(
            f"| {f['name']} | {f['lines'][0]}-{f['lines'][1]} | "
            f"{f['statements']} | {f['covered']} | {f['excluded']} |"
        )
    L.append("\nExcluded lines and reasons:\n")
    for e in spec["exclusions"]:
        L.append(f"- {e['lines']}: {e['reason']}")
    if cov["uncovered"]:
        L.append("\nStatements cited by no requirement:\n")
        for u in cov["uncovered"]:
            L.append(f"- L{u['line']}: `{u['text']}`")
    if (
        probe
        and probe.get("exec_coverage")
        and probe["exec_coverage"]["not_executed"]
    ):
        L.append("\nStatements the probes did not execute:\n")
        for u in probe["exec_coverage"]["not_executed"]:
            L.append(f"- L{u['line']}: `{u['text']}`")
    if rlz and rlz.get("mutants"):
        L.append(
            "\n## Sensitivity check 1: does a defect written as a "
            "requirement break realizability?\n"
        )
        L.append(
            "An original behaviour (as_is) must become realizable again "
            "when the requirement it conflicts with is removed "
            "(attribution). A hypothetical defect is a regression that "
            "the original does not have.\n"
        )
        L.append(
            "| Mutant | Origin | Component | Description | Expected "
            "conflict | Result | Without the requirement | FRET "
            "diagnosis |\n|---|---|---|---|---|---|---|---|"
        )
        for m in spec["mutants"]:
            r = rlz["mutants"].get(m["id"], {})
            dg = (r.get("diagnosis_run") or {}).get("diagnosis") or []
            found = sorted(
                {
                    q
                    for d in dg
                    for ce in d.get("Counterexamples", [])
                    for q in ce["requirements"]
                }
            )
            w = r.get("without_expected", {}).get("result", "")
            L.append(
                f"| {m['id']} | {m.get('origin', '')} | {m['component']} | "
                f"{m['desc']} | {', '.join(m['conflicts_with'])} | "
                f"{r.get('result', 'not run')} | {w} | {', '.join(found)} |"
            )
    if cmut:
        L.append(
            "\n## Sensitivity check 2: do the probes catch a code defect?\n"
        )
        L.append(
            "One defect at a time is put into a copy of core.py and the "
            "same probes are run. A mutant is caught when a requirement "
            "that holds on the original is violated.\n"
        )
        L.append(
            "| Mutant | Defect | Caught | Violated requirements |\n"
            "|---|---|---|---|"
        )
        for mid, v in cmut.items():
            L.append(_mutant_row(mid, v))
    (DOCS / "CORE_SPEC.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    sf_of: dict[str, list[str]] = {}
    for sf in spec["security_functions"]:
        for rid in sf["reqs"]:
            sf_of.setdefault(rid, []).append(sf["id"])
    with open(
        DOCS / "core_spec.csv", "w", encoding="utf-8-sig", newline=""
    ) as f:
        w = csv.writer(f)
        w.writerow(
            [
                "id",
                "component",
                "kind",
                "security_function",
                "sr",
                "asis",
                "guard",
                "asis_note",
                "observed_on_real_code",
                "description",
                "fretish",
                "code",
            ]
        )
        for r in reqs:
            o = obs(r["component"], r["id"])
            state = (
                "pending"
                if r.get("guard") == "pending"
                else "closed" if r["id"] in closed else ""
            )
            w.writerow(
                [
                    r["id"],
                    r["component"],
                    r["kind"],
                    " ".join(sf_of.get(r["id"], [])),
                    r.get("sr", ""),
                    r["asis"],
                    state,
                    r.get("asis_desc", ""),
                    (
                        ""
                        if not o
                        else f"{o['status']} ({o['checked']} observations)"
                    ),
                    r["desc"],
                    r["expanded"],
                    ", ".join(r["code"]),
                ]
            )
