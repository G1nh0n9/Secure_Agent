"""The trace evaluator (ptl.py) against NuSMV on random traces, for every compiled requirement.

NuSMV is the reference: a trace is replayed as a model whose last tick repeats forever, `LTLSPEC G <ltl_pt>` is asked, and the
verdict must equal the evaluator's verdict on the same trace extended by repeats of its last tick."""
from __future__ import annotations

import random

from . import fret_nusmv as fn
from . import ptl

INT_SIGNALS = {"steps", "max_steps"}


def _value(var: str, rng: random.Random):
    if var == "steps":
        return rng.randint(0, 5)
    if var == "max_steps":
        return rng.randint(2, 5)
    return rng.random() < 0.4


def _smv(ticks: list[dict], vars_: list[str], formula_smv: str) -> str:
    n = len(ticks) - 1
    lines = ["MODULE main", "VAR", f"  step : 0..{n};", "ASSIGN", "  init(step) := 0;",
             f"  next(step) := case step < {n} : step + 1; TRUE : step; esac;", "DEFINE"]
    for v in vars_:
        def lit(x):
            return str(x) if v in INT_SIGNALS else ("TRUE" if x else "FALSE")
        cases = " ".join(f"step = {i} : {lit(t[v])};" for i, t in enumerate(ticks[:-1]))
        lines.append(f"  {v} := case {cases} TRUE : {lit(ticks[-1][v])}; esac;")
    lines.append(f"LTLSPEC G {formula_smv}")
    return "\n".join(lines) + "\n"


def run(compiled: list[dict], traces_per_formula: int = 12, seed: int = 7) -> dict:
    rng = random.Random(seed)
    files, expected, meta = {}, {}, {}
    for c in compiled:
        ast = ptl.parse(c["ltl_pt"])
        vars_ = sorted(ptl.variables(ast))
        for k in range(traces_per_formula):
            ticks = [{v: _value(v, rng) for v in vars_} for _ in range(rng.randint(3, 8))]
            name = f"{c['id']}_t{k}"
            files[name] = _smv(ticks, vars_, ptl.to_smv(ast))
            expected[name] = ptl.check(ast, ticks + [ticks[-1]] * 12)["ok"]
            meta[name] = c["id"]
    outs = fn.run_nusmv(files, fn.RUNS / "selftest")
    per_req: dict[str, dict] = {}
    mismatches = []
    for name, exp in expected.items():
        got = fn.verdict(outs.get(name, ""))
        e = per_req.setdefault(meta[name], {"traces": 0, "agree": 0, "true": 0, "false": 0})
        e["traces"] += 1
        e["true" if exp else "false"] += 1
        if got is exp:
            e["agree"] += 1
        else:
            mismatches.append({"trace": name, "evaluator": exp, "nusmv": got})
    return {"per_requirement": per_req, "mismatches": mismatches,
            "total": sum(e["traces"] for e in per_req.values()), "agree": sum(e["agree"] for e in per_req.values())}
