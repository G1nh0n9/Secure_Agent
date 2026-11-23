"""Formal check of the tool-call monitor: FRET, NuSMV and real sessions.

The question: whatever the model says, does the monitor keep a few lines
that matter against an attacker who controls the model?  The attacker is
the environment of the model: any event can come next, any plan, any
extra grant from the verifier, any clock jump.  Five requirements in
``requirements/call_requirements.json`` say what must hold; they are
written in FRETish and compiled by the official FRET parser.

Two checks use the same compiled formulas:

* NuSMV checks them on an abstract model of the monitor
  (``model/call_monitor.smv.tpl``) over every behaviour of the
  environment.  That is a proof for the model, and a counterexample is
  an attack: a concrete event sequence the formal method found.
* The formulas are evaluated on what the real system does in generated
  sessions (:mod:`secure_agent_attach.generator`).  This links the model
  to the code: if the model and the code disagree, the two columns do.

Each check runs on the original and on the original with the guards.
The tool classes SENS and SEND of the ordering rule (assumption A-10)
are the tools ``a`` and ``t`` of the generator.
"""

from __future__ import annotations

import json

from . import fret_nusmv as fn
from . import generator, ptl
from .guard import GuardedStages

TEMPLATE = "call_monitor.smv.tpl"
# Reachability checks: the situations the requirements are about must
# be reachable, otherwise "holds" would be vacuous.
VACUITY = {
    "V1_sensitive_read_reachable": "G !exec_sens",
    "V2_send_reachable": "G !exec_send",
    "V3_blocked_send_reachable": (
        "G !(ev = CALL_SEND & ticket & g_send & tainted)"
    ),
    "V4_call_at_cap_reachable": (
        "G !(ev = LLM_CALL & in_turn & llm_calls >= 3)"
    ),
    "V5_claim_without_evidence_reachable": (
        "G !(ev = COMPLETE & in_turn & plan_tool & !ok_turn)"
    ),
    "V6_extra_grant_reachable": (
        "G !(ev = NEW_TURN & e_x_send & !e_p_send & pol_send)"
    ),
}
TRACE_KEYS = (
    "ev",
    "pol_sens",
    "pol_send",
    "p_sens",
    "p_send",
    "p_other",
    "g_sens",
    "g_send",
    "g_other",
    "ticket",
    "in_turn",
    "tainted",
    "ok_turn",
    "llm_calls",
)
SENS, SEND = "a", "t"
SIGNALS = (
    "exec_sens",
    "exec_send",
    "exec_outside_plan",
    "exec_unauthorized",
    "llm_over_cap",
    "completed_no_evidence",
)


def load_requirements() -> dict:
    """Return the call-monitor requirements and their vocabulary."""
    path = fn.ROOT / "requirements" / "call_requirements.json"
    return json.loads(path.read_text(encoding="utf-8"))


def compile_requirements() -> list[dict]:
    """Compile the requirements with the official FRET parser."""
    reqs = load_requirements()["requirements"]
    return fn.compile_requirements(reqs, "call_compiled.json")


def model_check(compiled: list[dict]) -> dict:
    """Check every requirement on both variants of the monitor model."""
    return fn.model_check(compiled, TEMPLATE, VACUITY, TRACE_KEYS)


def attack_events(rid: str, trace: list[dict]) -> list[str]:
    """Return the events of a counterexample up to the violation.

    NuSMV prints a counterexample as a lasso: a path and then a loop.
    Only the path up to the first event that breaks the requirement is
    the attack.  The signals are derived again from the printed states,
    with the semantics of the original variant, for display only.
    """
    events = []
    sensed = False
    for state in trace:
        ev = state["ev"]
        events.append(ev)
        flag = {
            k: state[k] == "TRUE"
            for k in state
            if k != "ev" and state[k] in ("TRUE", "FALSE")
        }
        granted = {
            "CALL_SENS": "g_sens",
            "CALL_SEND": "g_send",
            "CALL_OTHER": "g_other",
        }.get(ev)
        planned = {
            "CALL_SENS": "p_sens",
            "CALL_SEND": "p_send",
            "CALL_OTHER": "p_other",
        }.get(ev)
        ran = bool(granted) and flag["ticket"] and flag[granted]
        plan_tool = flag["p_sens"] or flag["p_send"] or flag["p_other"]
        if rid == "CM-02" and ran and not flag[planned]:
            return events
        if rid == "CM-03":
            if ran and ev == "CALL_SEND" and (sensed or flag["tainted"]):
                return events
            sensed = sensed or (ran and ev == "CALL_SENS")
        if rid == "CM-04" and ev == "LLM_CALL" and flag["in_turn"]:
            if int(state["llm_calls"]) >= 3:
                return events
        if (
            rid == "CM-05"
            and ev == "COMPLETE"
            and flag["in_turn"]
            and plan_tool
            and not flag["ok_turn"]
        ):
            return events
    return events


def session_ticks(run: dict) -> list[dict]:
    """Turn a real session into the ticks the requirements talk about.

    One tick per tool call that reached ``execute``, in order, then one
    tick per turn for what the turn did as a whole, then one tick for
    what the observer found out about the whole session.
    """
    idle = {name: False for name in SIGNALS}
    ticks = []
    for entry in run["executed"]:
        ticks.append(
            {
                **idle,
                "exec_sens": entry["tool"] == SENS,
                "exec_send": entry["tool"] == SEND,
                "exec_outside_plan": not entry["planned"],
            }
        )
    for turn in run["turns"]:
        result = turn["result"]
        completed = bool(result) and result.status.value == "completed"
        no_evidence = (
            completed
            and turn["last_stage"] == "evaluate"
            and turn["plan_has_tool"]
            and not any(e["ok"] for e in turn["executed"])
        )
        ticks.append(
            {
                **idle,
                "llm_over_cap": turn["over_calls"] > 0,
                "completed_no_evidence": no_evidence,
            }
        )
    unauthorized = any(t["exec_unauthorized"] for t in run["recorder"].ticks)
    ticks.append({**idle, "exec_unauthorized": unauthorized})
    return ticks


def check_sessions(
    compiled: list[dict], runs: int = 2000, stack=None, first_seed: int = 0
) -> dict:
    """Evaluate every formula on generated sessions of the real system.

    Returns:
        A dict with ``runs``, ``violations`` (requirement id to the
        number of sessions that broke it), ``seeds`` (the first few
        seeds of each, to replay) and ``tool_sessions`` (sessions in
        which a tool executed, to show how much was reached).
    """
    trees = {c["id"]: ptl.parse(c["ltl_pt"]) for c in compiled}
    counts, seeds, reached = {}, {}, 0
    for seed in range(first_seed, first_seed + runs):
        run = generator.run_one(seed, stack)
        reached += bool(run["executed"])
        ticks = session_ticks(run)
        for rid, tree in trees.items():
            if not ptl.check(tree, ticks)["ok"]:
                counts[rid] = counts.get(rid, 0) + 1
                seeds.setdefault(rid, [])
                if len(seeds[rid]) < 5:
                    seeds[rid].append(seed)
    return {
        "runs": runs,
        "violations": dict(sorted(counts.items())),
        "seeds": seeds,
        "tool_sessions": reached,
    }


def realizability() -> dict:
    """Check with Kind2 that the monitor can be implemented.

    The safety requirements alone are met by a monitor that does
    nothing.  The description in
    ``requirements/call_realizability.json`` adds the functional
    requirements (an allowed call must happen), and every input is
    unconstrained [Pnueli1989].  Each planted defect, the
    original behaviour written as a requirement, must make the set
    unrealizable, and must become realizable again when the requirement
    it conflicts with is removed.
    """
    from . import rlz
    from . import spec as sp

    path = fn.ROOT / "requirements" / "call_realizability.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    reqs = [dict(r, expanded=r["text"]) for r in doc["requirements"]]
    muts = [
        dict(
            m,
            expanded=m["text"],
            component="Monitor",
            check="attribution",
            origin="as_is",
        )
        for m in doc["mutants"]
    ]
    comp = sp.compile_texts([x["expanded"] for x in reqs + muts])
    spec = {
        "constants": {},
        "components": {
            "Monitor": {"signals": doc["signals"], "requirements": reqs}
        },
        "mutants": muts,
    }
    return rlz.run(spec, comp, only=["Monitor"])


def run_all(runs: int = 2000) -> dict:
    """Compile, model-check and evaluate on sessions."""
    from . import selftest

    compiled = compile_requirements()
    return {
        "compiled": [
            {k: c[k] for k in ("id", "fretish", "ok", "ltl_pt")}
            for c in compiled
        ],
        "model": model_check(compiled),
        "realizability": realizability(),
        "selftest": selftest.run(compiled),
        "sessions": {
            "original": check_sessions(compiled, runs),
            "guarded": check_sessions(compiled, runs, GuardedStages),
        },
    }
