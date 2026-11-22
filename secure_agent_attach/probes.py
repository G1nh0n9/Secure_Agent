"""Probes: the catalog's requirements evaluated on what the REAL original code does.

Each probe runs the unmodified original (imported read-only) with scripted LLMs, fake tools and a fake clock, and builds ticks: the
Inputs of a tick are what the probe fed in, the Outputs are what the code did. The compiled `ltl_pt` of every requirement of the
component is then evaluated on every tick that carries the signals it mentions. A requirement marked `asis: ok` must hold on every
tick; one marked `asis: gap` must be violated by at least one tick (the gap is reproduced). Anything else is a mismatch between the
catalog and the code.

The gate is enumerated exhaustively over the Boolean abstraction of its inputs (2^9 = 512 calls). The other components use
the cases that decide each requirement (every action, every decision, every kind of record, every combination of the authorizer's
checks, ...), not every combination of everything."""
from __future__ import annotations

import ast
import contextlib
import dataclasses
import io
import itertools
import json
import sys
import uuid

from . import loader, ptl
from . import spec as sp

core = loader.load_original()
ST_OF = {"analyze": "ST_ANALYZE", "authorize": "ST_AUTHORIZE", "execute": "ST_EXECUTE", "evaluate": "ST_EVALUATE", "completed": "ST_COMPLETED",
         "waiting_for_user": "ST_WAITING", "cancelled": "ST_CANCELLED", "failed": "ST_FAILED", "limit_reached": "ST_LIMIT"}


class Clock:
    def __init__(self, now: float = 100.0):
        self.now = now

    def monotonic(self):
        return self.now


@contextlib.contextmanager
def fake_clock(now: float = 100.0):
    clock, real = Clock(now), core.time
    core.time = clock
    try:
        yield clock
    finally:
        core.time = real


STAGES = None    # the guarded run puts a factory for GuardedStages here
RESTORE = None   # ... and TrustedHistory.from_jsonl here


def new_stages(*args, **kw):
    return (STAGES or core.TurnStages)(*args, **kw)


def st(C: dict, state) -> int:
    return C[ST_OF[state.value]]


def blank(spec: dict, cname: str) -> dict:
    """Every signal of a component with a neutral value; a probe overwrites what it observed or fed in."""
    return {n: (0 if s[1] == "integer" else False) for n, s in spec["components"][cname]["signals"].items()}


def mk_tool(name="t", calls=None, valid=True, res=("r1",), fails=False, result="ok"):
    calls = [] if calls is None else calls

    def validate(a):
        calls.append("validate")
        if not valid:
            raise ValueError("bad arguments")
        return dict(a)

    def resources(a):
        calls.append("resources")
        return tuple(res)

    def execute(a):
        calls.append("execute")
        if fails:
            raise RuntimeError("tool failed")
        return result

    return core.ToolDefinition(description=f"{name} tool", parameters={"type": "object", "properties": {}}, resource_hint="target",
                               validate=validate, resources=resources, execute=execute)


def new_ctx(text="x", session="sess", turn=1):
    instr = core.UserInstruction(session, turn, text)
    return instr, core.TurnContext(instr, core.ConversationHistory(session))


def put_ticket(stages, ctx, instr, tid="T1", grants=(("t", ("r1",)),), expires=500.0, calls_used=0, max_calls=12, session=None, task=None):
    t = core.CapabilityTicket(task_id=task or instr.task_id, ticket_id=tid, session_id=session or instr.session_id, grants=grants, expires_at=expires, max_calls=max_calls)
    stages._tickets[tid] = t
    stages._ticket_calls[tid] = calls_used
    ctx.ticket = tid
    return t


# ---------------------------------------------------------------- Gate (exhaustive)

def probe_gate(spec, C):
    ticks = []
    for found, bound, expired, granted, registered, valid, res_in, budget, fails in itertools.product([False, True], repeat=9):
        with fake_clock(100.0):
            calls, seen = [], {}

            def validate(a, calls=calls, seen=seen, valid=valid):
                calls.append("validate")
                seen["validate_arg"] = a
                a["mutated"] = True                      # a copy must absorb this
                if not valid:
                    raise ValueError("bad arguments")
                seen["checked"] = {"target": "r1"}
                return seen["checked"]

            def resources(a, calls=calls, seen=seen, res_in=res_in):
                calls.append("resources")
                seen["resources_arg"] = a
                return ("r1",) if res_in else ("zzz",)

            def execute(a, calls=calls, seen=seen, fails=fails):
                calls.append("execute")
                seen["execute_arg"] = a
                if fails:
                    raise RuntimeError("tool failed")
                return "ok"

            tool = core.ToolDefinition(description="t", parameters={}, resource_hint="x", validate=validate, resources=resources, execute=execute)
            stages = new_stages(tools={"t": tool} if registered else {}, max_tool_calls=2)
            instr, ctx = new_ctx()
            ticket = before = None
            if found:
                ticket = put_ticket(stages, ctx, instr, grants=(("t", ("r1",)),) if granted else (("other", ("r1",)),),
                                    expires=50.0 if expired else 500.0, calls_used=0 if budget else 2, max_calls=2,
                                    session="sess" if bound else "other", task=instr.task_id if bound else "sess:99")
                before = (dataclasses.astuple(ticket), stages._ticket_calls["T1"])
            else:
                ctx.ticket = "missing"
            args = {"target": "r1"}
            exc = None
            if hasattr(stages, "recorder"):
                stages.recorder.begin("execute")      # the observer expects a stage to be open
            try:
                stages._execute_tool(ctx, "t", args)
            except Exception as e:  # noqa: BLE001
                exc = e
            t = {"_label": f"found={found} bound={bound} expired={expired} granted={granted} registered={registered} valid={valid} res_in={res_in} budget={budget} fails={fails}",
                 "g_ticket_found": found, "g_ticket_bound": bound, "g_ticket_expired": expired, "g_tool_granted": granted, "g_tool_registered": registered,
                 "g_args_valid": valid, "g_resources_in_grants": res_in, "g_budget_left": budget, "g_execute_fails": fails,
                 "g_validate_called": "validate" in calls, "g_resources_called": "resources" in calls, "g_execute_called": "execute" in calls,
                 "g_counter_incremented": bool(found and stages._ticket_calls.get("T1") == before[1] + 1),
                 "g_permission_denied": isinstance(exc, PermissionError), "g_tool_error": exc is not None and not isinstance(exc, PermissionError),
                 "g_result_returned": exc is None,
                 "g_ticket_changed": bool(found and (stages._tickets.get("T1") is not ticket or dataclasses.astuple(stages._tickets["T1"]) != before[0]))}
            if "validate" in calls:
                t["g_args_copied"] = "mutated" not in args and seen["validate_arg"] is not args
            if "execute" in calls:
                t["g_same_checked_args"] = seen.get("checked") is not None and seen["checked"] is seen.get("resources_arg") and seen["checked"] is seen.get("execute_arg")
            ticks.append(t)
    return ticks


# ---------------------------------------------------------------- Ticket

def probe_ticket(spec, C):
    ticks = []
    for present in (True, False):
        stages = new_stages()
        instr, ctx = new_ctx()
        if present:
            put_ticket(stages, ctx, instr)
        else:
            ctx.ticket = "gone"
        err = None
        try:
            stages.revoke_ticket(ctx)
        except Exception as e:  # noqa: BLE001
            err = e
        ticks.append({"_label": f"revoke, ticket present={present}", "t_revoke_requested": True, "t_ticket_present": present,
                      "t_ticket_removed": "T1" not in stages._tickets, "t_counter_removed": "T1" not in stages._ticket_calls,
                      "t_context_cleared": ctx.ticket is None, "t_error": err is not None})
    stages = new_stages()
    instr, ctx = new_ctx()
    t = put_ticket(stages, ctx, instr)
    try:
        t.grants = ()
        mutated = True
    except dataclasses.FrozenInstanceError:
        mutated = False
    fields = {f.name for f in dataclasses.fields(core.CapabilityTicket)}
    ticks.append({"_label": "ticket data model", "t_ticket_mutated_in_place": mutated, "t_binding_fields_present": {"task_id", "session_id"} <= fields,
                  "t_has_expiry": "expires_at" in fields, "t_has_call_budget": "max_calls" in fields})
    return ticks


# ---------------------------------------------------------------- Authorizer

POLICY = {"read_file": ("reports/a.txt",), "send_email": ("team@corp",)}
GADGETS = [("in_plan", {"tool": "read_file", "resources": ["reports/a.txt"]}), ("outside_plan", {"tool": "send_email", "resources": ["team@corp"]}),
           ("exceeds", {"tool": "read_file", "resources": ["secrets/x"]}), ("unknown", {"tool": "ghost", "resources": ["x"]}),
           ("no_scope", {"tool": "ping", "resources": ["x"]})]


def probe_authorizer(spec, C):
    ticks, seen_ids = [], set()
    plan_steps = {"none": None, "notool": (core.PlannedStep("0", "think", None, ()),),
                  "read": (core.PlannedStep("0", "read", "read_file", ("reports/a.txt",)),)}
    for plan_kind, err, subset in itertools.product(plan_steps, (False, True), itertools.product([False, True], repeat=len(GADGETS))):
        chosen = {name for (name, _), on in zip(GADGETS, subset) if on}
        grants = [g for name, g in GADGETS if name in chosen]
        llm_calls, payloads = [], []

        def call_llm(messages, tools, json_output, grants=grants, err=err, llm_calls=llm_calls, payloads=payloads):
            llm_calls.append(1)
            payloads.append(json.loads(messages[1]["content"]))
            return {"content": "not json"} if err else {"content": json.dumps({"grants": grants, "declines": []})}

        with fake_clock(1000.0) as clock:
            tools = {n: mk_tool(n) for n in ("read_file", "send_email", "ping")}
            stages = new_stages(call_llm, tools=tools, agent_permissions=POLICY, user_permissions=POLICY, ticket_ttl=300, max_tool_calls=12)
            instr, ctx = new_ctx()
            ctx.plan = None if plan_steps[plan_kind] is None else core.TaskPlan(instr.task_id, "obj", plan_steps[plan_kind])
            res, exc = None, None
            try:
                res = stages.authorize_task(ctx)
            except Exception as e:  # noqa: BLE001
                exc = e
            plan_pairs = {("read_file", "reports/a.txt")} if plan_kind == "read" else set()
            conf_pairs = {(g["tool"], r) for g in grants for r in g["resources"]}
            in_policy = lambda p: p[0] in POLICY and p[1] in POLICY[p[0]]   # noqa: E731
            issued = ctx.ticket in stages._tickets
            t = {"_label": f"plan={plan_kind} verifier_error={err} grants={sorted(chosen)}",
                 "a_plan_present": plan_kind != "none", "a_plan_has_tool_steps": plan_kind == "read", "a_verifier_error": err,
                 "a_any_unknown_tool": "unknown" in chosen, "a_any_scope_missing": "no_scope" in chosen, "a_any_exceeds_policy": "exceeds" in chosen,
                 "a_any_outside_plan": bool(conf_pairs - plan_pairs), "a_usable_empty": not ("in_plan" in chosen and plan_kind == "read"),
                 "a_verifier_called": bool(llm_calls), "a_llm_calls": len(llm_calls),
                 "a_result_failed": res is not None and res.next_state == core.TurnState.FAILED,
                 "a_result_execute": res is not None and res.next_state == core.TurnState.EXECUTE,
                 "a_ticket_issued": issued, "a_message_nonempty": bool(res and res.message), "a_error_propagated": exc is not None}
            if payloads:
                expected = [] if plan_kind != "read" else [{"tool": "read_file", "resources": ["reports/a.txt"], "description": "read"}]
                t["a_request_from_plan_only"] = payloads[0] == {"objective": "obj", "requested_grants": expected}
            if issued:
                tk = stages._tickets[ctx.ticket]
                pairs = {(n, r) for n, rs in tk.grants for r in rs}
                t.update({"a_issued_outside_plan": bool(pairs - plan_pairs), "a_issued_beyond_policy": not all(in_policy(p) for p in pairs),
                          "a_issued_beyond_verifier": bool(pairs - conf_pairs), "a_grants_trimmed": bool({p for p in conf_pairs if in_policy(p)} - pairs),
                          "a_ticket_bound_to_task": (tk.session_id, tk.task_id) == (instr.session_id, instr.task_id),
                          "a_ticket_has_expiry": tk.expires_at == clock.now + 300, "a_ticket_has_call_budget": tk.max_calls == 12,
                          "a_ticket_id_fresh": tk.ticket_id not in seen_ids and bool(uuid.UUID(tk.ticket_id)), "a_ticket_stored": ctx.ticket == tk.ticket_id,
                          "a_counter_zero": stages._ticket_calls.get(tk.ticket_id) == 0})
                seen_ids.add(tk.ticket_id)
            else:
                t.update({"a_issued_outside_plan": False, "a_issued_beyond_policy": False, "a_issued_beyond_verifier": False, "a_grants_trimmed": False})
            ticks.append(t)
    return ticks


# ---------------------------------------------------------------- Analyzer

PLAN_JSON = {"action": "analyze", "objective": "o", "steps": [{"description": "d", "tool": "read_file", "resources": ["reports/a.txt"]}]}


def probe_analyzer(spec, C):
    ticks = []
    ACT = {"respond": C["ACT_RESPOND"], "clarify": C["ACT_CLARIFY"], "history": C["ACT_HISTORY"], "plan": C["ACT_PLAN"]}
    R, Q = {"action": "respond", "message": "R-text"}, {"action": "clarify", "message": "Q-text"}
    H = {"action": "history", "reason": "r", "turn_ids": [1]}
    cases = [("budget exhausted", False, False, "plan", "plan", [])]
    for label, resp in (("invalid JSON", ["not json"]), ("JSON list", ["[1]"]), ("malformed step", [json.dumps({"action": "analyze", "steps": [1]})]), ("llm raises", [RuntimeError])):
        cases.append((label, True, True, "plan", "plan", resp))
    cases += [("respond", True, False, "respond", "plan", [R]), ("clarify", True, False, "clarify", "plan", [Q]), ("plan", True, False, "plan", "plan", [PLAN_JSON]),
              ("other action", True, False, "plan", "plan", [{"action": "zzz", "objective": "o", "steps": []}]),
              ("no action key", True, False, "plan", "plan", [{"objective": "o", "steps": []}])]
    for second_name, second in (("respond", R), ("clarify", Q), ("history", H), ("plan", PLAN_JSON)):
        cases.append((f"history then {second_name}", True, False, "history", second_name, [H, second]))
    for label, budget, err, first, second, script in cases:
        script = list(script)
        calls = []

        def call_llm(messages, tools, json_output, script=script, calls=calls):
            calls.append({"messages": messages, "tools": tools})
            item = script[len(calls) - 1] if len(calls) <= len(script) else script[-1]
            if item is RuntimeError:
                raise RuntimeError("llm down")
            return {"content": item if isinstance(item, str) else json.dumps(item)}

        stages = new_stages(call_llm, tools={"read_file": mk_tool("read_file")}, agent_permissions=POLICY, user_permissions=POLICY)
        instr, ctx = new_ctx(text="please read")
        ctx.history.add_user(instr)                    # process_turn does this before the first stage
        ctx.analysis_calls = 0 if budget else stages.max_analysis_calls
        before = ctx.analysis_calls
        res, exc = None, None
        try:
            res = stages.analyze_instruction(ctx)
        except Exception as e:  # noqa: BLE001
            exc = e
        t = {"_label": label, "n_budget_left": budget, "n_error": err, "n_action": ACT[first], "n_action2": ACT[second],
             "n_next": st(C, res.next_state) if res else 0, "n_llm_calls": len(calls), "n_counter_incremented": ctx.analysis_calls == before + 1,
             "n_plan_created": ctx.plan is not None, "n_context_updated": ctx.plan is not None and ctx.analysis is not None, "n_error_propagated": exc is not None,
             "n_ticket_touched": bool(stages._tickets) or ctx.ticket is not None, "n_tool_executed": False,
             "n_message_from_llm": bool(res and res.message in ("R-text", "Q-text")), "n_recall_recorded": bool(ctx.recalled_turns), "n_input_from_history_and_registry": False}
        if calls:
            m = calls[0]["messages"]
            payload = json.loads(m[1]["content"])
            t["n_input_from_history_and_registry"] = (set(payload) == {"instruction"} and payload["instruction"].get("kind") == "user"
                                                      and payload["instruction"].get("content") == "please read" and "read_file" in m[0]["content"])
        ticks.append(t)
    return ticks


# ---------------------------------------------------------------- Executor

def probe_executor(spec, C):
    ticks = []
    GO = {"ok": C["GO_OK"], "denied": C["GO_DENIED"], "error": C["GO_TOOL_ERROR"]}
    for valid, budget, llm_err, calls_tools, exceeds, parse_ok, outcome, serial, text in itertools.product(
            (False, True), (False, True), (False, True), (False, True), (False, True), (False, True), ("ok", "denied", "error"), (False, True), (False, True)):
        with fake_clock(100.0):
            tool_calls_log, llm_log, gate_log = [], [], []
            tool = mk_tool("t", tool_calls_log, res=("r1",) if outcome != "denied" else ("zzz",), fails=(outcome == "error"),
                           result="ok" if serial else object())
            good = {"function": {"name": "t", "arguments": json.dumps({"target": "r1"})}}
            first = {"function": {"name": "t", "arguments": json.dumps({"target": "r1"}) if parse_ok else "{not json"}}

            def call_llm(messages, tools, json_output, llm_log=llm_log, llm_err=llm_err, calls_tools=calls_tools, text=text, first=first, good=good):
                llm_log.append(tools)
                if llm_err:
                    raise RuntimeError("llm down")
                if calls_tools:
                    return {"content": "interim" if text else None, "tool_calls": [first, good]}
                return {"content": "final text", "tool_calls": None}

            stages = new_stages(call_llm, tools={"t": tool, "u": mk_tool("u")}, max_worker_calls=8, max_tool_calls=12)   # "u" is registered but never granted
            orig_gate = stages._execute_tool

            def gate(context, name, arguments, orig=orig_gate, gate_log=gate_log):
                last = context.history.entries[-1]
                gate_log.append({"recorded": last.kind == "tool_call" and last.tool_name == name, "attempts": context.tool_attempts})
                return orig(context, name, arguments)

            stages._execute_tool = gate
            instr, ctx = new_ctx()
            if valid:
                put_ticket(stages, ctx, instr)
            ctx.worker_calls = 0 if budget else 8
            ctx.tool_attempts = 11 if exceeds else 0
            err, res = None, None
            with contextlib.redirect_stderr(io.StringIO()):
                try:
                    res = stages.execute_task(ctx)
                except Exception as e:  # noqa: BLE001
                    err = e
            ents = ctx.history.entries
            results = [e for e in ents if e.kind == "tool_result"]
            failed_call = bool(gate_log) and (outcome != "ok" or not serial)
            t = {"_label": f"valid={valid} budget={budget} llm_err={llm_err} calls={calls_tools} exceeds={exceeds} parse={parse_ok} outcome={outcome} serial={serial} text={text}",
                 "x_ticket_valid": valid, "x_worker_budget_left": budget, "x_llm_error": llm_err, "x_worker_calls_tools": calls_tools, "x_batch_exceeds_budget": exceeds,
                 "x_args_parse_ok": parse_ok, "x_gate_outcome": GO[outcome], "x_result_serializable": serial, "x_worker_text_present": text,
                 "x_llm_called": bool(llm_log), "x_schemas_only_granted": all({f["function"]["name"] for f in tools} <= {"t"} for tools in llm_log),
                 "x_next": st(C, res.next_state) if res else 0, "x_error_propagated": err is not None,
                 "x_work_result_recorded": ctx.work_result == "final text" and bool(ents) and ents[-1].kind == "assistant" and ents[-1].content == "final text",
                 "x_gate_invoked": bool(gate_log), "x_call_recorded_before_gate": bool(gate_log) and all(g["recorded"] for g in gate_log),
                 "x_attempt_counted": bool(gate_log) and all(g["attempts"] >= 1 for g in gate_log),
                 "x_error_type_only": bool(results) and results[0].is_error and set(json.loads(results[0].content)) == {"error_type"},
                 "x_later_calls_skipped": len(gate_log) == 1 if gate_log else True,
                 "x_result_recorded": bool(results) and not results[0].is_error and set(json.loads(results[0].content)) == {"result"},
                 "x_interim_text_recorded": any(e.kind == "assistant" and e.content == "interim" for e in ents),
                 "x_tool_run_outside_gate": tool_calls_log.count("execute") > len(gate_log)}
            if failed_call:
                t["x_later_calls_skipped"] = len(gate_log) == 1
            ticks.append(t)
    return ticks


# ---------------------------------------------------------------- Evaluator

def probe_evaluator(spec, C):
    ticks = []
    DEC = {"completed": C["DEC_COMPLETED"], "execute": C["DEC_EXECUTE"], "authorize": C["DEC_AUTHORIZE"], "analyze": C["DEC_ANALYZE"], "ask": C["DEC_ASK"], "failed": C["DEC_FAILED"]}
    cases = [(f"decision {n}", code, False, True, {"decision": n, "message": "M-text"}) for n, code in DEC.items()]
    cases += [(f"decision {n}, no message", code, False, False, {"decision": n}) for n, code in DEC.items()]
    cases += [("unknown decision", 0, False, True, {"decision": "bogus", "message": "M-text"}), ("decision is null", 99, False, True, {"decision": None, "message": "M-text"}),
              ("invalid JSON", 0, True, True, "not json"), ("JSON list", 0, True, True, "[1]"), ("llm raises", 0, True, True, RuntimeError)]
    for label, code, err, msg, resp in cases:
        log, tool_log = [], []

        def call_llm(messages, tools, json_output, resp=resp, log=log):
            log.append(1)
            if resp is RuntimeError:
                raise RuntimeError("llm down")
            return {"content": resp if isinstance(resp, str) else json.dumps(resp)}

        stages = new_stages(call_llm, tools={"t": mk_tool("t", tool_log)})
        instr, ctx = new_ctx()
        res, exc = None, None
        try:
            res = stages.evaluate_result(ctx)
        except Exception as e:  # noqa: BLE001
            exc = e
        ticks.append({"_label": label, "v_llm_error": err, "v_message_present": msg, "v_decision": code, "v_next": st(C, res.next_state) if res else 0,
                      "v_error_propagated": exc is not None, "v_llm_calls": len(log), "v_ticket_touched": bool(stages._tickets) or ctx.ticket is not None,
                      "v_tool_executed": "execute" in tool_log, "v_message_is_llm_text": bool(res and res.message == "M-text")})
    return ticks


# ---------------------------------------------------------------- History

def _rec(kind, content=None, session="s", turn=1, **kw):
    r = {"session_id": session, "task_id": f"{session}:{turn}" if turn is not None else None, "turn_id": turn, "kind": kind, "content": content,
         "call_id": None, "tool_name": None, "arguments": None, "is_error": False}
    r.update(kw)
    return r


def probe_history(spec, C):
    ticks = []

    def tick(label, op, before, after, **kw):
        new = after[len(before):]
        t = blank(spec, "History")
        t.update({"_label": label, "h_op": C[op], "h_entry_appended": len(after) > len(before),
                  "h_managed_entry_added": any(e.kind == "managed" for e in new), "h_tool_entry_added": any(e.kind in ("tool_call", "tool_result") for e in new)})
        t.update(kw)
        ticks.append(t)

    h = core.ConversationHistory("s")
    try:
        h.session_id = "other"
        fixed = False
    except AttributeError:
        fixed = True
    ticks.append({**blank(spec, "History"), "_label": "create", "h_op": C["OP_CREATE"], "h_history_empty": len(h.entries) == 0, "h_session_fixed": fixed and h.session_id == "s"})
    h = core.ConversationHistory("s")
    b = h.entries
    h.add_managed_prompt("op")
    tick("add_managed_prompt", "OP_ADD_MANAGED", b, h.entries)
    b = h.entries
    h.add_user(core.UserInstruction("s", 1, "hi"))
    tick("add_user", "OP_ADD_USER", b, h.entries, h_turn_registered=h.next_turn_id == 2)
    b = h.entries
    h.add_assistant(1, "yo")
    tick("add_assistant", "OP_ADD_ASSISTANT", b, h.entries)
    args = {"a": [1]}
    b = h.entries
    h.add_tool_call(1, "c1", "t", args)
    args["a"].append(2)
    tick("add_tool_call", "OP_ADD_TOOL_CALL", b, h.entries, h_args_deep_copied=h.entries[-1].arguments == {"a": [1]})
    b = h.entries
    h.add_tool_result(1, "c1", "R")
    tick("add_tool_result", "OP_ADD_TOOL_RESULT", b, h.entries)
    e = h.entries
    e[-2].arguments["a"].append(99)
    tick("entries", "OP_ENTRIES", e, h.entries, h_returns_copy=h.entries[-2].arguments == {"a": [1]})
    h2 = core.ConversationHistory("s")
    h2.add_user(core.UserInstruction("s", 1, "a"))
    h2.add_user(core.UserInstruction("s", 3, "b"))
    tick("next_turn_id", "OP_NEXT_TURN", h2.entries, h2.entries, h_next_turn_max_plus_one=h2.next_turn_id == 4)
    f = h.fork()
    n = len(h.entries)
    f.add_assistant(1, "only in fork")
    tick("fork", "OP_FORK", h.entries, h.entries, h_fork_new_session=f.session_id != h.session_id, h_fork_independent=len(h.entries) == n and len(f.entries) == n + 1)
    lines = list(h.to_jsonl())
    recs = [json.loads(x) for x in lines]
    ok = len(recs) == len(h.entries) and all(r["session_id"] == h.session_id and r["task_id"] == (f"{h.session_id}:{en.turn_id}" if en.turn_id is not None else None)
                                             and r["kind"] == en.kind and r["content"] == en.content for r, en in zip(recs, h.entries))
    tick("to_jsonl", "OP_EXPORT", h.entries, h.entries, h_export_complete=ok)
    base = _rec("user", "hello")
    cases = [("normal assistant record", [base, _rec("assistant", "TEST-REC")], {}),
             ("normal instruction record (no kind)", [base, {"session_id": "s", "turn_id": 2, "text": "TEST-REC"}], {}),
             ("managed record", [base, _rec("managed", "TEST-REC", turn=None)], {"h_record_kind_managed": True}),
             ("managed record as the first record", [_rec("managed", "TEST-REC", turn=None), base], {"h_record_kind_managed": True}),
             ("tool_call record", [base, _rec("tool_call", None, call_id="c1", tool_name="TEST-REC", arguments={})], {"h_record_kind_tool": True}),
             ("tool_result record", [base, _rec("tool_result", "TEST-REC", call_id="c1")], {"h_record_kind_tool": True}),
             ("unknown kind", [base, _rec("weird", "TEST-REC")], {"h_record_kind_unknown": True}),
             ("record of another session", [base, _rec("assistant", "TEST-REC", session="other")], {"h_record_foreign_session": True}),
             ("managed record of another session", [base, _rec("managed", "TEST-REC", session="other", turn=None)], {"h_record_kind_managed": True, "h_record_foreign_session": True}),
             ("extra key", [base, {**_rec("assistant", "TEST-REC"), "zzz": 1}], {"h_record_malformed": True}),
             ("missing session_id", [base, {k: v for k, v in _rec("assistant", "TEST-REC").items() if k != "session_id"}], {"h_record_malformed": True}),
             ("empty stream", [], {"h_stream_empty": True})]
    for label, recs, flags in cases:
        hist, err = None, None
        try:
            hist = (RESTORE or core.ConversationHistory.from_jsonl)(json.dumps(r) for r in recs)
        except Exception as ex:  # noqa: BLE001
            err = ex
        es = list(hist.entries) if hist else []
        hit = [x for x in es if "TEST-REC" in (x.content or "") or x.tool_name == "TEST-REC"]
        t = blank(spec, "History")
        t.update({"_label": label, "h_op": C["OP_RESTORE"], "h_entry_appended": bool(hit), "h_managed_entry_added": any(x.kind == "managed" for x in hit),
                  "h_tool_entry_added": any(x.kind in ("tool_call", "tool_result") for x in hit), "h_record_rejected": err is not None or not hit,
                  "h_error": err is not None, "h_history_returned": hist is not None})
        t.update(flags)
        ticks.append(t)
    return ticks


# ---------------------------------------------------------------- Instruction

def probe_instruction(spec, C):
    ticks = []
    u = core.UserInstruction("s", 1, "t")
    try:
        u.text = "x"
        mutable = True
    except dataclasses.FrozenInstanceError:
        mutable = False
    try:
        core.UserInstruction("s", 1, "t", task_id="evil")
        supplied = True
    except TypeError:
        supplied = False
    ticks.append({**blank(spec, "Instruction"), "_label": "construct", "i_op": C["IOP_CONSTRUCT"], "i_task_id_derived": u.task_id == "s:1" and not supplied, "i_mutable_after_creation": mutable})
    for label, line, flags in (("blank line", "   ", {"i_line_blank": True}), ("well-formed", '{"session_id":"s","turn_id":1,"text":"hi"}', {}),
                               ("with task_id", '{"session_id":"s","turn_id":1,"text":"hi","task_id":"x"}', {"i_record_has_task_id": True}),
                               ("missing text", '{"session_id":"s","turn_id":1}', {"i_record_malformed": True}),
                               ("extra key", '{"session_id":"s","turn_id":1,"text":"hi","zzz":1}', {"i_record_malformed": True})):
        got, err = [], None
        try:
            got = list(core.UserInstruction.from_jsonl([line]))
        except Exception as e:  # noqa: BLE001
            err = e
        t = blank(spec, "Instruction")
        t.update({"_label": label, "i_op": C["IOP_PARSE"], "i_instruction_yielded": bool(got), "i_error": err is not None, **flags})
        ticks.append(t)
    return ticks


# ---------------------------------------------------------------- Config

def probe_config(spec, C):
    ticks = []
    s = new_stages()
    t = blank(spec, "Config")
    t.update({"_label": "defaults", "c_construct": True, "c_use_defaults": True, "c_max_analysis": s.max_analysis_calls, "c_max_worker": s.max_worker_calls,
              "c_max_tools": s.max_tool_calls, "c_ttl": s.ticket_ttl, "c_ticket_exists_after": bool(s._tickets)})
    ticks.append(t)
    perms = {"t": ["a"]}
    s = new_stages(agent_permissions=perms, user_permissions=perms)
    exists = bool(s._tickets)
    perms["t"].append("b")
    perms["u"] = ["x"]
    t = blank(spec, "Config")
    t.update({"_label": "caller mutates the permission tables", "c_construct": True, "c_caller_mutates_policy_later": True, "c_ticket_exists_after": exists,
              "c_policy_widened": "b" in s.agent_permissions["t"] or "u" in s.agent_permissions or "b" in s.user_permissions["t"] or "u" in s.user_permissions})
    ticks.append(t)
    tools = {"t": mk_tool("t")}
    s = new_stages(tools=tools)
    exists = bool(s._tickets)
    tools["new"] = mk_tool("new")
    t = blank(spec, "Config")
    t.update({"_label": "caller mutates the tool registry", "c_construct": True, "c_caller_mutates_tools_later": True, "c_ticket_exists_after": exists, "c_registry_changed": "new" in s.tools})
    ticks.append(t)
    grant = {"grants": [{"tool": "t", "resources": ["r1"]}], "declines": []}
    s = new_stages(lambda m, tl, j: {"content": json.dumps(grant)}, tools={"t": mk_tool("t")})
    exists = bool(s._tickets)
    instr, ctx = new_ctx()
    ctx.plan = core.TaskPlan(instr.task_id, "o", (core.PlannedStep("0", "d", "t", ("r1",)),))
    res = s.authorize_task(ctx)
    t = blank(spec, "Config")
    t.update({"_label": "no permission tables", "c_construct": True, "c_no_permissions_given": True, "c_ticket_exists_after": exists,
              "c_any_grant_possible": res.next_state == core.TurnState.EXECUTE or ctx.ticket in s._tickets})
    ticks.append(t)
    return ticks


# ---------------------------------------------------------------- LlmIO

def probe_llmio(spec, C):
    ticks = []
    src = (loader.pin.original_root() / "src" / "core.py").read_text(encoding="utf-8")
    dangerous = {n.func.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("eval", "exec", "compile", "__import__")}
    static = {"l_output_executed": bool(dangerous)}

    def base(label, **kw):
        t = blank(spec, "LlmIO")
        t.update({"_label": label, **static, **kw})
        ticks.append(t)

    raw = {"content": "x", "tool_calls": None}
    s = new_stages(lambda m, t, j: raw)
    base("call, plain", l_op=C["LOP_CALL"], l_json_requested=False, l_response_passthrough=s._call([]) is raw)
    s = new_stages(lambda m, t, j: {"content": '{"a": 1}'})
    got = s._call([], json_output=True)
    base("call, json ok", l_op=C["LOP_CALL"], l_json_requested=True, l_output_valid_json=True, l_json_parsed=got == {"a": 1})
    s = new_stages(lambda m, t, j: {"content": "nope"})
    try:
        s._call([], json_output=True)
        err = False
    except Exception:  # noqa: BLE001
        err = True
    base("call, json invalid", l_op=C["LOP_CALL"], l_json_requested=True, l_output_valid_json=False, l_error_propagated=err)
    s = new_stages()
    instr, ctx = new_ctx()
    ctx.history.add_managed_prompt("MANAGED-ONE")
    ctx.history.add_managed_prompt("MANAGED-TWO")
    sysmsg = s._system(ctx, "INSTR")
    base("system prompt", l_op=C["LOP_SYSTEM"], l_managed_in_system_prompt="MANAGED-ONE" in sysmsg and "MANAGED-TWO" in sysmsg)
    hist = core.ConversationHistory("s")
    hist.add_managed_prompt("M-text")
    hist.add_user(core.UserInstruction("s", 1, "U-text"))
    hist.add_assistant(1, "A-text")
    hist.add_tool_call(1, "c1", "t", {})
    hist.add_tool_result(1, "c1", "R-text")
    ctx2 = core.TurnContext(core.UserInstruction("s", 2, "x"), hist)
    msgs = s._messages(ctx2)
    ROLE = {"user": C["ROLE_USER"], "assistant": C["ROLE_ASSISTANT"], "tool": C["ROLE_TOOL"]}
    probes = [("managed", "KIND_MANAGED", lambda m: m.get("content") == "M-text"), ("user", "KIND_USER", lambda m: m.get("content") == "U-text"),
              ("assistant", "KIND_ASSISTANT", lambda m: m.get("content") == "A-text"),
              ("tool_call", "KIND_TOOL_CALL", lambda m: any(c["id"] == "c1" for c in (m.get("tool_calls") or []))),
              ("tool_result", "KIND_TOOL_RESULT", lambda m: m.get("content") == "R-text")]
    for label, kind, match in probes:
        hit = [m for m in msgs if match(m)]
        base(f"message of kind {label}", l_op=C["LOP_MESSAGES"], l_entry_kind=C[kind], l_msg_emitted=bool(hit), l_role=ROLE.get(hit[0]["role"], 0) if hit else 0)
    return ticks


# ---------------------------------------------------------------- Data

def probe_data(spec, C):
    frozen = []
    samples = [core.TaskRecord("t"), core.ProcessingResult(message="m"), core.ConversationEntry(None, "user", "x"), core.PlannedStep("0", "d", None, ()),
               core.TaskPlan("t", "o", ()), core.StageResult(core.TurnState.COMPLETED), core.TurnResult("t", core.TurnState.COMPLETED, 0),
               core.ToolDefinition("d", {}, "h", lambda a: a, lambda a: (), lambda a: a), core.UserInstruction("s", 1, "t")]
    for obj in samples:
        field = dataclasses.fields(obj)[0].name
        try:
            setattr(obj, field, getattr(obj, field))
            frozen.append(False)
        except dataclasses.FrozenInstanceError:
            frozen.append(True)
    seen = []

    class Spy:
        def __init__(self):
            self.n = 0

        def _h(self, state):
            def h(context):
                seen.append(context)
                return core.StageResult(core.TurnState.COMPLETED, message="done")
            return h

        def revoke_ticket(self, context):
            context.ticket = None

        @property
        def analyze_instruction(self):
            return self._h("a")

        authorize_task = execute_task = evaluate_result = analyze_instruction

    for i in (1, 2):
        core.process_turn(core.UserInstruction("s", i, "x"), core.ConversationHistory("s"), stages=Spy())
    return [{**blank(spec, "Data"), "_label": "static facts", "d_record_mutated_in_place": not all(frozen), "d_state_count": len(core.TurnState),
             "d_context_new_per_turn": len(seen) == 2 and seen[0] is not seen[1]}]


# ---------------------------------------------------------------- Turn (scripted stages, one tick per loop iteration plus the exit)

def _run_turn(C, script, max_steps=20, cancel_at=None, dup=False, deny_exc=PermissionError):
    """script: state name -> list of outcomes: ('ok', next_state_name, message) or ('raise', ExcClass, text, blocked)."""
    events, cancels = [], {"n": 0}
    state_of = {"analyze": core.TurnState.ANALYZE, "authorize": core.TurnState.AUTHORIZE, "execute": core.TurnState.EXECUTE, "evaluate": core.TurnState.EVALUATE,
                "completed": core.TurnState.COMPLETED, "failed": core.TurnState.FAILED, "waiting": core.TurnState.WAITING_FOR_USER}
    plan = {k: list(v) for k, v in script.items()}
    last_len = {"n": 0}

    class Stub:
        def revoke_ticket(self, context):
            events.append(("revoke",))
            context.ticket = None

        def _h(self, name):
            def h(context):
                out = plan[name].pop(0) if plan[name] else ("ok", "completed", "")
                events.append(("handler", name, context.feedback, out, context.history.entries[-1].kind))
                if out[0] == "raise":
                    raise out[1](out[2])
                if dup and out[2]:
                    context.history.add_assistant(context.instruction.turn_id, out[2])
                last_len["n"] = len(context.history.entries)
                return core.StageResult(state_of[out[1]], message=out[2])
            return h

        def __getattr__(self, name):
            return {"analyze_instruction": self._h("analyze"), "authorize_task": self._h("authorize"), "execute_task": self._h("execute"), "evaluate_result": self._h("evaluate")}[name]

    def should_cancel():
        cancels["n"] += 1
        v = cancel_at is not None and cancels["n"] >= cancel_at
        events.append(("cancel_check", v))
        return v

    hist = core.ConversationHistory("s")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        res = core.process_turn(core.UserInstruction("s", 1, "x"), hist, stages=Stub(), max_steps=max_steps, should_cancel=should_cancel)
    return events, res, hist, err.getvalue(), last_len["n"]


def probe_turn(spec, C):
    ticks = []
    B = lambda *a: ("ok",) + a   # noqa: E731
    happy = {"analyze": [B("authorize", "")], "authorize": [B("execute", "")], "execute": [B("evaluate", "")], "evaluate": [B("completed", "done")]}
    scenarios = [
        ("normal", dict(script=happy)),
        ("cancel before the second iteration", dict(script=happy, cancel_at=2)),
        ("cancel before the first iteration", dict(script=happy, cancel_at=1)),
        ("step limit", dict(script={"analyze": [B("authorize", "")], "authorize": [B("execute", "")], "execute": [B("evaluate", "")], "evaluate": [B("execute", "")] * 9}, max_steps=3)),
        ("handler raises once, then succeeds", dict(script={**happy, "analyze": [("raise", ValueError, "boom", False), B("authorize", "")]})),
        ("blocked start, repeated", dict(script={"analyze": [B("authorize", "")], "authorize": [B("execute", "")], "execute": [("raise", PermissionError, "ticket", True)] * 30}, max_steps=6)),
        ("blocked start that clears", dict(script={**happy, "execute": [("raise", PermissionError, "ticket", True), B("evaluate", "")]})),
        ("final message equals the last assistant entry", dict(script=happy, dup=True)),
        ("completed with an empty message", dict(script={**happy, "evaluate": [B("completed", "")]})),
        ("authorization fails with a reason", dict(script={"analyze": [B("authorize", "")], "authorize": [B("failed", "Policy denies x")]})),
        ("evaluator asks for a new ticket", dict(script={**happy, "evaluate": [B("authorize", ""), B("completed", "done")], "authorize": [B("execute", "")] * 2, "execute": [B("evaluate", "")] * 2})),
        ("clarify", dict(script={"analyze": [B("waiting", "which one?")]})),
    ]
    code = lambda name: C["ST_" + name.upper()]   # noqa: E731
    for label, kw in scenarios:
        events, res, hist, stderr, last_len = _run_turn(C, **kw)
        max_steps = kw.get("max_steps", 20)
        final = st(C, res.status)
        # the iterations are rebuilt from the event log: cancel check, optional revoke, optional handler
        iters, p, state, n_handlers, denied = [], 0, "analyze", 0, False
        while p < len(events) and events[p][0] == "cancel_check":
            rec = {"state": state, "cancel": events[p][1], "revoked": False, "handler": None, "limit": n_handlers >= max_steps, "denied_before": denied}
            p += 1
            if p < len(events) and events[p][0] == "revoke":
                rec["revoked"] = True
                p += 1
            if p < len(events) and events[p][0] == "handler":
                rec["handler"] = events[p]
                p += 1
            iters.append(rec)
            if rec["handler"] is None:
                break
            out = rec["handler"][3]
            n_handlers += 1
            if out[0] == "raise":
                denied = denied or out[3]
            else:
                state = out[1]
                if state in ("completed", "failed", "waiting"):
                    break
        for k, rec in enumerate(iters):
            h = rec["handler"]
            t = blank(spec, "Turn")
            for key in ("r_feedback_error_type_only", "r_stderr_logged"):
                t.pop(key)                      # only observed after a handler exception
            t.update({"_label": f"{label}, iteration {k + 1}", "r_state": code(rec["state"]), "r_turn_start": k == 0, "r_cancel": rec["cancel"],
                      "r_steps_at_limit": rec["limit"], "r_handler_invoked": h is not None, "r_ticket_revoked_before_handler": rec["revoked"],
                      "r_step_counted": res.steps == n_handlers, "r_user_recorded": any(e.kind == "user" and e.turn_id == 1 for e in hist.entries),
                      "r_denial_seen": rec["denied_before"]})
            if h is None:
                t["r_next_state"] = final
            else:
                out = h[3]
                raised = out[0] == "raise"
                t["r_handler_raised"] = raised
                t["r_blocked_start"] = bool(raised and out[3])
                t["r_stage_next"] = 0 if raised else code(out[1])
                t["r_next_state"] = code(rec["state"]) if raised else code(out[1])
                if raised:
                    if out[3]:
                        t["r_denial_seen"] = True
                    t["r_stderr_logged"] = f"[{rec['state']}] {out[1].__name__}: {out[2]}" in stderr
                    nxt = iters[k + 1]["handler"] if k + 1 < len(iters) else None
                    if nxt is not None:
                        fb = json.loads(nxt[2]) if nxt[2] else {}
                        t["r_feedback_error_type_only"] = set(fb) == {"stage", "status", "error_type"} and out[2] not in nxt[2]
            ticks.append(t)
        ex = blank(spec, "Turn")
        ex.update({"_label": f"{label}, exit", "r_exit": True, "r_state": final, "r_next_state": final, "r_denial_seen": denied,
                   "r_message_nonempty_out": bool(res.message), "r_ticket_revoked_at_exit": bool(events) and events[-1][0] == "revoke",
                   "r_last_is_same_assistant": dup_flag(kw, res),
                   "r_message_appended": len(hist.entries) > last_len and hist.entries[-1].kind == "assistant" and hist.entries[-1].content == res.message})
        ticks.append(ex)
    return ticks


def dup_flag(kw, res) -> bool:
    return bool(kw.get("dup")) and bool(res.message)


PROBES = {"Gate": probe_gate, "Ticket": probe_ticket, "Authorizer": probe_authorizer, "Analyzer": probe_analyzer, "Executor": probe_executor,
          "Evaluator": probe_evaluator, "Turn": probe_turn, "History": probe_history, "Instruction": probe_instruction, "Config": probe_config,
          "LlmIO": probe_llmio, "Data": probe_data}


# ---------------------------------------------------------------- evaluation of the requirements on the ticks

def evaluate(spec: dict, comp: dict, cname: str, ticks: list[dict]) -> dict:
    C = spec["constants"]
    out = {}
    for r in spec["components"][cname]["requirements"]:
        tree = ptl.parse(comp[r["expanded"]]["ltl_pt"])
        needed = {v for v in ptl.variables(tree) if v not in C}
        checked, bad = 0, []
        for t in ticks:
            if not needed <= set(t):
                continue
            checked += 1
            full = {**C, **{k: v for k, v in t.items() if not k.startswith("_")}}
            if not ptl.check(tree, [full])["ok"]:
                bad.append(t.get("_label", "?"))
        status = "not_checked" if checked == 0 else ("violated" if bad else "holds")
        expected = r["asis"]
        consistent = (status == "holds" and expected == "ok") or (status == "violated" and expected == "gap")
        out[r["id"]] = {"status": status, "checked": checked, "violations": len(bad), "examples": bad[:3], "asis": expected, "consistent": consistent if status != "not_checked" else None}
    return out


def run(spec: dict, comp: dict, only: list[str] | None = None) -> dict:
    C = spec["constants"]
    res, summary = {}, {"ticks": 0, "holds": 0, "violated": 0, "not_checked": 0, "mismatch": []}
    for cname, fn_ in PROBES.items():
        if only and cname not in only:
            continue
        ticks = fn_(spec, C)
        ev = evaluate(spec, comp, cname, ticks)
        res[cname] = {"ticks": len(ticks), "requirements": ev}
        summary["ticks"] += len(ticks)
        for rid, e in ev.items():
            summary[e["status"]] += 1
            if e["consistent"] is False or e["status"] == "not_checked":
                summary["mismatch"].append({"id": rid, "status": e["status"], "asis": e["asis"], "examples": e["examples"]})
    n_req = sum(len(v["requirements"]) for v in res.values())
    summary["text"] = (f"{summary['ticks']} observations of the real code; of {n_req} requirements {summary['holds']} hold on every observation, {summary['violated']} are violated, "
                       f"{summary['not_checked']} were not observed; {len(summary['mismatch'])} differ from the catalog's asis column")
    return {"components": res, "summary": summary["text"], "mismatch": summary["mismatch"], "counts": {k: summary[k] for k in ("ticks", "holds", "violated", "not_checked")}}


def run_guarded(spec: dict, comp: dict) -> dict:
    """The same probes on the attach layer's guarded stack (GuardedStages and TrustedHistory). The Turn probe is left out: it drives the loop
    with scripted stages, so the guards cannot act in it; their effect on the loop is covered by the end-to-end scenarios of `traces`."""
    from .guard import GuardedStages, TrustedHistory
    from .observe import TraceRecorder
    global STAGES, RESTORE
    STAGES = lambda *a, **kw: GuardedStages(*a, recorder=TraceRecorder(), **kw)   # noqa: E731
    RESTORE = TrustedHistory.from_jsonl
    try:
        res = run(spec, comp, only=[c for c in PROBES if c != "Turn"])
    finally:
        STAGES = RESTORE = None
    closed, violated = [], []
    for cname, v in res["components"].items():
        for rid, e in v["requirements"].items():
            if e["status"] == "violated":
                violated.append(rid)
            elif e["asis"] == "gap" and e["status"] == "holds":
                closed.append(rid)
    res["closed_gaps"], res["still_violated"] = sorted(closed), sorted(violated)
    return res


# ---------------------------------------------------------------- which statements of core.py did the probes execute

def run_traced(spec: dict, comp: dict, only: list[str] | None = None) -> dict:
    """run() with a line tracer on core.py: every statement inside a function body is either executed by some probe or listed."""
    path = core.__file__
    executed: set[int] = set()

    def tracer(frame, event, arg):
        if frame.f_code.co_filename != path:
            return None

        def local(frame, event, arg):
            if event == "line":
                executed.add(frame.f_lineno)
            return local
        return local

    sys.settrace(tracer)
    try:
        out = run(spec, comp, only)
    finally:
        sys.settrace(None)
    src = open(path, encoding="utf-8").read()
    lines = src.splitlines()
    body: set[int] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.stmt) and sub is not node and not isinstance(sub, (ast.Try, ast.FunctionDef)):
                    body.add(sub.lineno)
    missed = sorted(body - executed)
    out["exec_coverage"] = {"statements_in_function_bodies": len(body), "executed": len(body & executed),
                            "not_executed": [{"line": ln, "text": lines[ln - 1].strip()[:100]} for ln in missed]}
    return out


# ---------------------------------------------------------------- code mutants: does spec + probes catch a defect that is put into the code?

CODE_MUTANTS = [
    ("C-01", "게이트가 티켓 만료를 보지 않는다", "        if time.monotonic() >= ticket.expires_at:\n            raise PermissionError", "        if False:\n            raise PermissionError"),
    ("C-02", "게이트가 티켓의 session_id, task_id 묶음을 보지 않는다", "(ticket.session_id, ticket.task_id) != (context.instruction.session_id, context.instruction.task_id)", "False"),
    ("C-03", "게이트가 자원 허가를 보지 않는다", "        if not set(resources) <= set(grants[name]):\n            raise PermissionError", "        if False:\n            raise PermissionError"),
    ("C-04", "게이트가 호출 한도를 보지 않는다", "        if self._ticket_calls[ticket.ticket_id] >= ticket.max_calls:\n            raise PermissionError", "        if False:\n            raise PermissionError"),
    ("C-05", "호출 횟수를 실행 뒤에 센다 (실패한 도구는 세지 않는다)", "        self._ticket_calls[ticket.ticket_id] += 1\n        return tool.execute(checked)", "        _r = tool.execute(checked)\n        self._ticket_calls[ticket.ticket_id] += 1\n        return _r"),
    ("C-06", "validate에 인자 복사본이 아니라 원본을 넘긴다", "tool.validate(deepcopy(arguments))", "tool.validate(arguments)"),
    ("C-07", "턴이 끝날 때 티켓을 지우지 않는다", "    finally:\n        stages.revoke_ticket(context)", "    finally:\n        pass"),
    ("C-08", "인가 단계가 정책(교집합) 검사를 건너뛴다", "            if not resources <= allowed:", "            if False:"),
    ("C-09", "작업 LLM에 모든 등록 도구의 스키마를 보여 준다", "}} for name in dict(ticket.grants)]", "}} for name in self.tools]"),
    ("C-10", "도구 실패의 메시지를 LLM에 기록한다", 'content = json.dumps({"error_type": type(error).__name__}, ensure_ascii=False)', 'content = json.dumps({"error_type": type(error).__name__, "message": str(error)}, ensure_ascii=False)'),
    ("C-11", "평가가 모르는 결정값을 완료로 처리한다", 'return StageResult(states[result["decision"]], message=result["message"])', 'return StageResult(states.get(result["decision"], TurnState.COMPLETED), message=result["message"])'),
    ("C-12", "entries가 복사본이 아니라 살아 있는 항목을 돌려준다", "return tuple(deepcopy(self._entries))", "return tuple(self._entries)"),
    ("C-13", "에이전트 권한표를 복사하지 않는다", "self.agent_permissions = deepcopy(agent_permissions or {})", "self.agent_permissions = agent_permissions if agent_permissions is not None else {}"),
    ("C-14", "단계 한도(max_steps)를 보지 않는다", "            if steps >= max_steps:", "            if False:"),
    ("C-15", "취소가 CANCELLED가 아니라 FAILED로 끝난다", "                state, message = TurnState.CANCELLED, \"\"", "                state, message = TurnState.FAILED, \"\""),
    ("C-16", "managed 항목이 대화 메시지로도 나간다", '            if entry.kind == "managed":\n                continue\n            if entry.kind in {"user", "assistant"}:', '            if entry.kind in {"user", "assistant", "managed"}:'),
    ("C-17", "분석 호출 한도를 보지 않는다", "        if context.analysis_calls >= self.max_analysis_calls:", "        if False:"),
    ("C-18", "분석 호출 횟수를 세지 않는다", "        context.analysis_calls += 1", "        pass"),
    ("C-19", "작업 LLM 호출 한도를 100회 늘린다", "        while context.worker_calls < self.max_worker_calls:", "        while context.worker_calls < self.max_worker_calls + 100:"),
    ("C-20", "도구 호출 묶음의 한도 검사를 하지 않는다", "            if context.tool_attempts + len(calls) > self.max_tool_calls:", "            if False:"),
    ("C-21", "티켓에 만료 시각이 사실상 없다", "expires_at=time.monotonic() + self.ticket_ttl,", "expires_at=time.monotonic() + 10 ** 9,"),
    ("C-22", "티켓의 호출 한도가 사실상 없다", "max_calls=self.max_tool_calls,", "max_calls=10 ** 6,"),
    ("C-23", "티켓이 세션에 묶이지 않는다", "            session_id=context.instruction.session_id,", '            session_id="shared",'),
    ("C-25", "시스템 프롬프트에 managed(운영자 지시)를 넣지 않는다", 'managed = [entry.content for entry in context.history.entries if entry.kind == "managed"]', "managed = []"),
    ("C-24", "인가 전에 AUTHORIZE에서는 이전 티켓을 지우지 않는다", "            if state in {TurnState.ANALYZE, TurnState.AUTHORIZE}:", "            if state in {TurnState.ANALYZE}:"),
]


def mutate(spec: dict, comp: dict) -> dict:
    """Every code mutant is a copy of the original core.py with ONE defect. The probes run on the copy; a mutant is caught when a
    requirement that holds on the original is violated on it. The original file is only read."""
    import importlib.util
    import shutil
    import tempfile
    from pathlib import Path
    global core
    src = (loader.pin.original_root() / "src" / "core.py").read_text(encoding="utf-8")
    real = core
    base = run(spec, comp)
    held = {(c, r) for c, v in base["components"].items() for r, e in v["requirements"].items() if e["status"] == "holds"}
    out, tmp = {}, Path(tempfile.mkdtemp(prefix="sa_mut_"))
    try:
        for mid, ko, old, new in CODE_MUTANTS:
            if src.count(old) != 1:
                out[mid] = {"ko": ko, "error": f"the text to replace occurs {src.count(old)} times"}
                continue
            name = "core_" + mid.replace("-", "_")
            path = tmp / f"{name}.py"
            path.write_text(src.replace(old, new), encoding="utf-8")
            spec_ = importlib.util.spec_from_file_location(name, path)
            mod = importlib.util.module_from_spec(spec_)
            sys.modules[name] = mod
            try:
                spec_.loader.exec_module(mod)
                core = mod
                res = run(spec, comp)
                bad = sorted(f"{c}:{r}" for c, v in res["components"].items() for r, e in v["requirements"].items() if e["status"] == "violated" and (c, r) in held)
                out[mid] = {"ko": ko, "caught": bool(bad), "violated": bad}
            except Exception as e:  # noqa: BLE001
                out[mid] = {"ko": ko, "caught": True, "violated": [], "crash": f"{type(e).__name__}: {e}"[:200]}
            finally:
                core = real
                sys.modules.pop(name, None)
    finally:
        core = real
        shutil.rmtree(tmp, ignore_errors=True)
    return out
