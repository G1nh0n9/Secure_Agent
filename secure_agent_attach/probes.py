"""Probes: the requirements judged on what the REAL original does.

Each probe runs the unmodified original (imported read-only) with
scripted LLMs, fake tools and a fake clock, and builds ticks: the Inputs
of a tick are what the probe fed in, the Outputs are what the code did.
The compiled `ltl_pt` of every requirement of the component is then
evaluated on every tick that carries the signals it mentions.  A
requirement marked `asis: ok` must hold on every tick; one marked `asis:
gap` must be violated by at least one tick (the gap is reproduced).
Anything else is a mismatch between the catalog and the code.

The gate is enumerated exhaustively over the Boolean abstraction of its
inputs (2^12 = 4096 calls). The other components use the cases that
decide each requirement (every action, every decision, every kind of
record, every combination of the authorizer's checks, ...)."""

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
from .oracles import (
    BUDGET,
    BUDGET_ROOMY,
    BUDGET_RUNAWAY,
    MAX_ARG_BYTES,
    MAX_ARG_DEPTH,
    RESULT_CAP,
    SCHEMA,
    SEQ_CAP,
    SEQ_FORBID,
    evil_note_rule,
    oracle_budget_over,
    oracle_content_ok,
    oracle_sequence_ok,
    oracle_shape_ok,
)

core = loader.load_original()
ST_OF = {
    "analyze": "ST_ANALYZE",
    "authorize": "ST_AUTHORIZE",
    "execute": "ST_EXECUTE",
    "evaluate": "ST_EVALUATE",
    "completed": "ST_COMPLETED",
    "waiting_for_user": "ST_WAITING",
    "cancelled": "ST_CANCELLED",
    "failed": "ST_FAILED",
    "limit_reached": "ST_LIMIT",
}


class Clock:
    """A fake clock that stays where the probe put it."""

    def __init__(self, now: float = 100.0):
        self.now = now

    def monotonic(self):
        """Return the fake time."""
        return self.now


@contextlib.contextmanager
def fake_clock(now: float = 100.0):
    """Replace the core's clock by a fake one for the block."""
    clock, real = Clock(now), core.time
    core.time = clock
    try:
        yield clock
    finally:
        core.time = real


STAGES = None  # the guarded run puts a factory for GuardedStages here
RESTORE = None  # ... and TrustedHistory.from_jsonl here


def new_stages(*args, budget=None, **kw):
    """Build the stack a probe runs on: the original or the guarded one.

    ``budget`` (a mapping like ``oracles.BUDGET``) tightens the budget
    of a guarded stack; the original has no budget and ignores it.
    """
    if STAGES is None:
        return core.TurnStages(*args, **kw)
    return STAGES(*args, budget=budget, **kw)


def st(C: dict, state) -> int:
    """Return the catalog's integer code of a turn state."""
    return C[ST_OF[state.value]]


def blank(spec: dict, cname: str) -> dict:
    """Return every signal of a component with a neutral value.

    A probe overwrites what it observed or fed in.
    """
    return {
        n: (0 if s[1] == "integer" else False)
        for n, s in spec["components"][cname]["signals"].items()
    }


def mk_tool(
    name="t", calls=None, valid=True, res=("r1",), fails=False, result="ok"
):
    """Return a fake tool that logs which of its functions ran."""
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

    return core.ToolDefinition(
        description=f"{name} tool",
        parameters={"type": "object", "properties": {}},
        resource_hint="target",
        validate=validate,
        resources=resources,
        execute=execute,
    )


def new_ctx(text="x", session="sess", turn=1):
    """Return an instruction and a fresh turn context."""
    instr = core.UserInstruction(session, turn, text)
    return instr, core.TurnContext(instr, core.ConversationHistory(session))


def put_ticket(
    stages,
    ctx,
    instr,
    tid="T1",
    grants=(("t", ("r1",)),),
    expires=500.0,
    calls_used=0,
    max_calls=12,
    session=None,
    task=None,
):
    """Store a ticket in the stack and attach it to a context."""
    t = core.CapabilityTicket(
        task_id=task or instr.task_id,
        ticket_id=tid,
        session_id=session or instr.session_id,
        grants=grants,
        expires_at=expires,
        max_calls=max_calls,
    )
    stages._tickets[tid] = t
    stages._ticket_calls[tid] = calls_used
    ctx.ticket = tid
    return t


# --------------------------------------------------- shared helpers


def probe_policy(budget=None):
    """Return the guard policy that matches the oracles of the probes.

    Args:
        budget: A mapping like ``oracles.BUDGET``, or None for the
            default budget of the guards.
    """
    from .policy import ArgumentLimits, Budget, GuardPolicy, SequenceRules

    limits = (
        Budget()
        if budget is None
        else Budget(
            max_calls=budget["calls"],
            max_chars=budget["chars"],
            max_seconds=budget["seconds"],
        )
    )
    return GuardPolicy(
        arguments=ArgumentLimits(MAX_ARG_BYTES, MAX_ARG_DEPTH),
        result_max_chars=RESULT_CAP,
        sequence=SequenceRules(
            forbidden_after=SEQ_FORBID, max_calls_per_turn=SEQ_CAP
        ),
        content_rules=(evil_note_rule,),
        budget=limits,
    )


def _gate(stages, ctx, name, args):
    """Make one call of the gate and return the exception, if any.

    The observer of a guarded stack expects a stage to be open.
    """
    if hasattr(stages, "recorder"):
        stages.recorder.begin("execute")
    try:
        stages._execute_tool(ctx, name, args)
    except Exception as error:  # noqa: BLE001
        return error
    return None


def _usage(stages):
    """Return the usage totals of a stack that keeps any, else None.

    A guard that implements LLM-11 exposes ``usage`` with the keys
    ``calls`` and ``chars``.
    """
    usage = getattr(stages, "usage", None)
    return None if usage is None else (usage["calls"], usage["chars"])


# ---------------------------------------------------- Gate (exhaustive)


def _gate_case(
    label,
    *,
    found=True,
    bound=True,
    expired=False,
    granted=True,
    registered=True,
    valid=True,
    res_in=True,
    budget=True,
    fails=False,
    args=None,
    prior=(),
    tool="t",
    turn=1,
):
    """Make one call of the gate on a fresh stack and describe it.

    Args:
        label: Name of the case, for reports.
        found, bound, expired, granted, registered, valid, res_in,
        budget, fails: The Boolean inputs of GATE-01 to GATE-16.
        args: Arguments of the call; the shape and content inputs
            are derived from them by the oracles.
        prior: Pairs ``(tool, turn)`` of calls that ran earlier in the
            same session, each on its own permissive ticket.
        tool: Name of the tool called.
        turn: Turn of the call.

    Returns:
        A tick: the 12 inputs as they were fed in, the 11 outputs as
        they were observed.
    """
    args = {"target": "r1"} if args is None else args
    with fake_clock(100.0):
        calls, seen, ran = [], {}, []

        def validate(arguments):
            calls.append("validate")
            seen["validate_arg"] = arguments
            if isinstance(arguments, dict):
                arguments["mutated"] = True  # a copy must absorb this
            if not valid:
                raise ValueError("bad arguments")
            if isinstance(arguments, dict):
                checked = {
                    k: v for k, v in arguments.items() if k != "mutated"
                }
            else:
                checked = (
                    list(arguments)
                    if isinstance(arguments, list)
                    else arguments
                )
            seen["checked"] = checked
            return checked

        def resources(checked):
            calls.append("resources")
            seen["resources_arg"] = checked
            return ("r1",) if res_in else ("zzz",)

        def execute(checked):
            calls.append("execute")
            seen["execute_arg"] = checked
            if fails:
                raise RuntimeError("tool failed")
            return "ok"

        tested = core.ToolDefinition(
            description=tool,
            parameters=SCHEMA,
            resource_hint="x",
            validate=validate,
            resources=resources,
            execute=execute,
        )
        tools = {n: mk_tool(n) for n in ("a", "c", "t") if n != tool}
        if registered:
            tools[tool] = tested
        stages = new_stages(tools=tools, max_tool_calls=2)
        everything = tuple((n, ("r1",)) for n in sorted(tools))
        for k, (earlier, earlier_turn) in enumerate(prior):
            instr_p, ctx_p = new_ctx(turn=earlier_turn)
            put_ticket(
                stages,
                ctx_p,
                instr_p,
                tid=f"P{k}",
                grants=everything,
                max_calls=50,
            )
            if _gate(stages, ctx_p, earlier, {"target": "r1"}) is None:
                ran.append(("sess", earlier_turn, earlier))  # it ran
        seq = oracle_sequence_ok(ran, "sess", turn, tool)
        instr, ctx = new_ctx(turn=turn)
        ticket = before = None
        if found:
            ticket = put_ticket(
                stages,
                ctx,
                instr,
                grants=((tool if granted else "other", ("r1",)),),
                expires=50.0 if expired else 500.0,
                calls_used=0 if budget else 2,
                max_calls=2,
                session="sess" if bound else "other",
                task=instr.task_id if bound else "sess:99",
            )
            before = (dataclasses.astuple(ticket), stages._ticket_calls["T1"])
        else:
            ctx.ticket = "missing"
        calls.clear()
        seen.clear()
        record = getattr(stages, "call_record", None)
        n_before = len(record) if record is not None else 0
        # As fed in: a defective stack may let validate change the
        # caller's object, so the oracles read the arguments first.
        shape_in = oracle_shape_ok(args)
        content_in = oracle_content_ok(args)
        error = _gate(stages, ctx, tool, args)
        tick = {
            "_label": label,
            "g_ticket_found": found,
            "g_ticket_bound": bound,
            "g_ticket_expired": expired,
            "g_tool_granted": granted,
            "g_tool_registered": registered,
            "g_args_valid": valid,
            "g_resources_in_grants": res_in,
            "g_budget_left": budget,
            "g_execute_fails": fails,
            "g_args_shape_ok": shape_in,
            "g_content_ok": content_in,
            "g_sequence_ok": seq,
            "g_validate_called": "validate" in calls,
            "g_resources_called": "resources" in calls,
            "g_execute_called": "execute" in calls,
            "g_counter_incremented": bool(
                found and stages._ticket_calls.get("T1") == before[1] + 1
            ),
            "g_permission_denied": isinstance(error, PermissionError),
            "g_tool_error": (
                error is not None and not isinstance(error, PermissionError)
            ),
            "g_result_returned": error is None,
            "g_ticket_changed": bool(
                found
                and (
                    stages._tickets.get("T1") is not ticket
                    or dataclasses.astuple(stages._tickets["T1"]) != before[0]
                )
            ),
            "g_call_recorded": (record is not None and len(record) > n_before),
        }
        if "validate" in calls:
            # A copy matters only for a mutable argument: deepcopy of a
            # string or a number is the same object, and nothing can be
            # mutated through it.
            mutable = isinstance(args, (dict, list))
            tick["g_args_copied"] = not mutable or (
                seen["validate_arg"] is not args
                and not (isinstance(args, dict) and "mutated" in args)
            )
        if "execute" in calls:
            checked = seen.get("checked")
            tick["g_same_checked_args"] = (
                checked is not None
                and checked is seen.get("resources_arg")
                and checked is seen.get("execute_arg")
            )
        return tick


def probe_gate(spec, C):
    """Probe the gate with every input combination and malformed input.

    The cases are: all 2^12 = 4096 combinations of the 12 Boolean
    inputs, every kind of malformed argument, and every call sequence
    of up to three calls over the tools a, t and c (the order rules:
    t may not run once a has run, c runs at most twice per turn).
    """
    ticks = []
    combos = itertools.product([False, True], repeat=12)
    for (
        found,
        bound,
        expired,
        granted,
        registered,
        valid,
        res_in,
        budget,
        fails,
        shape,
        content,
        seq,
    ) in combos:
        args = {"target": "r1"}
        if not shape:
            args["extra"] = "x"  # outside the declared schema
        if not content:
            args["note"] = "EVIL"  # what the content oracle refuses
        label = (
            f"found={found} bound={bound} expired={expired} "
            f"granted={granted} registered={registered} "
            f"valid={valid} res_in={res_in} budget={budget} "
            f"fails={fails} shape={shape} content={content} seq={seq}"
        )
        tick = _gate_case(
            label,
            found=found,
            bound=bound,
            expired=expired,
            granted=granted,
            registered=registered,
            valid=valid,
            res_in=res_in,
            budget=budget,
            fails=fails,
            args=args,
            prior=() if seq else (("a", 0),),
        )
        named = (shape, content, seq)
        built = (
            tick["g_args_shape_ok"],
            tick["g_content_ok"],
            tick["g_sequence_ok"],
        )
        if built != named:
            tick["_label"] += (
                " (an earlier call was refused, so the "
                "order input differs from the name)"
            )
        ticks.append(tick)
    malformed = (
        ("a list", ["r1"]),
        ("a string", "r1"),
        ("required field missing", {"note": "x"}),
        ("wrong type", {"target": 5}),
        ("wrong type of an object field", {"target": "r1", "meta": "x"}),
        ("additional property", {"target": "r1", "extra": "x"}),
        ("oversize", {"target": "x" * (MAX_ARG_BYTES + 1)}),
        (
            "too deep",
            {"target": "r1", "meta": {"a": {"b": {"c": {"d": "e"}}}}},
        ),
    )
    for kind, args in malformed:
        ticks.append(_gate_case(f"malformed arguments: {kind}", args=args))
    for length in (1, 2, 3):
        for names in itertools.product(("a", "t", "c"), repeat=length):
            *earlier, last = names
            ticks.append(
                _gate_case(
                    f"call sequence {' '.join(names)}",
                    tool=last,
                    prior=tuple((name, 1) for name in earlier),
                )
            )
    return ticks


# ---------------------------------------------------- Ticket


def probe_ticket(spec, C):
    """Observe the ticket store and the ticket data structure."""
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
        ticks.append(
            {
                "_label": f"revoke, ticket present={present}",
                "t_revoke_requested": True,
                "t_ticket_present": present,
                "t_ticket_removed": "T1" not in stages._tickets,
                "t_counter_removed": "T1" not in stages._ticket_calls,
                "t_context_cleared": ctx.ticket is None,
                "t_error": err is not None,
            }
        )
    stages = new_stages()
    instr, ctx = new_ctx()
    t = put_ticket(stages, ctx, instr)
    try:
        t.grants = ()
        mutated = True
    except dataclasses.FrozenInstanceError:
        mutated = False
    fields = {f.name for f in dataclasses.fields(core.CapabilityTicket)}
    ticks.append(
        {
            "_label": "ticket data model",
            "t_ticket_mutated_in_place": mutated,
            "t_binding_fields_present": {"task_id", "session_id"} <= fields,
            "t_has_expiry": "expires_at" in fields,
            "t_has_call_budget": "max_calls" in fields,
        }
    )
    return ticks


# ---------------------------------------------------- Authorizer

POLICY = {"read_file": ("reports/a.txt",), "send_email": ("team@corp",)}
GADGETS = [
    ("in_plan", {"tool": "read_file", "resources": ["reports/a.txt"]}),
    ("outside_plan", {"tool": "send_email", "resources": ["team@corp"]}),
    ("exceeds", {"tool": "read_file", "resources": ["secrets/x"]}),
    ("unknown", {"tool": "ghost", "resources": ["x"]}),
    ("no_scope", {"tool": "ping", "resources": ["x"]}),
]


def probe_authorizer(spec, C):
    """Observe the authorization stage over every check."""
    ticks, seen_ids = [], set()
    plan_steps = {
        "none": None,
        "notool": (core.PlannedStep("0", "think", None, ()),),
        "read": (
            core.PlannedStep("0", "read", "read_file", ("reports/a.txt",)),
        ),
    }
    for plan_kind, err, subset in itertools.product(
        plan_steps,
        (False, True),
        itertools.product([False, True], repeat=len(GADGETS)),
    ):
        chosen = {name for (name, _), on in zip(GADGETS, subset) if on}
        grants = [g for name, g in GADGETS if name in chosen]
        llm_calls, payloads = [], []

        def call_llm(
            messages,
            tools,
            json_output,
            grants=grants,
            err=err,
            llm_calls=llm_calls,
            payloads=payloads,
        ):
            llm_calls.append(1)
            payloads.append(json.loads(messages[1]["content"]))
            return (
                {"content": "not json"}
                if err
                else {
                    "content": json.dumps({"grants": grants, "declines": []})
                }
            )

        with fake_clock(1000.0) as clock:
            tools = {
                n: mk_tool(n) for n in ("read_file", "send_email", "ping")
            }
            stages = new_stages(
                call_llm,
                tools=tools,
                agent_permissions=POLICY,
                user_permissions=POLICY,
                ticket_ttl=300,
                max_tool_calls=12,
            )
            instr, ctx = new_ctx()
            ctx.plan = (
                None
                if plan_steps[plan_kind] is None
                else core.TaskPlan(instr.task_id, "obj", plan_steps[plan_kind])
            )
            res, exc = None, None
            try:
                res = stages.authorize_task(ctx)
            except Exception as e:  # noqa: BLE001
                exc = e
            plan_pairs = (
                {("read_file", "reports/a.txt")}
                if plan_kind == "read"
                else set()
            )
            conf_pairs = {
                (g["tool"], r) for g in grants for r in g["resources"]
            }
            in_policy = (
                lambda p: p[0] in POLICY and p[1] in POLICY[p[0]]
            )  # noqa: E731
            issued = ctx.ticket in stages._tickets
            t = {
                "_label": f"plan={plan_kind} verifier_error={err} "
                f"grants={sorted(chosen)}",
                "a_plan_present": plan_kind != "none",
                "a_plan_has_tool_steps": plan_kind == "read",
                "a_verifier_error": err,
                "a_any_unknown_tool": "unknown" in chosen,
                "a_any_scope_missing": "no_scope" in chosen,
                "a_any_exceeds_policy": "exceeds" in chosen,
                "a_any_outside_plan": bool(conf_pairs - plan_pairs),
                "a_usable_empty": not (
                    "in_plan" in chosen and plan_kind == "read"
                ),
                "a_verifier_called": bool(llm_calls),
                "a_llm_calls": len(llm_calls),
                "a_result_failed": res is not None
                and res.next_state == core.TurnState.FAILED,
                "a_result_execute": res is not None
                and res.next_state == core.TurnState.EXECUTE,
                "a_ticket_issued": issued,
                "a_message_nonempty": bool(res and res.message),
                "a_error_propagated": exc is not None,
            }
            if payloads:
                expected = (
                    []
                    if plan_kind != "read"
                    else [
                        {
                            "tool": "read_file",
                            "resources": ["reports/a.txt"],
                            "description": "read",
                        }
                    ]
                )
                t["a_request_from_plan_only"] = payloads[0] == {
                    "objective": "obj",
                    "requested_grants": expected,
                }
            if issued:
                tk = stages._tickets[ctx.ticket]
                pairs = {(n, r) for n, rs in tk.grants for r in rs}
                t.update(
                    {
                        "a_issued_outside_plan": bool(pairs - plan_pairs),
                        "a_issued_beyond_policy": not all(
                            in_policy(p) for p in pairs
                        ),
                        "a_issued_beyond_verifier": bool(pairs - conf_pairs),
                        "a_grants_trimmed": bool(
                            {p for p in conf_pairs if in_policy(p)} - pairs
                        ),
                        "a_ticket_bound_to_task": (tk.session_id, tk.task_id)
                        == (instr.session_id, instr.task_id),
                        "a_ticket_has_expiry": tk.expires_at
                        == clock.now + 300,
                        "a_ticket_has_call_budget": tk.max_calls == 12,
                        "a_ticket_id_fresh": tk.ticket_id not in seen_ids
                        and bool(uuid.UUID(tk.ticket_id)),
                        "a_ticket_stored": ctx.ticket == tk.ticket_id,
                        "a_counter_zero": stages._ticket_calls.get(
                            tk.ticket_id
                        )
                        == 0,
                    }
                )
                seen_ids.add(tk.ticket_id)
            else:
                t.update(
                    {
                        "a_issued_outside_plan": False,
                        "a_issued_beyond_policy": False,
                        "a_issued_beyond_verifier": False,
                        "a_grants_trimmed": False,
                    }
                )
            ticks.append(t)
    return ticks


# ---------------------------------------------------- Analyzer

PLAN_JSON = {
    "action": "analyze",
    "objective": "o",
    "steps": [
        {
            "description": "d",
            "tool": "read_file",
            "resources": ["reports/a.txt"],
        }
    ],
}


def probe_analyzer(spec, C):
    """Observe the analysis stage over every action."""
    ticks = []
    ACT = {
        "respond": C["ACT_RESPOND"],
        "clarify": C["ACT_CLARIFY"],
        "history": C["ACT_HISTORY"],
        "plan": C["ACT_PLAN"],
    }
    R, Q = {"action": "respond", "message": "R-text"}, {
        "action": "clarify",
        "message": "Q-text",
    }
    H = {"action": "history", "reason": "r", "turn_ids": [1]}
    cases = [("budget exhausted", False, False, "plan", "plan", [])]
    for label, resp in (
        ("invalid JSON", ["not json"]),
        ("JSON list", ["[1]"]),
        ("malformed step", [json.dumps({"action": "analyze", "steps": [1]})]),
        ("llm raises", [RuntimeError]),
    ):
        cases.append((label, True, True, "plan", "plan", resp))
    cases += [
        ("respond", True, False, "respond", "plan", [R]),
        ("clarify", True, False, "clarify", "plan", [Q]),
        ("plan", True, False, "plan", "plan", [PLAN_JSON]),
        (
            "other action",
            True,
            False,
            "plan",
            "plan",
            [{"action": "zzz", "objective": "o", "steps": []}],
        ),
        (
            "no action key",
            True,
            False,
            "plan",
            "plan",
            [{"objective": "o", "steps": []}],
        ),
    ]
    for second_name, second in (
        ("respond", R),
        ("clarify", Q),
        ("history", H),
        ("plan", PLAN_JSON),
    ):
        cases.append(
            (
                f"history then {second_name}",
                True,
                False,
                "history",
                second_name,
                [H, second],
            )
        )
    for label, budget, err, first, second, script in cases:
        script = list(script)
        calls = []

        def call_llm(messages, tools, json_output, script=script, calls=calls):
            calls.append({"messages": messages, "tools": tools})
            item = (
                script[len(calls) - 1]
                if len(calls) <= len(script)
                else script[-1]
            )
            if item is RuntimeError:
                raise RuntimeError("llm down")
            return {
                "content": item if isinstance(item, str) else json.dumps(item)
            }

        stages = new_stages(
            call_llm,
            tools={"read_file": mk_tool("read_file")},
            agent_permissions=POLICY,
            user_permissions=POLICY,
        )
        instr, ctx = new_ctx(text="please read")
        ctx.history.add_user(
            instr
        )  # process_turn does this before the first stage
        ctx.analysis_calls = 0 if budget else stages.max_analysis_calls
        before = ctx.analysis_calls
        res, exc = None, None
        try:
            res = stages.analyze_instruction(ctx)
        except Exception as e:  # noqa: BLE001
            exc = e
        t = {
            "_label": label,
            "n_budget_left": budget,
            "n_error": err,
            "n_action": ACT[first],
            "n_action2": ACT[second],
            "n_next": st(C, res.next_state) if res else 0,
            "n_llm_calls": len(calls),
            "n_counter_incremented": ctx.analysis_calls == before + 1,
            "n_plan_created": ctx.plan is not None,
            "n_context_updated": ctx.plan is not None
            and ctx.analysis is not None,
            "n_error_propagated": exc is not None,
            "n_ticket_touched": bool(stages._tickets)
            or ctx.ticket is not None,
            "n_tool_executed": False,
            "n_message_from_llm": bool(
                res and res.message in ("R-text", "Q-text")
            ),
            "n_recall_recorded": bool(ctx.recalled_turns),
            "n_input_from_history_and_registry": False,
        }
        if calls:
            m = calls[0]["messages"]
            payload = json.loads(m[1]["content"])
            t["n_input_from_history_and_registry"] = (
                set(payload) == {"instruction"}
                and payload["instruction"].get("kind") == "user"
                and payload["instruction"].get("content") == "please read"
                and "read_file" in m[0]["content"]
            )
        ticks.append(t)
    return ticks


# ---------------------------------------------------- Executor


def probe_executor(spec, C):
    """Observe the execution stage over its input combinations."""
    ticks = []
    GO = {
        "ok": C["GO_OK"],
        "denied": C["GO_DENIED"],
        "error": C["GO_TOOL_ERROR"],
    }
    flags = itertools.product(
        (False, True),
        (False, True),
        (False, True),
        (False, True),
        (False, True),
        (False, True),
        ("ok", "denied", "error"),
        (False, True),
        (False, True),
        (False, True),
    )
    for (
        valid,
        budget,
        llm_err,
        calls_tools,
        exceeds,
        parse_ok,
        outcome,
        serial,
        text,
        oversize,
    ) in flags:
        with fake_clock(100.0):
            tool_calls_log, llm_log, gate_log = [], [], []
            big = "x" * (RESULT_CAP + 1000) if oversize else "ok"
            tool = mk_tool(
                "t",
                tool_calls_log,
                res=("r1",) if outcome != "denied" else ("zzz",),
                fails=(outcome == "error"),
                result=big if serial else object(),
            )
            good = {
                "function": {
                    "name": "t",
                    "arguments": json.dumps({"target": "r1"}),
                }
            }
            first = {
                "function": {
                    "name": "t",
                    "arguments": (
                        json.dumps({"target": "r1"})
                        if parse_ok
                        else "{not json"
                    ),
                }
            }

            def call_llm(
                messages,
                tools,
                json_output,
                llm_log=llm_log,
                llm_err=llm_err,
                calls_tools=calls_tools,
                text=text,
                first=first,
                good=good,
            ):
                llm_log.append(tools)
                if llm_err:
                    raise RuntimeError("llm down")
                if calls_tools:
                    return {
                        "content": "interim" if text else None,
                        "tool_calls": [first, good],
                    }
                return {"content": "final text", "tool_calls": None}

            stages = new_stages(
                call_llm,
                tools={"t": tool, "u": mk_tool("u")},
                max_worker_calls=8,
                max_tool_calls=12,
            )  # "u" is registered but never granted
            orig_gate = stages._execute_tool

            def gate(
                context, name, arguments, orig=orig_gate, gate_log=gate_log
            ):
                last = context.history.entries[-1]
                gate_log.append(
                    {
                        "recorded": last.kind == "tool_call"
                        and last.tool_name == name,
                        "attempts": context.tool_attempts,
                    }
                )
                return orig(context, name, arguments)

            stages._execute_tool = gate
            instr, ctx = new_ctx()
            if valid:
                put_ticket(stages, ctx, instr)
            ctx.worker_calls = 0 if budget else 8
            ctx.tool_attempts = 11 if exceeds else 0
            attempts_before = ctx.tool_attempts
            err, res = None, None
            with contextlib.redirect_stderr(io.StringIO()):
                try:
                    res = stages.execute_task(ctx)
                except Exception as e:  # noqa: BLE001
                    err = e
            ents = ctx.history.entries
            results = [e for e in ents if e.kind == "tool_result"]
            failed_call = bool(gate_log) and (outcome != "ok" or not serial)
            label = (
                f"valid={valid} budget={budget} llm_err={llm_err} "
                f"calls={calls_tools} exceeds={exceeds} "
                f"parse={parse_ok} outcome={outcome} serial={serial} "
                f"text={text} oversize={oversize}"
            )
            t = {
                "_label": label,
                "x_result_oversize": oversize,
                "x_malformed_recorded": any(
                    e.kind in ("tool_call", "tool_result") for e in ents
                ),
                "x_result_truncated": (
                    bool(results)
                    and not results[0].is_error
                    and len(results[0].content) <= RESULT_CAP
                ),
                "x_ticket_valid": valid,
                "x_worker_budget_left": budget,
                "x_llm_error": llm_err,
                "x_worker_calls_tools": calls_tools,
                "x_batch_exceeds_budget": exceeds,
                "x_args_parse_ok": parse_ok,
                "x_gate_outcome": GO[outcome],
                "x_result_serializable": serial,
                "x_worker_text_present": text,
                "x_llm_called": bool(llm_log),
                "x_schemas_only_granted": all(
                    {f["function"]["name"] for f in tools} <= {"t"}
                    for tools in llm_log
                ),
                "x_next": st(C, res.next_state) if res else 0,
                "x_error_propagated": err is not None,
                "x_work_result_recorded": ctx.work_result == "final text"
                and bool(ents)
                and ents[-1].kind == "assistant"
                and ents[-1].content == "final text",
                "x_gate_invoked": bool(gate_log),
                "x_call_recorded_before_gate": bool(gate_log)
                and all(g["recorded"] for g in gate_log),
                "x_attempt_counted": ctx.tool_attempts > attempts_before,
                "x_error_type_only": bool(results)
                and results[0].is_error
                and set(json.loads(results[0].content)) == {"error_type"},
                "x_later_calls_skipped": (
                    len(gate_log) == 1 if gate_log else True
                ),
                "x_result_recorded": bool(results)
                and not results[0].is_error
                and set(json.loads(results[0].content)) == {"result"},
                "x_interim_text_recorded": any(
                    e.kind == "assistant" and e.content == "interim"
                    for e in ents
                ),
                "x_tool_run_outside_gate": tool_calls_log.count("execute")
                > len(gate_log),
            }
            if failed_call:
                t["x_later_calls_skipped"] = len(gate_log) == 1
            ticks.append(t)
    return ticks


# ---------------------------------------------------- Evaluator


def probe_evaluator(spec, C):
    """Observe the evaluation stage over every decision."""
    ticks = []
    DEC = {
        "completed": C["DEC_COMPLETED"],
        "execute": C["DEC_EXECUTE"],
        "authorize": C["DEC_AUTHORIZE"],
        "analyze": C["DEC_ANALYZE"],
        "ask": C["DEC_ASK"],
        "failed": C["DEC_FAILED"],
    }
    cases = [
        (
            f"decision {n}",
            code,
            False,
            True,
            {"decision": n, "message": "M-text"},
        )
        for n, code in DEC.items()
    ]
    cases += [
        (f"decision {n}, no message", code, False, False, {"decision": n})
        for n, code in DEC.items()
    ]
    cases += [
        (
            "unknown decision",
            0,
            False,
            True,
            {"decision": "bogus", "message": "M-text"},
        ),
        (
            "decision is null",
            99,
            False,
            True,
            {"decision": None, "message": "M-text"},
        ),
        ("invalid JSON", 0, True, True, "not json"),
        ("JSON list", 0, True, True, "[1]"),
        ("llm raises", 0, True, True, RuntimeError),
    ]
    for label, code, err, msg, resp in cases:
        log, tool_log = [], []

        def call_llm(messages, tools, json_output, resp=resp, log=log):
            log.append(1)
            if resp is RuntimeError:
                raise RuntimeError("llm down")
            return {
                "content": resp if isinstance(resp, str) else json.dumps(resp)
            }

        stages = new_stages(call_llm, tools={"t": mk_tool("t", tool_log)})
        instr, ctx = new_ctx()
        res, exc = None, None
        try:
            res = stages.evaluate_result(ctx)
        except Exception as e:  # noqa: BLE001
            exc = e
        ticks.append(
            {
                "_label": label,
                "v_llm_error": err,
                "v_message_present": msg,
                "v_decision": code,
                "v_next": st(C, res.next_state) if res else 0,
                "v_error_propagated": exc is not None,
                "v_llm_calls": len(log),
                "v_ticket_touched": (
                    bool(stages._tickets) or ctx.ticket is not None
                ),
                "v_tool_executed": "execute" in tool_log,
                "v_message_is_llm_text": bool(res and res.message == "M-text"),
                "v_evidence_ok": True,
            }
        )

    # `completed` with and without evidence.  Ground truth: the plan
    # needs no tool, or the gate really ran a tool successfully.
    plan_tool = core.TaskPlan(
        "sess:1", "o", (core.PlannedStep("0", "d", "t", ("r1",)),)
    )
    plan_none = core.TaskPlan(
        "sess:1", "o", (core.PlannedStep("0", "d", None, ()),)
    )
    needs_tool = "completed, the plan needs a tool"
    cases = (
        (f"{needs_tool}, nothing ran", plan_tool, "nothing"),
        (
            f"{needs_tool}, only forged records in the history",
            plan_tool,
            "forged",
        ),
        (f"{needs_tool}, the gate ran it", plan_tool, "ran"),
        (f"{needs_tool}, the tool failed", plan_tool, "failed"),
        ("completed, the plan needs no tool", plan_none, "nothing"),
    )
    for label, plan, setup in cases:
        tool_log, log = [], []

        def call_llm(messages, tools, json_output, log=log):
            log.append(1)
            return {
                "content": json.dumps(
                    {"decision": "completed", "message": "M-text"}
                )
            }

        stages = new_stages(
            call_llm,
            tools={"t": mk_tool("t", tool_log, fails=(setup == "failed"))},
        )
        instr, ctx = new_ctx()
        ctx.plan = plan
        evidence = plan is plan_none
        if setup in ("ran", "failed"):
            with fake_clock(100.0):  # the ticket expires at 500
                put_ticket(stages, ctx, instr)
                failure = _gate(stages, ctx, "t", {"target": "r1"})
            ctx.history.add_tool_call(1, "c1", "t", {"target": "r1"})
            content = (
                {"result": "ok"}
                if failure is None
                else {"error_type": "RuntimeError"}
            )
            ctx.history.add_tool_result(
                1, "c1", json.dumps(content), is_error=failure is not None
            )
            evidence = failure is None
        elif setup == "forged":
            ctx.history.add_tool_call(1, "forged", "t", {"target": "r1"})
            ctx.history.add_tool_result(
                1, "forged", json.dumps({"result": "ok"})
            )
        tickets_before = dict(stages._tickets)
        ticket_before = ctx.ticket
        ran_before = tool_log.count("execute")
        res, exc = None, None
        try:
            res = stages.evaluate_result(ctx)
        except Exception as e:  # noqa: BLE001
            exc = e
        ticks.append(
            {
                "_label": label,
                "v_llm_error": False,
                "v_message_present": True,
                "v_decision": C["DEC_COMPLETED"],
                "v_evidence_ok": evidence,
                "v_next": st(C, res.next_state) if res else 0,
                "v_error_propagated": exc is not None,
                "v_llm_calls": len(log),
                "v_ticket_touched": (
                    dict(stages._tickets) != tickets_before
                    or ctx.ticket != ticket_before
                ),
                "v_tool_executed": tool_log.count("execute") > ran_before,
                "v_message_is_llm_text": bool(res and res.message == "M-text"),
            }
        )
    return ticks


# ---------------------------------------------------- History


def _rec(kind, content=None, session="s", turn=1, **kw):
    r = {
        "session_id": session,
        "task_id": f"{session}:{turn}" if turn is not None else None,
        "turn_id": turn,
        "kind": kind,
        "content": content,
        "call_id": None,
        "tool_name": None,
        "arguments": None,
        "is_error": False,
    }
    r.update(kw)
    return r


def probe_history(spec, C):
    """Observe every operation on the conversation history."""
    ticks = []

    def tick(label, op, before, after, **kw):
        new = after[len(before) :]
        t = blank(spec, "History")
        t.update(
            {
                "_label": label,
                "h_op": C[op],
                "h_entry_appended": len(after) > len(before),
                "h_managed_entry_added": any(e.kind == "managed" for e in new),
                "h_tool_entry_added": any(
                    e.kind in ("tool_call", "tool_result") for e in new
                ),
            }
        )
        t.update(kw)
        ticks.append(t)

    h = core.ConversationHistory("s")
    try:
        h.session_id = "other"
        fixed = False
    except AttributeError:
        fixed = True
    ticks.append(
        {
            **blank(spec, "History"),
            "_label": "create",
            "h_op": C["OP_CREATE"],
            "h_history_empty": len(h.entries) == 0,
            "h_session_fixed": fixed and h.session_id == "s",
        }
    )
    h = core.ConversationHistory("s")
    b = h.entries
    h.add_managed_prompt("op")
    tick("add_managed_prompt", "OP_ADD_MANAGED", b, h.entries)
    b = h.entries
    h.add_user(core.UserInstruction("s", 1, "hi"))
    tick(
        "add_user",
        "OP_ADD_USER",
        b,
        h.entries,
        h_turn_registered=h.next_turn_id == 2,
    )
    b = h.entries
    h.add_assistant(1, "yo")
    tick("add_assistant", "OP_ADD_ASSISTANT", b, h.entries)
    args = {"a": [1]}
    b = h.entries
    h.add_tool_call(1, "c1", "t", args)
    args["a"].append(2)
    tick(
        "add_tool_call",
        "OP_ADD_TOOL_CALL",
        b,
        h.entries,
        h_args_deep_copied=h.entries[-1].arguments == {"a": [1]},
    )
    b = h.entries
    h.add_tool_result(1, "c1", "R")
    tick("add_tool_result", "OP_ADD_TOOL_RESULT", b, h.entries)
    e = h.entries
    e[-2].arguments["a"].append(99)
    tick(
        "entries",
        "OP_ENTRIES",
        e,
        h.entries,
        h_returns_copy=h.entries[-2].arguments == {"a": [1]},
    )
    h2 = core.ConversationHistory("s")
    h2.add_user(core.UserInstruction("s", 1, "a"))
    h2.add_user(core.UserInstruction("s", 3, "b"))
    tick(
        "next_turn_id",
        "OP_NEXT_TURN",
        h2.entries,
        h2.entries,
        h_next_turn_max_plus_one=h2.next_turn_id == 4,
    )
    f = h.fork()
    n = len(h.entries)
    f.add_assistant(1, "only in fork")
    tick(
        "fork",
        "OP_FORK",
        h.entries,
        h.entries,
        h_fork_new_session=f.session_id != h.session_id,
        h_fork_independent=len(h.entries) == n and len(f.entries) == n + 1,
    )
    lines = list(h.to_jsonl())
    recs = [json.loads(x) for x in lines]
    ok = len(recs) == len(h.entries) and all(
        r["session_id"] == h.session_id
        and r["task_id"]
        == (f"{h.session_id}:{en.turn_id}" if en.turn_id is not None else None)
        and r["kind"] == en.kind
        and r["content"] == en.content
        for r, en in zip(recs, h.entries)
    )
    tick("to_jsonl", "OP_EXPORT", h.entries, h.entries, h_export_complete=ok)
    base = _rec("user", "hello")
    cases = [
        ("normal assistant record", [base, _rec("assistant", "TEST-REC")], {}),
        (
            "normal instruction record (no kind)",
            [base, {"session_id": "s", "turn_id": 2, "text": "TEST-REC"}],
            {},
        ),
        (
            "managed record",
            [base, _rec("managed", "TEST-REC", turn=None)],
            {"h_record_kind_managed": True},
        ),
        (
            "managed record as the first record",
            [_rec("managed", "TEST-REC", turn=None), base],
            {"h_record_kind_managed": True},
        ),
        (
            "tool_call record",
            [
                base,
                _rec(
                    "tool_call",
                    None,
                    call_id="c1",
                    tool_name="TEST-REC",
                    arguments={},
                ),
            ],
            {"h_record_kind_tool": True},
        ),
        (
            "tool_result record",
            [base, _rec("tool_result", "TEST-REC", call_id="c1")],
            {"h_record_kind_tool": True},
        ),
        (
            "unknown kind",
            [base, _rec("weird", "TEST-REC")],
            {"h_record_kind_unknown": True},
        ),
        (
            "record of another session",
            [base, _rec("assistant", "TEST-REC", session="other")],
            {"h_record_foreign_session": True},
        ),
        (
            "managed record of another session",
            [base, _rec("managed", "TEST-REC", session="other", turn=None)],
            {"h_record_kind_managed": True, "h_record_foreign_session": True},
        ),
        (
            "extra key",
            [base, {**_rec("assistant", "TEST-REC"), "zzz": 1}],
            {"h_record_malformed": True},
        ),
        (
            "missing session_id",
            [
                base,
                {
                    k: v
                    for k, v in _rec("assistant", "TEST-REC").items()
                    if k != "session_id"
                },
            ],
            {"h_record_malformed": True},
        ),
        ("empty stream", [], {"h_stream_empty": True}),
    ]
    for label, recs, flags in cases:
        hist, err = None, None
        try:
            hist = (RESTORE or core.ConversationHistory.from_jsonl)(
                json.dumps(r) for r in recs
            )
        except Exception as ex:  # noqa: BLE001
            err = ex
        es = list(hist.entries) if hist else []
        hit = [
            x
            for x in es
            if "TEST-REC" in (x.content or "") or x.tool_name == "TEST-REC"
        ]
        t = blank(spec, "History")
        t.update(
            {
                "_label": label,
                "h_op": C["OP_RESTORE"],
                "h_entry_appended": bool(hit),
                "h_managed_entry_added": any(x.kind == "managed" for x in hit),
                "h_tool_entry_added": any(
                    x.kind in ("tool_call", "tool_result") for x in hit
                ),
                "h_record_rejected": err is not None or not hit,
                "h_error": err is not None,
                "h_history_returned": hist is not None,
            }
        )
        t.update(flags)
        ticks.append(t)
    return ticks


# ------------------------------------------------- Instruction


def probe_instruction(spec, C):
    """Observe the creation and parsing of instructions."""
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
    ticks.append(
        {
            **blank(spec, "Instruction"),
            "_label": "construct",
            "i_op": C["IOP_CONSTRUCT"],
            "i_task_id_derived": u.task_id == "s:1" and not supplied,
            "i_mutable_after_creation": mutable,
        }
    )
    for label, line, flags in (
        ("blank line", "   ", {"i_line_blank": True}),
        ("well-formed", '{"session_id":"s","turn_id":1,"text":"hi"}', {}),
        (
            "with task_id",
            '{"session_id":"s","turn_id":1,"text":"hi","task_id":"x"}',
            {"i_record_has_task_id": True},
        ),
        (
            "missing text",
            '{"session_id":"s","turn_id":1}',
            {"i_record_malformed": True},
        ),
        (
            "extra key",
            '{"session_id":"s","turn_id":1,"text":"hi","zzz":1}',
            {"i_record_malformed": True},
        ),
    ):
        got, err = [], None
        try:
            got = list(core.UserInstruction.from_jsonl([line]))
        except Exception as e:  # noqa: BLE001
            err = e
        t = blank(spec, "Instruction")
        t.update(
            {
                "_label": label,
                "i_op": C["IOP_PARSE"],
                "i_instruction_yielded": bool(got),
                "i_error": err is not None,
                **flags,
            }
        )
        ticks.append(t)
    return ticks


# ---------------------------------------------------- Config


def probe_config(spec, C):
    """Observe the configuration of the stages."""
    ticks = []
    s = new_stages()
    t = blank(spec, "Config")
    t.update(
        {
            "_label": "defaults",
            "c_construct": True,
            "c_use_defaults": True,
            "c_max_analysis": s.max_analysis_calls,
            "c_max_worker": s.max_worker_calls,
            "c_max_tools": s.max_tool_calls,
            "c_ttl": s.ticket_ttl,
            "c_ticket_exists_after": bool(s._tickets),
        }
    )
    ticks.append(t)
    perms = {"t": ["a"]}
    s = new_stages(agent_permissions=perms, user_permissions=perms)
    exists = bool(s._tickets)
    perms["t"].append("b")
    perms["u"] = ["x"]
    t = blank(spec, "Config")
    t.update(
        {
            "_label": "caller mutates the permission tables",
            "c_construct": True,
            "c_caller_mutates_policy_later": True,
            "c_ticket_exists_after": exists,
            "c_policy_widened": "b" in s.agent_permissions["t"]
            or "u" in s.agent_permissions
            or "b" in s.user_permissions["t"]
            or "u" in s.user_permissions,
        }
    )
    ticks.append(t)
    tools = {"t": mk_tool("t")}
    s = new_stages(tools=tools)
    exists = bool(s._tickets)
    tools["new"] = mk_tool("new")
    t = blank(spec, "Config")
    t.update(
        {
            "_label": "caller mutates the tool registry",
            "c_construct": True,
            "c_caller_mutates_tools_later": True,
            "c_ticket_exists_after": exists,
            "c_registry_changed": "new" in s.tools,
        }
    )
    ticks.append(t)
    grant = {"grants": [{"tool": "t", "resources": ["r1"]}], "declines": []}
    s = new_stages(
        lambda m, tl, j: {"content": json.dumps(grant)},
        tools={"t": mk_tool("t")},
    )
    exists = bool(s._tickets)
    instr, ctx = new_ctx()
    ctx.plan = core.TaskPlan(
        instr.task_id, "o", (core.PlannedStep("0", "d", "t", ("r1",)),)
    )
    res = s.authorize_task(ctx)
    t = blank(spec, "Config")
    t.update(
        {
            "_label": "no permission tables",
            "c_construct": True,
            "c_no_permissions_given": True,
            "c_ticket_exists_after": exists,
            "c_any_grant_possible": res.next_state == core.TurnState.EXECUTE
            or ctx.ticket in s._tickets,
        }
    )
    ticks.append(t)
    return ticks


# ---------------------------------------------------------------- LlmIO


def probe_llmio(spec, C):
    """Observe the calls to the model and the message building."""
    ticks = []
    src = (loader.pin.original_root() / "src" / "core.py").read_text(
        encoding="utf-8"
    )
    dangerous = {
        n.func.id
        for n in ast.walk(ast.parse(src))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id in ("eval", "exec", "compile", "__import__")
    }
    static = {"l_output_executed": bool(dangerous)}

    def base(label, **kw):
        t = blank(spec, "LlmIO")
        t.update({"_label": label, **static, **kw})
        ticks.append(t)

    raw = {"content": "x", "tool_calls": None}
    log = []
    s = new_stages(lambda m, t, j, log=log: (log.append(1), raw)[1])
    u0 = _usage(s)
    got = s._call([])
    base(
        "call, plain",
        l_op=C["LOP_CALL"],
        l_json_requested=False,
        l_response_passthrough=got is raw,
        l_provider_called=bool(log),
        l_usage_recorded=_usage(s) not in (None, u0),
    )
    log = []
    s = new_stages(
        lambda m, t, j, log=log: (log.append(1), {"content": '{"a": 1}'})[1]
    )
    u0 = _usage(s)
    got = s._call([], json_output=True)
    base(
        "call, json ok",
        l_op=C["LOP_CALL"],
        l_json_requested=True,
        l_output_valid_json=True,
        l_json_parsed=got == {"a": 1},
        l_provider_called=bool(log),
        l_usage_recorded=_usage(s) not in (None, u0),
    )
    log = []
    s = new_stages(
        lambda m, t, j, log=log: (log.append(1), {"content": "nope"})[1]
    )
    u0 = _usage(s)
    try:
        s._call([], json_output=True)
        err = False
    except Exception:  # noqa: BLE001
        err = True
    base(
        "call, json invalid",
        l_op=C["LOP_CALL"],
        l_json_requested=True,
        l_output_valid_json=False,
        l_error_propagated=err,
        l_provider_called=bool(log),
        l_usage_recorded=_usage(s) not in (None, u0),
    )
    s = new_stages()
    instr, ctx = new_ctx()
    ctx.history.add_managed_prompt("MANAGED-ONE")
    ctx.history.add_managed_prompt("MANAGED-TWO")
    sysmsg = s._system(ctx, "INSTR")
    base(
        "system prompt",
        l_op=C["LOP_SYSTEM"],
        l_managed_in_system_prompt="MANAGED-ONE" in sysmsg
        and "MANAGED-TWO" in sysmsg,
    )
    hist = core.ConversationHistory("s")
    hist.add_managed_prompt("M-text")
    hist.add_user(core.UserInstruction("s", 1, "U-text"))
    hist.add_assistant(1, "A-text")
    hist.add_tool_call(1, "c1", "t", {})
    hist.add_tool_result(1, "c1", "R-text")
    ctx2 = core.TurnContext(core.UserInstruction("s", 2, "x"), hist)
    msgs = s._messages(ctx2)
    ROLE = {
        "user": C["ROLE_USER"],
        "assistant": C["ROLE_ASSISTANT"],
        "tool": C["ROLE_TOOL"],
    }
    probes = [
        ("managed", "KIND_MANAGED", lambda m: m.get("content") == "M-text"),
        ("user", "KIND_USER", lambda m: m.get("content") == "U-text"),
        (
            "assistant",
            "KIND_ASSISTANT",
            lambda m: m.get("content") == "A-text",
        ),
        (
            "tool_call",
            "KIND_TOOL_CALL",
            lambda m: any(
                c["id"] == "c1" for c in (m.get("tool_calls") or [])
            ),
        ),
        (
            "tool_result",
            "KIND_TOOL_RESULT",
            lambda m: m.get("content") == "R-text",
        ),
    ]
    for label, kind, match in probes:
        hit = [m for m in msgs if match(m)]
        base(
            f"message of kind {label}",
            l_op=C["LOP_MESSAGES"],
            l_entry_kind=C[kind],
            l_msg_emitted=bool(hit),
            l_role=ROLE.get(hit[0]["role"], 0) if hit else 0,
        )

    # Calls under a budget of 3 calls, 2000 characters and 30 seconds
    # per turn.  The oracle counts only what reached the provider.
    def size(value):
        return len(json.dumps(value, ensure_ascii=False))

    scenarios = (
        ("within the budget", [(100, 100, 0), (100, 100, 0)]),
        ("call cap", [(10, 10, 0)] * 5),
        ("character cap", [(900, 10, 0)] * 3),
        ("output size", [(100, 1900, 0), (100, 10, 0)]),
        ("time cap", [(10, 10, 0), (10, 10, 31)]),
    )
    for label, steps in scenarios:
        log, cur = [], {}
        with fake_clock(100.0) as clock:

            def provider(messages, tools, json_output, log=log, cur=cur):
                log.append(1)
                cur["resp"] = {"content": "y" * cur["out"]}
                return cur["resp"]

            s = new_stages(provider, budget=BUDGET)
            used_calls = used_chars = 0
            started = clock.now
            for k, (n_in, n_out, wait) in enumerate(steps):
                clock.now += wait
                messages = [{"role": "user", "content": "x" * n_in}]
                new_chars = size(messages) + size([])
                over = oracle_budget_over(
                    used_calls, used_chars, new_chars, clock.now - started
                )
                cur["out"] = n_out
                n_before, u0 = len(log), _usage(s)
                try:
                    got, err = s._call(messages, []), False
                except Exception:  # noqa: BLE001
                    got, err = None, True
                called = len(log) > n_before
                if called:
                    used_calls += 1
                    used_chars += new_chars + size(cur["resp"])
                base(
                    f"call under the budget, {label}, call {k + 1}",
                    l_op=C["LOP_CALL"],
                    l_json_requested=False,
                    l_budget_over=over,
                    l_provider_called=called,
                    l_error_propagated=err,
                    l_response_passthrough=(
                        not err and got is cur.get("resp")
                    ),
                    l_usage_recorded=_usage(s) not in (None, u0),
                )
    return ticks


# ---------------------------------------------------------------- Data


def probe_data(spec, C):
    """Observe the static facts of the data model."""
    frozen = []
    samples = [
        core.TaskRecord("t"),
        core.ProcessingResult(message="m"),
        core.ConversationEntry(None, "user", "x"),
        core.PlannedStep("0", "d", None, ()),
        core.TaskPlan("t", "o", ()),
        core.StageResult(core.TurnState.COMPLETED),
        core.TurnResult("t", core.TurnState.COMPLETED, 0),
        core.ToolDefinition(
            "d", {}, "h", lambda a: a, lambda a: (), lambda a: a
        ),
        core.UserInstruction("s", 1, "t"),
    ]
    for obj in samples:
        field = dataclasses.fields(obj)[0].name
        try:
            setattr(obj, field, getattr(obj, field))
            frozen.append(False)
        except dataclasses.FrozenInstanceError:
            frozen.append(True)
    seen = []

    class Spy:
        """A stage set whose handlers record the context they get."""

        def __init__(self):
            self.n = 0

        def _h(self, state):
            def h(context):
                seen.append(context)
                return core.StageResult(
                    core.TurnState.COMPLETED, message="done"
                )

            return h

        def revoke_ticket(self, context):
            context.ticket = None

        @property
        def analyze_instruction(self):
            return self._h("a")

        authorize_task = execute_task = evaluate_result = analyze_instruction

    for i in (1, 2):
        core.process_turn(
            core.UserInstruction("s", i, "x"),
            core.ConversationHistory("s"),
            stages=Spy(),
        )
    return [
        {
            **blank(spec, "Data"),
            "_label": "static facts",
            "d_record_mutated_in_place": not all(frozen),
            "d_state_count": len(core.TurnState),
            "d_context_new_per_turn": len(seen) == 2
            and seen[0] is not seen[1],
        }
    ]


# ---- Turn (scripted stages; one tick per iteration plus the exit)


def _run_turn(
    C,
    script,
    max_steps=20,
    cancel_at=None,
    dup=False,
    deny_exc=PermissionError,
):
    """Run ``process_turn`` over scripted stages.

    ``script`` maps a state name to a list of outcomes, each either
    ``('ok', next_state_name, message)`` or
    ``('raise', ExcClass, text, blocked)``.
    """
    events, cancels = [], {"n": 0}
    state_of = {
        "analyze": core.TurnState.ANALYZE,
        "authorize": core.TurnState.AUTHORIZE,
        "execute": core.TurnState.EXECUTE,
        "evaluate": core.TurnState.EVALUATE,
        "completed": core.TurnState.COMPLETED,
        "failed": core.TurnState.FAILED,
        "waiting": core.TurnState.WAITING_FOR_USER,
    }
    plan = {k: list(v) for k, v in script.items()}
    last_len = {"n": 0}

    class Stub:
        """A stage set with scripted handlers."""

        def revoke_ticket(self, context):
            events.append(("revoke",))
            context.ticket = None

        def _h(self, name):
            def h(context):
                out = (
                    plan[name].pop(0)
                    if plan[name]
                    else ("ok", "completed", "")
                )
                events.append(
                    (
                        "handler",
                        name,
                        context.feedback,
                        out,
                        context.history.entries[-1].kind,
                    )
                )
                if out[0] == "raise":
                    raise out[1](out[2])
                if dup and out[2]:
                    context.history.add_assistant(
                        context.instruction.turn_id, out[2]
                    )
                last_len["n"] = len(context.history.entries)
                return core.StageResult(state_of[out[1]], message=out[2])

            return h

        def __getattr__(self, name):
            return {
                "analyze_instruction": self._h("analyze"),
                "authorize_task": self._h("authorize"),
                "execute_task": self._h("execute"),
                "evaluate_result": self._h("evaluate"),
            }[name]

    def should_cancel():
        cancels["n"] += 1
        v = cancel_at is not None and cancels["n"] >= cancel_at
        events.append(("cancel_check", v))
        return v

    hist = core.ConversationHistory("s")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        res = core.process_turn(
            core.UserInstruction("s", 1, "x"),
            hist,
            stages=Stub(),
            max_steps=max_steps,
            should_cancel=should_cancel,
        )
    return events, res, hist, err.getvalue(), last_len["n"]


def probe_turn(spec, C):
    """Observe the turn loop over scripted stages."""
    ticks = []
    B = lambda *a: ("ok",) + a  # noqa: E731
    happy = {
        "analyze": [B("authorize", "")],
        "authorize": [B("execute", "")],
        "execute": [B("evaluate", "")],
        "evaluate": [B("completed", "done")],
    }
    scenarios = [
        ("normal", dict(script=happy)),
        (
            "cancel before the second iteration",
            dict(script=happy, cancel_at=2),
        ),
        ("cancel before the first iteration", dict(script=happy, cancel_at=1)),
        (
            "step limit",
            dict(
                script={
                    "analyze": [B("authorize", "")],
                    "authorize": [B("execute", "")],
                    "execute": [B("evaluate", "")],
                    "evaluate": [B("execute", "")] * 9,
                },
                max_steps=3,
            ),
        ),
        (
            "handler raises once, then succeeds",
            dict(
                script={
                    **happy,
                    "analyze": [
                        ("raise", ValueError, "boom", False),
                        B("authorize", ""),
                    ],
                }
            ),
        ),
        (
            "blocked start, repeated",
            dict(
                script={
                    "analyze": [B("authorize", "")],
                    "authorize": [B("execute", "")],
                    "execute": [("raise", PermissionError, "ticket", True)]
                    * 30,
                },
                max_steps=6,
            ),
        ),
        (
            "blocked start that clears",
            dict(
                script={
                    **happy,
                    "execute": [
                        ("raise", PermissionError, "ticket", True),
                        B("evaluate", ""),
                    ],
                }
            ),
        ),
        (
            "final message equals the last assistant entry",
            dict(script=happy, dup=True),
        ),
        (
            "completed with an empty message",
            dict(script={**happy, "evaluate": [B("completed", "")]}),
        ),
        (
            "authorization fails with a reason",
            dict(
                script={
                    "analyze": [B("authorize", "")],
                    "authorize": [B("failed", "Policy denies x")],
                }
            ),
        ),
        (
            "evaluator asks for a new ticket",
            dict(
                script={
                    **happy,
                    "evaluate": [B("authorize", ""), B("completed", "done")],
                    "authorize": [B("execute", "")] * 2,
                    "execute": [B("evaluate", "")] * 2,
                }
            ),
        ),
        ("clarify", dict(script={"analyze": [B("waiting", "which one?")]})),
        # The oracle says the budget is spent from the 3rd iteration on.
        # The stubs spend nothing: this fixes what the exit owes.
        (
            "budget exhausted, the loop runs to the step limit",
            dict(
                script={
                    "analyze": [B("authorize", "")],
                    "authorize": [B("execute", "")],
                    "execute": [B("evaluate", "")] * 9,
                    "evaluate": [B("execute", "")] * 9,
                },
                max_steps=6,
                budget_over_from=3,
            ),
        ),
    ]
    code = lambda name: C["ST_" + name.upper()]  # noqa: E731
    for label, kw in scenarios:
        kw = dict(kw)
        over_from = kw.pop("budget_over_from", None)
        events, res, hist, stderr, last_len = _run_turn(C, **kw)
        max_steps = kw.get("max_steps", 20)
        final = st(C, res.status)
        # the iterations are rebuilt from the event log: cancel check,
        # optional revoke, optional handler
        iters, p, state, n_handlers, denied = [], 0, "analyze", 0, False
        while p < len(events) and events[p][0] == "cancel_check":
            rec = {
                "state": state,
                "cancel": events[p][1],
                "revoked": False,
                "handler": None,
                "limit": n_handlers >= max_steps,
                "denied_before": denied,
            }
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
                t.pop(key)  # only observed after a handler exception
            t.update(
                {
                    "_label": f"{label}, iteration {k + 1}",
                    "r_state": code(rec["state"]),
                    "r_turn_start": k == 0,
                    "r_cancel": rec["cancel"],
                    "r_steps_at_limit": rec["limit"],
                    "r_handler_invoked": h is not None,
                    "r_ticket_revoked_before_handler": rec["revoked"],
                    "r_step_counted": res.steps == n_handlers,
                    "r_user_recorded": any(
                        e.kind == "user" and e.turn_id == 1
                        for e in hist.entries
                    ),
                    "r_denial_seen": rec["denied_before"],
                }
            )
            if h is None:
                t["r_next_state"] = final
            else:
                out = h[3]
                raised = out[0] == "raise"
                t["r_handler_raised"] = raised
                t["r_blocked_start"] = bool(raised and out[3])
                t["r_stage_next"] = 0 if raised else code(out[1])
                t["r_next_state"] = (
                    code(rec["state"]) if raised else code(out[1])
                )
                if raised:
                    if out[3]:
                        t["r_denial_seen"] = True
                    t["r_stderr_logged"] = (
                        f"[{rec['state']}] {out[1].__name__}: {out[2]}"
                        in stderr
                    )
                    nxt = (
                        iters[k + 1]["handler"] if k + 1 < len(iters) else None
                    )
                    if nxt is not None:
                        fb = json.loads(nxt[2]) if nxt[2] else {}
                        t["r_feedback_error_type_only"] = (
                            set(fb) == {"stage", "status", "error_type"}
                            and out[2] not in nxt[2]
                        )
            ticks.append(t)
        ex = blank(spec, "Turn")
        ex.update(
            {
                "_label": f"{label}, exit",
                "r_exit": True,
                "r_state": final,
                "r_next_state": final,
                "r_denial_seen": denied,
                "r_budget_seen": (
                    over_from is not None and len(iters) >= over_from
                ),
                "r_message_nonempty_out": bool(res.message),
                "r_ticket_revoked_at_exit": bool(events)
                and events[-1][0] == "revoke",
                "r_last_is_same_assistant": dup_flag(kw, res),
                "r_message_appended": len(hist.entries) > last_len
                and hist.entries[-1].kind == "assistant"
                and hist.entries[-1].content == res.message,
            }
        )
        ticks.append(ex)
    return ticks


def _stage_of(prompt):
    """Return which stage a system prompt belongs to."""
    stages = (
        ("You are an intent analyzer", "analyze"),
        ("You are a permission verifier", "verify"),
        ("You are the delegated Worker", "worker"),
        ("You are the result evaluator", "evaluate"),
    )
    for start, stage in stages:
        if prompt.startswith(start):
            return stage
    raise RuntimeError("unknown stage prompt")


def _e2e_model(decision, forever, log):
    """Scripted model for whole turns; the stage comes from the prompt.

    The worker calls the tool whenever the last message is not a tool
    result, so a turn that is allowed to finish executes once and then
    answers.  With ``forever`` it never answers.  The evaluator always
    gives ``decision``.
    """
    verdict = {
        "grants": [{"tool": "read_file", "resources": ["reports/a.txt"]}],
        "declines": [],
    }
    call = {
        "function": {
            "name": "read_file",
            "arguments": json.dumps({"target": "reports/a.txt"}),
        }
    }

    def call_llm(messages, tools, json_output):
        log.append(1)
        stage = _stage_of(messages[0]["content"])
        if stage == "analyze":
            return {"content": json.dumps(PLAN_JSON)}
        if stage == "verify":
            return {"content": json.dumps(verdict)}
        if stage == "worker":
            if forever or messages[-1].get("role") != "tool":
                return {"content": None, "tool_calls": [call]}
            return {"content": "done", "tool_calls": None}
        return {"content": json.dumps({"decision": decision, "message": "m"})}

    return call_llm


def _reset_seen(before, after, calls):
    """Say whether the usage totals were reset during one iteration.

    Args:
        before: Totals ``(calls, chars)`` when the iteration began, or
            None if the stack keeps none.
        after: Totals when it ended.
        calls: Calls that reached the provider during the iteration.
    """
    if before is None:
        return False
    return before[0] == 0 or after[0] != before[0] + calls


def probe_turn_budget(spec, C):
    """Run whole turns on the real loop; evidence for TRN-13 and TRN-14.

    The real stages run under the real ``process_turn`` with a
    scripted model: once for a turn that would run away, once for two
    honest turns in a row.  The ticks carry only what the two
    requirements need.

    * TRN-13: a turn that exceeds its budget ends with a message.
    * TRN-14: the usage totals are reset at the first iteration of a
      turn and at no other iteration.  The reset is read from the totals
      themselves, not from a note of the guard: a total that merely adds
      up has not been reset.  Two honest turns that fit the budget one
      by one but not together show that an earlier turn does not use up
      a later one.
    """
    ticks = []
    scenarios = (
        ("a runaway turn", BUDGET_RUNAWAY, True, "execute", 1, True),
        ("two honest turns", BUDGET_ROOMY, False, "completed", 2, False),
    )
    for label, budget, forever, decision, turns, exceeds in scenarios:
        log, iterations = [], []
        with fake_clock(100.0):
            tools = {
                "read_file": mk_tool("read_file", [], res=("reports/a.txt",))
            }
            stages = new_stages(
                _e2e_model(decision, forever, log),
                tools=tools,
                agent_permissions=POLICY,
                user_permissions=POLICY,
                budget=budget,
            )

            def spy(inner, stages=stages, log=log, iterations=iterations):
                def handler(context):
                    before, n_before = _usage(stages), len(log)
                    try:
                        return inner(context)
                    finally:
                        iterations.append(
                            (before, _usage(stages), len(log) - n_before)
                        )

                return handler

            for name in (
                "analyze_instruction",
                "authorize_task",
                "execute_task",
                "evaluate_result",
            ):
                setattr(stages, name, spy(getattr(stages, name)))
            history = core.ConversationHistory("sess")
            done = 0
            for turn in range(1, turns + 1):
                instruction = core.UserInstruction(
                    "sess", history.next_turn_id, "x"
                )
                with contextlib.redirect_stderr(io.StringIO()):
                    result = core.process_turn(
                        instruction, history, stages=stages, max_steps=20
                    )
                for k in range(result.steps):
                    tick = blank(spec, "Turn")
                    tick.update(
                        {
                            "_label": f"{label}, turn {turn}, "
                            f"iteration {k + 1}",
                            "r_turn_start": k == 0,
                            "r_usage_reset": _reset_seen(
                                *iterations[done + k]
                            ),
                        }
                    )
                    ticks.append(tick)
                tick = blank(spec, "Turn")
                tick.update(
                    {
                        "_label": f"{label}, turn {turn}, exit",
                        "r_exit": True,
                        "r_budget_seen": exceeds,
                        "r_message_nonempty_out": bool(result.message),
                    }
                )
                ticks.append(tick)
                done += result.steps
    return ticks


def _merge_eval(first, second):
    """Combine two evaluations of one requirement."""
    checked = first["checked"] + second["checked"]
    violations = first["violations"] + second["violations"]
    status = (
        "not_checked"
        if checked == 0
        else "violated" if violations else "holds"
    )
    expected = first["asis"]
    consistent = (status == "holds" and expected == "ok") or (
        status == "violated" and expected == "gap"
    )
    return {
        "status": status,
        "checked": checked,
        "violations": violations,
        "examples": (first["examples"] + second["examples"])[:3],
        "asis": expected,
        "consistent": None if status == "not_checked" else consistent,
    }


def _turn_budget_evidence(spec, comp, C):
    """Return the whole-turn ticks and the verdicts on TRN-13, 14."""
    ticks = probe_turn_budget(spec, C)
    evaluated = evaluate(spec, comp, "Turn", ticks)
    return ticks, {rid: evaluated[rid] for rid in ("TRN-13", "TRN-14")}


def dup_flag(kw, res) -> bool:
    """Say whether the final message repeats the last entry."""
    return bool(kw.get("dup")) and bool(res.message)


PROBES = {
    "Gate": probe_gate,
    "Ticket": probe_ticket,
    "Authorizer": probe_authorizer,
    "Analyzer": probe_analyzer,
    "Executor": probe_executor,
    "Evaluator": probe_evaluator,
    "Turn": probe_turn,
    "History": probe_history,
    "Instruction": probe_instruction,
    "Config": probe_config,
    "LlmIO": probe_llmio,
    "Data": probe_data,
}


# ------------------- evaluation of the requirements on the ticks


def evaluate(spec: dict, comp: dict, cname: str, ticks: list[dict]) -> dict:
    """Judge every requirement of a component on the ticks."""
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
            full = {
                **C,
                **{k: v for k, v in t.items() if not k.startswith("_")},
            }
            if not ptl.check(tree, [full])["ok"]:
                bad.append(t.get("_label", "?"))
        status = (
            "not_checked" if checked == 0 else ("violated" if bad else "holds")
        )
        expected = r["asis"]
        consistent = (status == "holds" and expected == "ok") or (
            status == "violated" and expected == "gap"
        )
        out[r["id"]] = {
            "status": status,
            "checked": checked,
            "violations": len(bad),
            "examples": bad[:3],
            "asis": expected,
            "consistent": consistent if status != "not_checked" else None,
        }
    return out


def _summarize(components: dict) -> dict:
    """Count what the probes saw and where it differs."""
    counts = {"ticks": 0, "holds": 0, "violated": 0, "not_checked": 0}
    mismatch = []
    for part in components.values():
        counts["ticks"] += part["ticks"]
        for rid, e in part["requirements"].items():
            counts[e["status"]] += 1
            if e["consistent"] is False or e["status"] == "not_checked":
                mismatch.append(
                    {
                        "id": rid,
                        "status": e["status"],
                        "asis": e["asis"],
                        "examples": e["examples"],
                    }
                )
    n_req = sum(len(v["requirements"]) for v in components.values())
    text = (
        f"{counts['ticks']} observations of the real code; of {n_req} "
        f"requirements {counts['holds']} hold on every observation, "
        f"{counts['violated']} are violated, {counts['not_checked']} "
        f"were not observed; {len(mismatch)} differ from the catalog's "
        f"asis column"
    )
    return {"summary": text, "mismatch": mismatch, "counts": counts}


def run(spec: dict, comp: dict, only: list[str] | None = None) -> dict:
    """Run the probes of every (or the named) component and evaluate."""
    C = spec["constants"]
    res = {}
    for cname, fn_ in PROBES.items():
        if only and cname not in only:
            continue
        ticks = fn_(spec, C)
        ev = evaluate(spec, comp, cname, ticks)
        if cname == "Turn":
            # TRN-13 and TRN-14 are also judged on whole turns.
            more_ticks, more = _turn_budget_evidence(spec, comp, C)
            ticks = ticks + more_ticks
            for rid, item in more.items():
                ev[rid] = _merge_eval(ev[rid], item)
        res[cname] = {"ticks": len(ticks), "requirements": ev}
    return {"components": res, **_summarize(res)}


def run_guarded(spec: dict, comp: dict, stack=None) -> dict:
    """Run the same probes on the guarded stack.

    For Turn only TRN-13 and TRN-14 are judged, on whole turns
    (:func:`probe_turn_budget`); the end-to-end scenarios of `traces`
    cover the guards on the loop.

    Args:
        spec: The loaded catalog.
        comp: The compiled requirements.
        stack: The guarded stack class; ``GuardedStages`` by default.

    Returns:
        The result of :func:`run`, plus ``closed_gaps`` (gaps of the
        original that hold now), ``still_violated``, ``pending_guard``
        (violated and declared pending) and ``unexpected_violations``.

    """
    from .guard import GuardedStages, TrustedHistory
    from .observe import TraceRecorder

    global STAGES, RESTORE
    stack = stack or GuardedStages

    def factory(*args, budget=None, **kwargs):
        return stack(
            *args,
            recorder=TraceRecorder(),
            policy=probe_policy(budget),
            **kwargs,
        )

    STAGES, RESTORE = factory, TrustedHistory.from_jsonl
    try:
        res = run(spec, comp, only=[c for c in PROBES if c != "Turn"])
        ticks, more = _turn_budget_evidence(spec, comp, spec["constants"])
        res["components"]["Turn"] = {"ticks": len(ticks), "requirements": more}
        res.update(_summarize(res["components"]))
    finally:
        STAGES = RESTORE = None
    closed, violated = [], []
    for part in res["components"].values():
        for rid, e in part["requirements"].items():
            if e["status"] == "violated":
                violated.append(rid)
            elif e["asis"] == "gap" and e["status"] == "holds":
                closed.append(rid)
    pending = {
        r["id"] for r in sp.requirements(spec) if r.get("guard") == "pending"
    }
    res["closed_gaps"], res["still_violated"] = sorted(closed), sorted(
        violated
    )
    res["pending_guard"] = sorted(set(violated) & pending)
    res["unexpected_violations"] = sorted(set(violated) - pending)
    return res


# --------- which statements of core.py the probes executed


def run_traced(spec: dict, comp: dict, only: list[str] | None = None) -> dict:
    """Run the probes with a line tracer on core.py.

    Every statement inside a function body is either executed by some
    probe or listed as not executed.
    """
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
                if (
                    isinstance(sub, ast.stmt)
                    and sub is not node
                    and not isinstance(sub, (ast.Try, ast.FunctionDef))
                ):
                    body.add(sub.lineno)
    missed = sorted(body - executed)
    out["exec_coverage"] = {
        "statements_in_function_bodies": len(body),
        "executed": len(body & executed),
        "not_executed": [
            {"line": ln, "text": lines[ln - 1].strip()[:100]} for ln in missed
        ],
    }
    return out


# --------- code mutants: do the probes catch a defect in the code

CODE_MUTANTS = [
    (
        "C-01",
        "The gate does not check ticket expiry",
        "        if time.monotonic() >= ticket.expires_at:\n            raise "
        "PermissionError",
        "        if False:\n            raise PermissionError",
    ),
    (
        "C-02",
        "The gate does not check the ticket binding to the turn",
        "(ticket.session_id, ticket.task_id) != "
        "(context.instruction.session_id, context.instruction.task_id)",
        "False",
    ),
    (
        "C-03",
        "The gate does not check the resource grant",
        "        if not set(resources) <= set(grants[name]):\n            "
        "raise PermissionError",
        "        if False:\n            raise PermissionError",
    ),
    (
        "C-04",
        "The gate does not check the call limit",
        "        if self._ticket_calls[ticket.ticket_id] >= "
        "ticket.max_calls:\n            raise PermissionError",
        "        if False:\n            raise PermissionError",
    ),
    (
        "C-05",
        "The call count is taken after execution (not for a failing tool)",
        "        self._ticket_calls[ticket.ticket_id] += 1\n        return "
        "tool.execute(checked)",
        "        _r = tool.execute(checked)\n        "
        "self._ticket_calls[ticket.ticket_id] += 1\n        return _r",
    ),
    (
        "C-06",
        "validate gets the original arguments, not a copy",
        "tool.validate(deepcopy(arguments))",
        "tool.validate(arguments)",
    ),
    (
        "C-07",
        "The ticket is not removed when the turn ends",
        "    finally:\n        stages.revoke_ticket(context)",
        "    finally:\n        pass",
    ),
    (
        "C-08",
        "The authorization stage skips the policy (intersection) check",
        "            if not resources <= allowed:",
        "            if False:",
    ),
    (
        "C-09",
        "The worker LLM is shown the schemas of all registered tools",
        "}} for name in dict(ticket.grants)]",
        "}} for name in self.tools]",
    ),
    (
        "C-10",
        "The message of a tool failure is recorded for the LLM",
        'content = json.dumps({"error_type": type(error).__name__}, '
        "ensure_ascii=False)",
        "content = "
        'json.dumps({"error_type": type(error).__name__, '
        '"message": str(error)}, ensure_ascii=False)',
    ),
    (
        "C-11",
        "The evaluation treats an unknown decision value as completion",
        'return StageResult(states[result["decision"]], '
        'message=result["message"])',
        'return StageResult(states.get(result["decision"], '
        'TurnState.COMPLETED), message=result["message"])',
    ),
    (
        "C-12",
        "entries returns the live entries, not a copy",
        "return tuple(deepcopy(self._entries))",
        "return tuple(self._entries)",
    ),
    (
        "C-13",
        "The agent permission table is not copied",
        "self.agent_permissions = deepcopy(agent_permissions or {})",
        "self.agent_permissions = agent_permissions if agent_permissions is "
        "not None else {}",
    ),
    (
        "C-14",
        "The step limit (max_steps) is not checked",
        "            if steps >= max_steps:",
        "            if False:",
    ),
    (
        "C-15",
        "Cancellation ends with FAILED instead of CANCELLED",
        '                state, message = TurnState.CANCELLED, ""',
        '                state, message = TurnState.FAILED, ""',
    ),
    (
        "C-16",
        "Managed entries are also sent as conversation messages",
        '            if entry.kind == "managed":\n                continue\n  '
        '          if entry.kind in {"user", "assistant"}:',
        '            if entry.kind in {"user", "assistant", "managed"}:',
    ),
    (
        "C-17",
        "The analysis call limit is not checked",
        "        if context.analysis_calls >= self.max_analysis_calls:",
        "        if False:",
    ),
    (
        "C-18",
        "The analysis call count is not incremented",
        "        context.analysis_calls += 1",
        "        pass",
    ),
    (
        "C-19",
        "The worker LLM call limit is raised by 100",
        "        while context.worker_calls < self.max_worker_calls:",
        "        while context.worker_calls < self.max_worker_calls + 100:",
    ),
    (
        "C-20",
        "The limit check of the tool call batch is skipped",
        "            if context.tool_attempts + len(calls) > "
        "self.max_tool_calls:",
        "            if False:",
    ),
    (
        "C-21",
        "The ticket effectively has no expiry time",
        "expires_at=time.monotonic() + self.ticket_ttl,",
        "expires_at=time.monotonic() + 10 ** 9,",
    ),
    (
        "C-22",
        "The ticket effectively has no call limit",
        "max_calls=self.max_tool_calls,",
        "max_calls=10 ** 6,",
    ),
    (
        "C-23",
        "The ticket is not bound to the session",
        "            session_id=context.instruction.session_id,",
        '            session_id="shared",',
    ),
    (
        "C-25",
        "Managed entries (operator instructions) are not in the system prompt",
        "managed = [entry.content for entry in context.history.entries if "
        'entry.kind == "managed"]',
        "managed = []",
    ),
    (
        "C-24",
        "The previous ticket is not removed before authorization in AUTHORIZE",
        "            if state in {TurnState.ANALYZE, TurnState.AUTHORIZE}:",
        "            if state in {TurnState.ANALYZE}:",
    ),
]


def mutate(spec: dict, comp: dict) -> dict:
    """Run the probes on copies of core.py that each have ONE defect.

    A mutant is caught when a requirement that holds on the original
    is violated on it.  The original file is only read.

    """
    import importlib.util
    import shutil
    import tempfile
    from pathlib import Path

    global core
    src = (loader.pin.original_root() / "src" / "core.py").read_text(
        encoding="utf-8"
    )
    real = core
    base = run(spec, comp)
    held = {
        (c, r)
        for c, v in base["components"].items()
        for r, e in v["requirements"].items()
        if e["status"] == "holds"
    }
    out, tmp = {}, Path(tempfile.mkdtemp(prefix="sa_mut_"))
    try:
        for mid, desc, old, new in CODE_MUTANTS:
            if src.count(old) != 1:
                out[mid] = {
                    "desc": desc,
                    "error": "the text to replace occurs "
                    f"{src.count(old)} times",
                }
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
                bad = sorted(
                    f"{c}:{r}"
                    for c, v in res["components"].items()
                    for r, e in v["requirements"].items()
                    if e["status"] == "violated" and (c, r) in held
                )
                out[mid] = {"desc": desc, "caught": bool(bad), "violated": bad}
            except Exception as e:  # noqa: BLE001
                out[mid] = {
                    "desc": desc,
                    "caught": True,
                    "violated": [],
                    "crash": f"{type(e).__name__}: {e}"[:200],
                }
            finally:
                core = real
                sys.modules.pop(name, None)
    finally:
        core = real
        shutil.rmtree(tmp, ignore_errors=True)
    return out
