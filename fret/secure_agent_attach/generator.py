"""Generate sessions of hostile model behaviour on the real system.

The scripted model answers every call of a session at random, driven by
a seed: valid plans, garbage, unknown tools, grants outside the plan,
tool calls that are valid, malformed, oversize or repeated, clock jumps,
tools that fail or return huge results.  A session is one to three turns
of the real stages under the real ``process_turn``.  The same seed gives
the same session.

The sessions are the real side of the formal checks in
:mod:`secure_agent_attach.callcheck`.  The properties that NuSMV
proves on the abstract model are evaluated on what the real system
does in these sessions.  This is random testing in the sense of
[Miller1990] and [Claessen2000]; here it only produces behaviour, and
the judgement is made by the FRET requirements.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import random

from . import probes
from .observe import ObservedStages, TraceRecorder, run_turn
from .oracles import MAX_ARG_BYTES, RESULT_CAP, SCHEMA, oracle_budget_over

TOOLS = ("a", "t", "c")
POLICY = {name: ("r1",) for name in TOOLS}
STAGES = (
    ("You are an intent analyzer", "analyze"),
    ("You are a permission verifier", "verify"),
    ("You are the delegated Worker", "worker"),
    ("You are the result evaluator", "evaluate"),
)
DECISIONS = (
    ("completed", 45),
    ("execute", 20),
    ("authorize", 8),
    ("analyze", 4),
    ("ask", 4),
    ("failed", 8),
)
JUMPS = (1, 50, 200, 400, 4000)


def _stage_of(prompt: str) -> str:
    for start, stage in STAGES:
        if prompt.startswith(start):
            return stage
    raise RuntimeError("unknown stage prompt")


def _weighted(rng: random.Random, options):
    """Pick one of ``(weight, value)`` pairs."""
    return rng.choices(
        [v for _, v in options], weights=[w for w, _ in options]
    )[0]


def _raw_arguments(rng: random.Random):
    """Return the ``arguments`` of one tool call of the scripted model.

    Most are text, as a real provider sends them; a few are valid JSON
    of the wrong shape, or not JSON at all, or not even text.
    """
    deep = {"a": {"b": {"c": {"d": "e"}}}}
    return _weighted(
        rng,
        (
            (45, json.dumps({"target": "r1"})),
            (8, json.dumps({"target": "r1", "note": "hello"})),
            (5, json.dumps({"target": "r1", "note": "EVIL"})),
            (5, json.dumps({"target": "r1", "extra": "x"})),
            (3, json.dumps({"target": 5})),
            (3, json.dumps({})),
            (3, json.dumps(["r1"])),
            (2, json.dumps("r1")),
            (1, "null"),
            (3, json.dumps({"target": "r1", "meta": deep})),
            (3, json.dumps({"target": "x" * (MAX_ARG_BYTES + 5)})),
            (6, "{not json"),
            (1, {"target": "r1"}),
            (2, ""),
        ),
    )


class Model:
    """The scripted model of one session, driven by a seeded generator.

    The counters describe the turn in progress; :meth:`begin_turn`
    resets them.

    Attributes:
        provider_calls: Calls that reached the model in this turn.
        over_calls: Calls that reached the model although the oracle
            says the budget of the turn was already used up.
        last_stage: Stage of the latest call.
        plan_has_tool: Whether the latest plan asked for a tool.
        plan_tools: The tools the latest plan asked for.
    """

    def __init__(self, seed: int, clock, budget: dict, state: dict):
        self.rng = random.Random(seed)
        self.clock, self.budget, self.state = clock, budget, state
        self.turn = 0
        self.begin_turn()

    def begin_turn(self) -> None:
        """Start the counters of a new turn."""
        self.turn += 1
        self.started = self.clock.now
        self.provider_calls = self.over_calls = self.chars = 0
        self.last_stage, self.plan_has_tool = "", False
        self.plan_tools = []

    def __call__(self, messages, tools, json_output):
        sent = len(json.dumps(messages, ensure_ascii=False))
        sent += len(json.dumps(tools, ensure_ascii=False))
        if oracle_budget_over(
            self.provider_calls,
            self.chars,
            sent,
            self.clock.now - self.started,
            self.budget,
        ):
            self.over_calls += 1
        stage = _stage_of(messages[0]["content"])
        self.last_stage = stage
        self.provider_calls += 1
        response = getattr(self, "_" + stage)()
        self.chars += sent + len(json.dumps(response, ensure_ascii=False))
        if self.rng.random() < 0.1:
            self.clock.now += self.rng.choice(JUMPS)
        return response

    def _text(self, obj) -> dict:
        return {"content": json.dumps(obj)}

    def _analyze(self) -> dict:
        rng = self.rng
        draw = rng.random()
        if draw < 0.65 or 0.8 <= draw < 0.86:
            tools = []
            if draw < 0.65:
                tools = rng.sample(TOOLS + ("zz",), rng.randint(1, 3))
            self.plan_tools = tools
            self.plan_has_tool = bool(tools)
            self.state["plan_tools"] = list(tools)
            steps = [
                {
                    "description": "d",
                    "tool": name,
                    "resources": ["r1" if rng.random() < 0.92 else "zzz"],
                }
                for name in tools
            ] or [{"description": "d", "tool": None, "resources": []}]
            return self._text(
                {"action": "analyze", "objective": "o", "steps": steps}
            )
        if draw < 0.72:
            return self._text({"action": "respond", "message": "hi"})
        if draw < 0.77:
            return self._text({"action": "clarify", "message": "which?"})
        if draw < 0.8:
            return self._text({"action": "history", "turn_ids": [1]})
        return {"content": "### not json"}

    def _verify(self) -> dict:
        rng = self.rng
        if rng.random() < 0.04:
            return {"content": "nope"}
        names = [n for n in self.plan_tools if rng.random() < 0.9]
        names += [n for n in TOOLS if rng.random() < 0.15]
        grants = [
            {"tool": n, "resources": ["r1" if rng.random() < 0.95 else "zzz"]}
            for n in dict.fromkeys(names)
        ]
        return self._text({"grants": grants, "declines": []})

    def _worker(self) -> dict:
        rng = self.rng
        if rng.random() < 0.3:
            return {"content": "done", "tool_calls": None}
        calls = [
            {
                "function": {
                    "name": rng.choice(TOOLS + ("zz",)),
                    "arguments": _raw_arguments(rng),
                }
            }
            for _ in range(rng.randint(1, 3))
        ]
        text = "thinking" if rng.random() < 0.3 else None
        return {"content": text, "tool_calls": calls}

    def _evaluate(self) -> dict:
        rng = self.rng
        if rng.random() < 0.05:
            return {"content": "bogus"}
        decision = _weighted(rng, [(w, n) for n, w in DECISIONS])
        return self._text({"decision": decision, "message": "m"})


def _tools(executed: list, rng: random.Random, state: dict) -> dict:
    """Return fake tools that log every call and sometimes misbehave."""

    def make(name):
        def validate(args):
            return dict(args)

        def resources(args):
            return ("r1",)

        def execute(args):
            entry = {
                "tool": name,
                "args": copy.deepcopy(args),
                "ok": False,
                "turn": state["turn"],
                "planned": name in state["plan_tools"],
            }
            executed.append(entry)
            if rng.random() < 0.05:
                raise RuntimeError("tool failed")
            entry["ok"] = True
            if rng.random() < 0.1:
                return "x" * (RESULT_CAP + rng.randint(1, 5000))
            return "ok"

        return probes.core.ToolDefinition(
            description=f"{name} tool",
            parameters=SCHEMA,
            resource_hint="target",
            validate=validate,
            resources=resources,
            execute=execute,
        )

    return {name: make(name) for name in TOOLS}


def _weighted_budget(rng: random.Random) -> dict:
    return {
        "calls": _weighted(rng, ((1, 3), (2, 6), (3, 12), (4, 40))),
        "chars": _weighted(rng, ((1, 3000), (2, 20000), (6, 400000))),
        "seconds": _weighted(rng, ((1, 30.0), (3, 300.0))),
    }


def run_one(seed: int, stack=None) -> dict:
    """Run one generated session and return what happened.

    Args:
        seed: Seed of the generator; the same seed, the same session.
        stack: A guarded stack class, or None for the original with the
            observer only.

    Returns:
        A dict with ``turns`` (per turn: the result, the tool calls that
        reached ``execute``, the counters of the model), ``recorder``
        (the observer's ticks) and ``executed`` (every tool call that
        reached ``execute``, in order).
    """
    from .guard import amend_denied

    core = probes.core
    rng = random.Random(seed)
    budget = _weighted_budget(rng)
    max_steps = rng.randint(3, 20)
    executed, turns = [], []
    state = {"turn": 0, "plan_tools": []}
    with probes.fake_clock(100.0) as clock:
        model = Model(seed ^ 0x5EED, clock, budget, state)
        recorder = TraceRecorder(max_steps=max_steps, clock=clock.monotonic)
        common = dict(
            tools=_tools(executed, random.Random(seed ^ 0xF00D), state),
            agent_permissions=POLICY,
            user_permissions=POLICY,
            ticket_ttl=_weighted(rng, ((1, 60), (3, 300))),
            recorder=recorder,
        )
        if stack is None:
            stages = ObservedStages(model, **common)
        else:
            stages = stack(model, policy=probes.probe_policy(budget), **common)
        history = core.ConversationHistory("sess")
        history.add_managed_prompt("OPERATOR")
        for number in range(1, rng.choice([1, 1, 2, 3]) + 1):
            if number > 1:
                model.begin_turn()
            state["turn"] = number
            instruction = core.UserInstruction(
                "sess", history.next_turn_id, "x"
            )
            seen_calls = len(executed)
            result = None
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    result = run_turn(
                        instruction,
                        history,
                        stages=stages,
                        max_steps=max_steps,
                        amend=None if stack is None else amend_denied,
                    )
            except Exception:  # noqa: BLE001 - a crash is reported
                result = None
            turns.append(
                {
                    "result": result,
                    "executed": executed[seen_calls:],
                    "over_calls": model.over_calls,
                    "last_stage": model.last_stage,
                    "plan_has_tool": model.plan_has_tool,
                }
            )
    return {
        "seed": seed,
        "turns": turns,
        "recorder": recorder,
        "executed": executed,
    }


__all__ = ["run_one"]
